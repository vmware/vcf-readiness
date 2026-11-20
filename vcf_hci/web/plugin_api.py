"""Authenticated, session-local VDT imports and hybrid HTML download."""

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from vcf_hci.plugins.mtat.lifecycle import catalog_entry
from vcf_hci.plugins.mtat_package import MAX_ZIP_BYTES, discover_packages, install_package
from vcf_hci.plugins.mtat_runtime import RuntimeErrorMTAT
from vcf_hci.plugins.vdt import parse_vdt_export
from vcf_hci.plugins.vinv.lifecycle import catalog_entry as vinv_catalog_entry
from vcf_hci.web.export_api import _ApiMixinBase
from vcf_hci.web.remote_vdt_api import remote_collection_available, remote_collection_capabilities
from vcf_hci.web.scan_worker import _state, _state_lock

logger = logging.getLogger('vcf_assess')
_MTAT_ACK_REQUIRED = {'connect', 'jobs.start', 'jobs.resume', 'import.upload', 'import.chunk',
                      'import.batch', 'import.resume', 'query', 'calculate', 'export'}


class PluginApiMixin(_ApiMixinBase):
    """No tool execution, server-path imports, or appliance credentials."""

    def _plugin_session_key(self) -> str:
        handler: Any = self
        return handler._current_session() or ''

    def _api_plugins(self) -> None:
        server: Any = self.server
        catalog = dict(server.vdt_plugin)
        catalog['remote_collection'] = remote_collection_capabilities(remote_collection_available(server))
        mtat = catalog_entry(bool(getattr(server, 'experimental_mtat', False)))
        mtat['packages'] = discover_packages(Path(server.vdt_plugin_root))
        mtat['packages']['install_allowed'] = not self._is_remote_server()
        manager = getattr(server, 'mtat_runtime', None)
        if manager is not None:
            session = self._plugin_session_key()
            worker = manager.workers.get(session)
            if worker is not None:
                mtat['packages']['active_folder'] = worker.folder.name
        self._send_json({'mtat': mtat, 'vinv': vinv_catalog_entry(bool(getattr(server, 'experimental_vinv', False))), 'vdt': catalog}, extra_headers={'Cache-Control': 'no-store'})

    def _api_mtat_install(self) -> None:
        """Install inert upstream bytes; this never switches the active engine."""
        handler: Any = self
        if self._is_remote_server() or not handler._require_same_origin():
            handler.close_connection = True
            self._send_json({'error': 'MTAT package installation requires the local web listener and same origin.'}, 403)
            return
        try:
            length = int(handler.headers.get('Content-Length', '0'))
        except (ValueError, TypeError):
            length = 0
        if not 0 < length <= MAX_ZIP_BYTES:
            handler.close_connection = True
            self._send_json({'error': 'Choose an MTAT ZIP no larger than 32 MiB.'}, 413)
            return
        if handler.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() not in ('application/zip', 'application/octet-stream'):
            handler.close_connection = True
            self._send_json({'error': 'Upload a built MTAT plugin ZIP.'}, 400)
            return
        timeout = handler.connection.gettimeout()
        try:
            handler.connection.settimeout(30)
            raw = handler.rfile.read(length)
            if len(raw) != length:
                raise ValueError('The MTAT ZIP upload was incomplete.')
            installed = install_package(raw, Path(handler.server.vdt_plugin_root))
            self._send_json({'installed': installed}, extra_headers={'Cache-Control': 'no-store'})
        except (ValueError, OSError):
            logger.warning('MTAT package installation rejected', exc_info=True)
            self._send_json({'error': 'MTAT package validation or installation failed. Verify the ZIP with the MTAT builder and check local diagnostics.'}, 400)
        finally:
            handler.connection.settimeout(timeout)

    def _api_mtat_upstream(self, op: str) -> None:
        """Private-pipe bridge with host session ownership and a fixed operation set."""
        handler: Any = self
        session = self._plugin_session_key()
        if not session or self._is_remote_server() or not handler._require_same_origin():
            self._send_json({'error': 'Use an authenticated same-origin local session.'}, 403)
            return
        allowed = {'activate', 'describe', 'close', 'connect', 'ranges', 'jobs.start', 'jobs.status',
                   'jobs.cancel', 'jobs.resume', 'jobs.result', 'jobs.list', 'query', 'import.upload',
                   'import.chunk', 'import.batch', 'import.status', 'import.cancel', 'import.resume', 'import.list', 'calculate', 'export'}
        if op not in allowed:
            self._send_json({'error': 'Unsupported MTAT operation.'}, 404)
            return
        data = self._read_json_body()
        if not isinstance(data, dict):
            self._send_json({'error': 'Expected a JSON object.'}, 400)
            return
        try:
            if op in _MTAT_ACK_REQUIRED and data.get('acknowledged') is not True:
                raise RuntimeErrorMTAT('Acknowledge read-only experimental MTAT collection before connecting or running jobs.')
            manager = handler.server.mtat_runtime
            if op == 'activate':
                result = manager.activate(session, str(data.get('folder') or ''), str(data.get('workspace_id') or ''))
            elif op == 'describe':
                result = manager.describe(session)
            elif op == 'close':
                result = manager.close(session)
            else:
                worker = manager.get(session)
                if op == 'connect':
                    password = handler._password_for(data)
                    if password is None:
                        return
                    data['password'] = password
                try:
                    result = worker.request(op, data)
                finally:
                    if op == 'connect':
                        data['password'] = ''
            self._send_json(result, extra_headers={'Cache-Control': 'no-store'})
        except (ValueError, OSError) as exc:
            logger.warning('MTAT upstream operation failed: %s', op, exc_info=True)
            # RuntimeErrorMTAT only contains authored messages; no arbitrary SDK text.
            message = str(exc) if isinstance(exc, RuntimeErrorMTAT) else 'MTAT input or runtime validation failed. Review the package and source settings.'
            self._send_json({'error': message}, 400, extra_headers={'Cache-Control': 'no-store'})

    def _api_vdt(self, action: str) -> None:
        server: Any = self.server
        key = self._plugin_session_key()
        if action == 'import':
            data = self._read_json_body()
            if not isinstance(data, dict):
                self._send_json({'error': 'Expected a JSON object.'}, 400)
                return
            try:
                run = parse_vdt_export(data.get('content', ''), data.get('product', ''), data.get('target', ''), data.get('filename', 'vdt.json'))
                with server.vdt_lock:
                    runs = server.vdt_sessions.get(key, [])
                    duplicate = any(item['id'] == run['id'] for item in runs)
                    if not duplicate:
                        if len(runs) >= 20:
                            raise ValueError('Remove an export before importing more than 20 exports.')
                        if sum(len(json.dumps(item).encode('utf-8')) for item in runs) + len(json.dumps(run).encode('utf-8')) > 24 * 1024 * 1024:
                            raise ValueError('This assessment exceeds the 24 MiB evidence limit. Remove older exports.')
                        server.vdt_sessions[key] = [*runs, run]
            except (ValueError, TypeError, RecursionError) as exc:
                self._send_json({'error': str(exc)}, 400)
                return
        elif action == 'remove':
            data = self._read_json_body()
            if not isinstance(data, dict):
                self._send_json({'error': 'Expected a JSON object.'}, 400)
                return
            with server.vdt_lock:
                runs = server.vdt_sessions.get(key, [])
                server.vdt_sessions[key] = [run for run in runs if run['id'] != data.get('id')]
        elif action == 'clear':
            with server.vdt_lock:
                server.vdt_sessions.pop(key, None)
        with server.vdt_lock:
            runs = list(server.vdt_sessions.get(key, []))
        if action == 'hybrid':
            with _state_lock:
                results = list(_state.get('results') or [])
                failed_hosts = list(_state.get('failed_hosts') or [])
                running = _state.get('running', False)
            if running:
                self._send_json({'error': 'Wait for the native assessment to finish before exporting.'}, 409)
                return
            if not runs or not (results or failed_hosts):
                self._send_json({'error': 'Import VDT evidence and complete or import a native Redfish assessment first.'}, 400)
                return
            from vcf_hci.report.hybrid import build_hybrid_summary, hybrid_html
            try:
                report = hybrid_html(build_hybrid_summary(results, failed_hosts, runs)).encode('utf-8')
            except Exception:
                logger.exception('Hybrid report export failed')
                self._send_json({'error': 'Could not generate the hybrid assessment report.'}, 500)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="00_hybrid_assessment.html"')
            self.send_header('Content-Length', str(len(report)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(report)
            return
        summaries = [{name: value for name, value in run.items() if name != 'findings'} for run in runs]
        for summary, run in zip(summaries, runs):
            summary['counts'] = dict(Counter(finding['status'] for finding in run['findings']))
        self._send_json({'runs': summaries}, extra_headers={'Cache-Control': 'no-store'})
