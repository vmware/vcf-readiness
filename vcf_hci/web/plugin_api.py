"""Authenticated, session-local VDT imports and hybrid HTML download."""

import json
import logging
from collections import Counter
from typing import Any

from vcf_hci.plugins.vdt import parse_vdt_export
from vcf_hci.web.export_api import _ApiMixinBase
from vcf_hci.web.remote_vdt_api import remote_collection_available, remote_collection_capabilities
from vcf_hci.web.scan_worker import _state, _state_lock

logger = logging.getLogger('vcf_assess')


class PluginApiMixin(_ApiMixinBase):
    """No tool execution, server-path imports, or appliance credentials."""

    def _plugin_session_key(self) -> str:
        handler: Any = self
        return handler._current_session() or ''

    def _api_plugins(self) -> None:
        server: Any = self.server
        catalog = dict(server.vdt_plugin)
        catalog['remote_collection'] = remote_collection_capabilities(remote_collection_available(server))
        self._send_json({'vdt': catalog}, extra_headers={'Cache-Control': 'no-store'})

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
