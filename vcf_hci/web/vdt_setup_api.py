"""Local, authenticated ZIP installation and anonymous vCenter version discovery."""

from pathlib import Path
from typing import Any

from vcf_hci.plugins.vcenter_probe import probe_vcenter, select_vdt
from vcf_hci.plugins.vdt import discover_vdt
from vcf_hci.plugins.vdt_install import MAX_ZIP_BYTES, install_vdt_zip
from vcf_hci.web.export_api import _ApiMixinBase
from vcf_hci.web.remote_vdt_api import _normalize_appliance_host, remote_collection_available


class VdtSetupApiMixin(_ApiMixinBase):
    """Install inert packages and match product versions before requesting secrets."""

    def _api_vdt_install(self) -> None:
        handler: Any = self
        server: Any = self.server
        if not remote_collection_available(server):
            self._send_json({'error': 'VDT ZIP installation is available only from the local web listener.'}, 403)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except (TypeError, ValueError):
            length = 0
        if length <= 0 or length > MAX_ZIP_BYTES:
            handler.close_connection = True
            self._send_json({'error': 'Choose a ZIP package no larger than 32 MiB.'}, 413)
            return
        content_type = self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
        if content_type not in ('application/zip', 'application/octet-stream'):
            handler.close_connection = True
            self._send_json({'error': 'Upload the original VDT ZIP file.'}, 400)
            return
        previous_timeout = handler.connection.gettimeout()
        try:
            handler.connection.settimeout(30)
            archive = handler.rfile.read(length)
            if len(archive) != length:
                raise ValueError('The ZIP upload was incomplete.')
            with server.vdt_lock:
                if any(job['status'] not in ('completed', 'failed', 'cancelled', 'needs_credentials')
                       for job in server.vdt_remote_jobs.values()):
                    self._send_json({'error': 'Wait for the active VDT collection to finish before installing packages.'}, 409)
                    return
                installed = install_vdt_zip(archive, Path(server.vdt_plugin_root))
                server.vdt_plugin = discover_vdt(server.vdt_plugin_root)
                catalog = dict(server.vdt_plugin)
            self._send_json({'installed': installed, 'vdt': catalog}, extra_headers={'Cache-Control': 'no-store'})
        except (ValueError, OSError) as exc:
            self._send_json({'error': str(exc)}, 400)
        finally:
            handler.connection.settimeout(previous_timeout)

    def _api_vdt_discover(self) -> None:
        server: Any = self.server
        if not remote_collection_available(server):
            self._send_json({'error': 'vCenter discovery is available only from the local web listener.'}, 403)
            return
        data = self._read_json_body()
        if not isinstance(data, dict):
            self._send_json({'error': 'Expected a JSON object.'}, 400)
            return
        try:
            host = _normalize_appliance_host(data.get('host'))
            port = data.get('https_port', 443)
            detected = probe_vcenter(host, port=port)
            with server.vdt_lock:
                installations = list(server.vdt_plugin.get('installations', []))
            selection = select_vdt(installations, detected['version'])
            self._send_json({'vcenter': detected, 'selection': selection}, extra_headers={'Cache-Control': 'no-store'})
        except (ValueError, OSError) as exc:
            self._send_json({'error': str(exc)}, 400)
