"""Authenticated browser download of an offline HCL dataset snapshot."""

import logging

from vcf_hci.hcl.export_bundle import HclExportError, export_active_hcl_bundle
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.web.export_api import _ApiMixinBase
from vcf_hci.web.scan_worker import _state, _state_lock

logger = logging.getLogger("vcf_assess")


class HclExportApiMixin(_ApiMixinBase):
    """Mixed into AppHandler; its authenticated GET dispatch protects this route."""

    def _api_hcl_export(self) -> None:
        with _state_lock:
            custom_path = _state.get("custom_hcl_bundle_path")
        try:
            payload = export_active_hcl_bundle(custom_path)
        except HclExportError as exc:
            logger.warning("Offline HCL dataset export unavailable: %s", exc)
            self._send_json({"error": str(exc)}, 409, {"Cache-Control": "no-store"})
            return
        except Exception:
            logger.exception("Offline HCL dataset export failed")
            self._send_json({"error": "Could not export HCL datasets; see the server log for details."}, 500,
                            {"Cache-Control": "no-store"})
            return
        filename = sanitize_filename("vcf_hcl_bundle_offline.zip")
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)
