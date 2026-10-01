"""
VCF Readiness Tool — Web API Mixin Facade (vcf_hci.web.api_mixin)

Barrel facade composing endpoint-group mixins into ApiMixin for AppHandler.
"""

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from http.server import SimpleHTTPRequestHandler
    class _ApiMixinBase(SimpleHTTPRequestHandler):
        def _send_json(self, obj: Any, status: int = 200, extra_headers: Optional[dict] = None) -> None: ...
        def _send_html(self, html: str, status: int = 200, extra_headers: Optional[dict] = None) -> None: ...
        def _read_json_body(self) -> dict: ...
        def _send_error_json(self, msg: str, code: int = 400) -> None: ...
        def _require_auth(self) -> bool: ...
        def _get_request_session_token(self) -> Optional[str]: ...
        def _cors_headers(self) -> None: ...
        def _is_remote_server(self) -> bool: ...
else:
    _ApiMixinBase = object

from vcf_hci.web.export_api import ExportApiMixin
from vcf_hci.web.fleet_api import FleetApiMixin
from vcf_hci.web.import_api import ImportApiMixin
from vcf_hci.web.jump_api import JumpApiMixin
from vcf_hci.web.scan_api import ScanApiMixin
from vcf_hci.web.security_api import SecurityApiMixin
from vcf_hci.web.session_api import SessionApiMixin

_COLLECTOR_OK = True


class ApiMixin(
    JumpApiMixin,
    ScanApiMixin,
    ImportApiMixin,
    ExportApiMixin,
    FleetApiMixin,
    SessionApiMixin,
    SecurityApiMixin,
    _ApiMixinBase,
):
    """HTTP JSON API handlers mixed into AppHandler."""
    pass


__all__ = [
    "ApiMixin",
    "ExportApiMixin",
    "FleetApiMixin",
    "ImportApiMixin",
    "ScanApiMixin",
    "SecurityApiMixin",
    "SessionApiMixin",
    "_ApiMixinBase",
    "_COLLECTOR_OK",
]
