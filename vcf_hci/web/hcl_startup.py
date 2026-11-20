"""Background HCL refresh for an online Web UI launch."""
import logging
import threading
from typing import Optional

logger = logging.getLogger('vcf_assess')


def start_hcl_refresh(disabled: bool = False, imported_bundle: Optional[str] = None) -> Optional[threading.Thread]:
    if disabled or imported_bundle:
        return None

    def refresh() -> None:
        from vcf_hci.hcl.bundle_manager import create_hcl_bundle
        from vcf_hci.hcl.loader import load_vsan_hcl_json
        try:
            load_vsan_hcl_json(refresh_live=True)
            create_hcl_bundle()
        except Exception as exc:
            logger.warning('Startup HCL refresh failed; retaining offline data: %s', exc)

    worker = threading.Thread(target=refresh, name='hcl-startup-refresh', daemon=True)
    worker.start()
    return worker
