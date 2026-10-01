"""
VCF Readiness Tool — HCL management package.

Re-exports all HCL loader and bundle management functions.
"""
from .bundle_manager import (
    HCLBundleManager,
    create_hcl_bundle,
    ensure_auto_hcl_bundle,
    get_hcl_dir,
    import_hcl_bundle,
)
from .cross_reference import (
    cross_reference_device,
    cross_reference_drive,
    detect_qlc_nvme,
    evaluate_drive_hcl_tier,
    lookup_unique_hcl_device,
)
from .loader import (
    clear_hcl_caches,
    get_hcl_cache_status,
    load_optional_vsan_csv,
    load_vsan_hcl_json,
    sanitize_hcl_entry,
)

__all__ = [
    "HCLBundleManager",
    "clear_hcl_caches",
    "create_hcl_bundle",
    "cross_reference_device",
    "cross_reference_drive",
    "detect_qlc_nvme",
    "ensure_auto_hcl_bundle",
    "evaluate_drive_hcl_tier",
    "get_hcl_cache_status",
    "get_hcl_dir",
    "import_hcl_bundle",
    "load_optional_vsan_csv",
    "load_vsan_hcl_json",
    "lookup_unique_hcl_device",
    "sanitize_hcl_entry",
]
