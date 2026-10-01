"""Load io_nics.json from a zipapp or a normal checkout via importlib.resources."""

import json
from typing import Optional

__all__ = ["load_packaged_io_nics"]


def load_packaged_io_nics() -> Optional[dict]:
    """Return the packaged catalog, or None when it is not in this install."""
    try:
        from importlib.resources import files
        resource = files("vcf_hci.hcl").joinpath("io_nics.json")
        if not resource.is_file():
            return None
        catalog = json.loads(resource.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(catalog, dict):
        return None
    return catalog
