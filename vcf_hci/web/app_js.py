"""
Client-side JavaScript (SSE client, form logic, dark mode, HCL, vault) for the web UI.

Assembled from modular sub-components in ``vcf_hci.web.js``:
- ``core.py``: Theme management, shutdown handler, DOM/network helpers, session persistence, profile management.
- ``vault.py``: TOFU certificate trust inspection, credential testing, credential vault UI, keychain.
- ``scan.py``: Server-Sent Events (SSE) listener, host cards, progress tracking, stage management, scan trigger.
- ``hcl.py``: Dark-Site HCL bundle management, upload, additive retry, offline summary import.
- ``actions.py``: Fleet actions, report launchers, Excel/CSV/JSON exports, pre-render, pagination, fleet library modal.
"""

from vcf_hci.web.js import (
    JS_ACTIONS,
    JS_CORE,
    JS_HCL,
    JS_JUMP,
    JS_SCAN,
    JS_VAULT,
)

__all__ = ["APP_JS"]

APP_JS = "".join([
    '\n(function () {\n  "use strict";\n',
    JS_CORE,
    JS_VAULT.lstrip("\n"),
    JS_JUMP.lstrip("\n"),
    JS_SCAN.lstrip("\n"),
    JS_HCL.lstrip("\n"),
    JS_ACTIONS.lstrip("\n"),
    "})();\n",
])
