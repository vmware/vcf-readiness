#!/usr/bin/env python3
"""
VCF Readiness — Browser UI entry point.

Clarity-styled web app interface.
Starts a temporary HTTP server bound to 127.0.0.1 (or specified host), opens the default browser,
and runs until the user clicks Quit or presses Ctrl-C.

Usage:
    python vcfr_web.py
    python -m vcf_hci.web
    vcf-readiness-web

No external dependencies. Requires Python 3.9+ and a browser.
"""
import os
import sys

# Ensure vcf_hci package directory is in sys.path regardless of execution path or working directory
_script_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_script_dir)
for _d in (_script_dir, _parent_dir):
    if _d and _d not in sys.path and os.path.isdir(os.path.join(_d, "vcf_hci")):
        sys.path.insert(0, _d)
        break

from vcf_hci.web import main

if __name__ == "__main__":
    main()
