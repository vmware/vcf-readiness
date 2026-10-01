#!/usr/bin/env python3
"""
VCF / vSphere 9.1 Readiness Assessment Tool — CLI Entry Point.

This is the primary command-line interface for the VCF Readiness Tool.
All core logic is implemented in the vcf_hci/ package.

Usage:
    python vcfr_collector.py --targets 10.0.0.1
    python vcfr_collector.py --targets "192.168.1.0/24" --threads 8
    python -m vcf_hci --targets 10.0.0.1

No external dependencies. Requires Python 3.9+.
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

# Re-export everything so callers importing from vcfr_collector work seamlessly
from vcf_hci import *  # noqa: F403
from vcf_hci.cli import main

# Optional Service Tag feature — available when Dell TechDirect credentials are configured
from vcf_hci.servicetag import (  # noqa: F401
    DellTechDirectClient,
    evaluate_esa_from_components,
    summarise_warranty,
)

if __name__ == "__main__":
    main()
