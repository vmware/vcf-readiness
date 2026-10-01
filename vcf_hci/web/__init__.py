"""
VCF Readiness Tool — browser-based UI package.

Start the web UI with vcfr_web.py, python -m vcf_hci.web, or vcf-readiness-web.
(redfish_web.py is also supported as a backward-compat shim).
Nothing in this package imports Tkinter.
"""
def main(*args, **kwargs):
    from vcf_hci.web.server import main as _server_main
    return _server_main(*args, **kwargs)

__all__ = ["main"]
