"""
vcf_hci package __main__.py — enables `python -m vcf_hci`.

Run the VCF Readiness Assessment CLI:
    python -m vcf_hci --targets 10.0.0.1
    python -m vcf_hci --targets "10.0.0.0/24" --threads 8
"""
from vcf_hci.cli import main

if __name__ == "__main__":
    main()
