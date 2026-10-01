"""Public CI Smoke Tests — Fast synthetic validation of the VCF Readiness Assessment Tool.

Tests core CLI argument parsing, synthetic hardware evaluation, and zero-dependency imports
using pure in-memory data with zero external dependencies or file fixtures.
Execution completes in < 1 second.
"""

import subprocess
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vcf_hci.compat_engine import (
    VCF9CompatibilityEngine,
    evaluate_boot_mode,
)
from vcf_hci.constants import TOOL_VERSION


class TestPublicSmoke(unittest.TestCase):
    """Synthetic unit tests runnable in public CI environments without lab captures."""

    def test_version_string(self):
        """Verify TOOL_VERSION is defined and semver-compliant."""
        self.assertIsInstance(TOOL_VERSION, str)
        parts = TOOL_VERSION.split(".")
        self.assertGreaterEqual(len(parts), 3, "Version must be at least major.minor.patch")

    def test_cli_help(self):
        """Verify CLI entry point responds to --help cleanly."""
        cmd = [sys.executable, str(PROJECT_ROOT / "vcfr_collector.py"), "--help"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        self.assertEqual(res.returncode, 0, f"CLI help failed: {res.stderr}")
        self.assertIn("Readiness Assessment Tool", res.stdout)
        self.assertIn("--targets", res.stdout)

    def test_cli_version(self):
        """Verify CLI entry point responds to --version."""
        cmd = [sys.executable, str(PROJECT_ROOT / "vcfr_collector.py"), "--version"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        self.assertEqual(res.returncode, 0)
        self.assertIn(TOOL_VERSION, res.stdout)

    def test_synthetic_cpu_evaluation(self):
        """Evaluate compatibility on synthetic CPU strings."""
        badge, arch, channels, _, _ = VCF9CompatibilityEngine.evaluate_cpu("Intel Xeon Gold 6338")
        self.assertIn("Ice Lake", arch)
        self.assertEqual(channels, 8)

    def test_synthetic_boot_mode_evaluation(self):
        """Evaluate boot mode evaluation rules."""
        uefi_res = evaluate_boot_mode("Uefi")
        self.assertIsInstance(uefi_res, (str, tuple, dict))

    def test_stdlib_purity_import(self):
        """Verify that importing core package modules requires only Python stdlib."""
        import vcf_hci
        import vcf_hci.cli
        import vcf_hci.compat_engine
        import vcf_hci.constants
        import vcf_hci.logging_utils
        import vcf_hci.vault.crypto
        import vcf_hci.vault.store
        import vcf_hci.web.server

        self.assertIsNotNone(vcf_hci.constants.TOOL_VERSION)

    def test_bundled_docs_strict_public_alignment(self):
        """Verify bundled documentation in vcf_hci/web/docs_data.py strictly aligns with public release."""
        import re

        from vcf_hci.web.docs_data import DOCS_DATA

        try:
            from tools.export_public_repo import DOCS_FILES, ROOT_FILES, STRICT_BLACKLIST_PATTERNS
            allowed_rel_paths = set(ROOT_FILES) | {f"docs/{f}" for f in DOCS_FILES}
            compiled_blacklists = [re.compile(p, re.I) for p in STRICT_BLACKLIST_PATTERNS]
        except ImportError:
            # When running in exported public tree (where export_public_repo is omitted)
            allowed_rel_paths = {
                "00_HOWTOLAUNCH.TXT", "ARCHITECTURE.md", "CONTRIBUTING.md", "LICENSE.md",
                "NOTICE", "THIRD_PARTY_LICENSES.md", "README.md", "pyproject.toml",
                "vcfr_collector.py", "vcfr_web.py", "redfish_collector.py", "redfish_web.py",
                ".gitignore",
                "docs/INSTALL.md", "docs/OEM_REFERENCE.md", "docs/adding-oem-support.md",
                "docs/SECURITY_ARCHITECTURE.md", "docs/CREDENTIAL_VAULT.md",
                "docs/INVENTORY_REFERENCE.md", "docs/USER_GUIDE_REFERENCE.md",
                "docs/REMOTE_JUMP_HOST_GUIDE.md", "docs/CUSTOMER_DELIVERABLE_SBOM.md",
            }
            compiled_blacklists = [
                re.compile(r"CHANGELOG\.md$", re.I),
                re.compile(r"docs/Management_Pack_Docs", re.I),
                re.compile(r"management_pack", re.I),
                re.compile(r"docs/plans", re.I),
                re.compile(r"docs/decisions", re.I),
            ]

        for doc_id, doc in DOCS_DATA.items():
            rel = doc.get("rel_path", "")
            self.assertIn(
                rel,
                allowed_rel_paths,
                f"Document '{rel}' (id: '{doc_id}') in DOCS_DATA is not in allowed document list!",
            )
            for pat in compiled_blacklists:
                self.assertIsNone(
                    pat.search(rel),
                    f"Document '{rel}' in DOCS_DATA matches blacklist pattern '{pat.pattern}'!",
                )


if __name__ == "__main__":
    unittest.main()
