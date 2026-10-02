#!/usr/bin/env python3
"""Scan customer-facing files for internal hostname/IP/infrastructure leakage.

Enforces the .cursorrules "Customer-Facing Data Hygiene" policy deterministically.
Exit 0 = clean. Exit 1 = violations found (printed as file:line: pattern).

Usage:
    python tools/check_data_hygiene.py            # scan default customer-facing paths
    python tools/check_data_hygiene.py --all      # scan the whole repo (advisory)
    python tools/check_data_hygiene.py PATH ...   # scan specific files/dirs
"""
import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Customer-facing surfaces: anything here ships to (or is visible to) customers.
DEFAULT_SCAN_PATHS = [
    "docs",
    "README.md",
    "INSTALL.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "ARCHITECTURE.md",
    "00_HOWTOLAUNCH.TXT",
    "LICENSE.md",
    "NOTICE",
    "THIRD_PARTY_LICENSES.md",
    "vcf_hci/web",
    "vcf_hci/report",
    "tests",
    "build-web.bat",
    "build-web.sh",
    "build.bat",
    "build.sh",
    "build_offline_package.sh",
]

TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".sh", ".bat", ".ps1", ".html", ".css", ".js",
    ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".rst",
}

# Each entry: (compiled regex, human-readable reason / suggested replacement)
VIOLATION_PATTERNS = [
    (re.compile(r"[a-z0-9._%+-]*@?[a-z0-9.-]*broadcom\.(?:net|com)", re.I),
     "internal Broadcom hostname — use packages.rainpole.net / pypi.rainpole.net"),
    (re.compile(r"[a-z0-9.-]*vmware\.com/(?!go/)", re.I),
     "internal VMware URL — use a rainpole.io example or a public docs.vmware.com/go link"),
    (re.compile(r"artifactory/api/pypi/(?!pypi-virtual/simple)[\w-]+", re.I),
     "internal Artifactory repo path — use /artifactory/api/pypi/pypi-virtual/simple"),
    (re.compile(r"\b10\.(?:162\.9|158\.212|211\.(?:156|144|180)|160\.\d{1,3}|191\.\d{1,3}|142\.\d{1,3}|132\.\d{1,3}|97\.\d{1,3}|34\.\d{1,3}|0\.70)(?:\.\d{1,3})?(?:/\d{1,2})?\b"),
     "lab datacenter/BMC IP or subnet — use RFC 5737 documentation IPs (192.0.2.x / 198.51.100.x / 203.0.113.x)"),
    (re.compile(r"\b10\.(?!0\.0\.)\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b"),
     "unauthorized private 10.x IP/subnet — use RFC 5737 documentation IPs or generic 10.0.0.x placeholder"),
    (re.compile(r"\b((Normal|vSAN-PE|IOV)\s*Lab|IOV-Lab|Model-Run)\b", re.I),
     "internal lab group name — use generic enterprise fleet description"),
    (re.compile(r"/etc/vcf-lab", re.I),
     "internal lab configuration path — remove reference"),
    (re.compile(r"/(?:Users|home)/[a-zA-Z0-9_-]+/(?:Documents|Downloads|Desktop|projects|Redfish-Library|Staging-VCFR)", re.I),
     "developer workstation path — remove reference"),
    (re.compile(r"\b(lvnlvcf|lvcf|w[0-9]-hs[0-9])[\w.-]*", re.I),
     "internal lab BMC hostname — use rainpole.net hostnames"),
    (re.compile(r"\.(lvn\.broad|corp\.local|lab\.local)\b", re.I),
     "internal corporate/lab domain suffix — use .rainpole.net / .example.com"),
    (re.compile(r"\busw1-edge[\w.-]*", re.I),
     "internal edge/package host — use packages.rainpole.net"),
    (re.compile(r"\bvcfd\.[\w.-]+", re.I),
     "internal VCF infra domain — use rainpole.net"),
    (re.compile(r"\b(jumpbox|installation-04|vcf-jump-box|win-build(?!\.rainpole\.net))\b", re.I),
     "internal build/jump infrastructure reference — remove or genericize (win-build.rainpole.net is OK)"),
    (re.compile(r"[A-Za-z]:\\\\?(dropbox|Dropbox|Users\\\\?john)[\w\\.-]*"),
     "developer-local Windows path — remove"),
    (re.compile(r"\bDump-Redfish1-2\.sh\b", re.I),
     "deleted legacy BMC dump script — use tools/redfishMockupCreate.py"),
    (re.compile(r"\b(remote_log_tool|setup_lab_jump_host|remote_lab_smoke|generate_lab_inventory|set_bmc_credentials)\.sh\b", re.I),
     "deleted internal lab script — remove reference"),
    (re.compile(r"\b(lab_fleet_smoke|oem_expand_live_benchmark|enroll_iov_credentials|probe_jump_targets|generate_extended_inventory|run_remote)\.(py|sh)\b", re.I),
     "internal lab runner script — remove reference"),
]

# Substrings that are always fine (checked case-insensitively against the matched text).
ALLOWLIST = [
    "rainpole.io",
    "rainpole.net",
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
    "github.com/johnnicholson-vmw",   # public repo URL is intentional
    "github.com/vmware/vcf-readiness", # official public repository URL
    "compatibilityguide.broadcom.com",
    "knowledge.broadcom.com",
    "vvs.broadcom.com",
    "www.broadcom.com",
    "docs.broadcom.com",
    "techdocs.broadcom.com",
    "support.broadcom.com",
    "developer.broadcom.com",
    "vcf.broadcom.com",
    "configmax.broadcom.com",
    "projects.packages.broadcom.com",
    "projects.registry.vmware.com",
    "vsan-hcl.pdl@broadcom.com",
    "vsansizer.vmware.com",
    "docs.vmware.com",
    "www.vmware.com/docs/",
    "www.vmware.com",
    "kb.vmware.com",
    "schemas.vmware.com",
    "blogs.vmware.com",
    "core.vmware.com",
    "techzone.vmware.com",
    "developer.vmware.com",
]


def is_allowlisted(matched_text: str) -> bool:
    low = matched_text.lower()
    return any(a.lower() in low for a in ALLOWLIST)


INTERNAL_DIRS = {"__pycache__", "plans", "Management_Pack_Docs", "Internal Plans and things", "fixtures"}
EXCLUDED_FILES = {"assets.py", "docs_data.py", "check_data_hygiene.py", "test_data_hygiene.py"}
PUBLIC_TEST_FILES = {
    "__init__.py", "test_public_smoke.py", "test_data_hygiene.py",
    "test_no_forbidden_imports.py", "test_vault_crypto.py",
    "test_vault_provider_tls.py", "test_logging_utils.py",
}


def iter_files(paths):
    for raw in paths:
        p = (REPO_ROOT / raw) if not Path(raw).is_absolute() else Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in TEXT_EXTENSIONS:
                    if any(part in INTERNAL_DIRS for part in f.parts):
                        continue
                    if f.name in EXCLUDED_FILES:
                        continue
                    # In dev workspaces with internal lab/replay suites, only test public synthetic files
                    if "tests" in f.parts and f.name.endswith(".py"):
                        if (REPO_ROOT / "tests" / "test_replay_crawled_samples.py").exists():
                            if f.name not in PUBLIC_TEST_FILES:
                                continue
                    yield f


def scan_file(path: Path):
    violations = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return violations
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern, reason in VIOLATION_PATTERNS:
            for m in pattern.finditer(line):
                matched = m.group(0)
                if not is_allowlisted(matched):
                    violations.append((path, lineno, matched, reason))
    return violations


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="files/dirs to scan (default: customer-facing set)")
    parser.add_argument("--all", action="store_true", help="scan entire repo (advisory mode)")
    args = parser.parse_args(argv)

    paths = args.paths or (["."] if args.all else DEFAULT_SCAN_PATHS)
    all_violations = []
    for f in iter_files(paths):
        all_violations.extend(scan_file(f))

    if all_violations:
        print(f"DATA HYGIENE: {len(all_violations)} violation(s) found:\n")
        for path, lineno, match, reason in all_violations:
            rel = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
            print(f"  {rel}:{lineno}: '{match}'\n      -> {reason}")
        print("\n[DATA_HYGIENE_STATUS: FAILED]")
        return 1
    print("[DATA_HYGIENE_STATUS: PASSED]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
