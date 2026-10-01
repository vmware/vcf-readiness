"""Tests for tools/check_data_hygiene.py — the internal-hostname leakage scanner."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import check_data_hygiene as cdh


def _scan_text(tmp_path, text, name="doc.md"):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return cdh.scan_file(f)


def test_detects_internal_broadcom_hostname(tmp_path):
    target_url = "https://packages.vcfd." + "broadcom" + ".net/simple"
    hits = _scan_text(tmp_path, f"pip install --index-url {target_url} foo")
    assert hits, "internal broadcom.net hostname must be flagged"


def test_detects_lab_ip(tmp_path):
    lab_ip = "10.160." + "12.34"
    assert _scan_text(tmp_path, f"Connect to the BMC at {lab_ip} for testing.")
    bmc_ip = "10.0." + "70.17"
    assert _scan_text(tmp_path, f"Captured from {bmc_ip}")


def test_detects_lab_hostname_and_domain(tmp_path):
    bmc_host = "lvnlvcf" + "stgtmmc55"
    assert _scan_text(tmp_path, f"Target BMC: {bmc_host}")
    domain_suffix = ".corp" + ".local"
    assert _scan_text(tmp_path, f"Host domain: server01{domain_suffix}")


def test_detects_lab_jump_aliases(tmp_path):
    host = "installation" + "-04"
    alias = "vcf-jump" + "-box"
    assert _scan_text(tmp_path, "Checking reachability to " + host)
    assert _scan_text(tmp_path, "builder@" + alias)
    # Negative: fictitious example used in INSTALL.md must stay clean
    assert _scan_text(tmp_path, "builder@win-build.rainpole.net") == []


def test_detects_legacy_scripts(tmp_path):
    script_name = "Dump-Redfish" + "1-2.sh"
    assert _scan_text(tmp_path, f"Run {script_name} to dump BMC")


def test_detects_artifactory_internal_path(tmp_path):
    repo_path = "/artifactory/api/pypi/" + "gateway-pypi-vr/simple"
    assert _scan_text(tmp_path, f"use {repo_path} as index")


def test_detects_lab_group_names(tmp_path):
    assert _scan_text(tmp_path, "Results from Normal Lab testing")
    assert _scan_text(tmp_path, "Host verified in vSAN-PE Lab cluster")
    assert _scan_text(tmp_path, "Multi-OEM verification in IOV Lab")
    assert _scan_text(tmp_path, "Inventory discovered from IOV-Lab")
    assert _scan_text(tmp_path, "Captures stored under Model-Run directory")
    assert _scan_text(tmp_path, "Config loaded from /etc/vcf-lab/inventory.json")


def test_detects_specific_lab_subnets(tmp_path):
    assert _scan_text(tmp_path, "Normal Lab subnet 10.162.9.0/24 verified")
    assert _scan_text(tmp_path, "vSAN-PE subnet 10.158.212.0/24 scanned")
    assert _scan_text(tmp_path, "IOV subnet 10.211.156.0/24 responsive")
    assert _scan_text(tmp_path, "Subsystem address at 10.211.144.13")
    assert _scan_text(tmp_path, "Host IP at 10.211.180.12")


def test_detects_developer_workstation_paths(tmp_path):
    assert _scan_text(tmp_path, "Path: /Users/nicholsonj/Documents/Redfish-Library/scans")
    assert _scan_text(tmp_path, "Evidence at /Users/developer/Desktop/VCF-Scans/run-1")
    assert _scan_text(tmp_path, "Output: /home/builder/projects/vcf-readiness")


def test_jump_host_does_not_mask_violations_on_same_line(tmp_path):
    # 'jump host' on the same line must NOT suppress detection of lab IPs, names, or hosts
    text = "Access via remote jump host to installation-04 at 10.160.177.30 in Normal Lab."
    hits = _scan_text(tmp_path, text)
    assert len(hits) >= 3, f"Expected multiple violations on line with 'jump host', got: {hits}"
    matched_tokens = [h[2] for h in hits]
    assert any("installation-04" in t for t in matched_tokens)
    assert any("Normal Lab" in t for t in matched_tokens)


def test_detects_internal_lab_runner_scripts(tmp_path):
    assert _scan_text(tmp_path, "Run lab_fleet_smoke.py for diagnostics")
    assert _scan_text(tmp_path, "Benchmarked via oem_expand_live_benchmark.py")
    assert _scan_text(tmp_path, "Execute enroll_iov_credentials.sh")
    assert _scan_text(tmp_path, "Probed targets using probe_jump_targets.py")


def test_allows_generic_placeholders_and_documentation_ips(tmp_path):
    text = (
        "Default target: 10.0.0.1\n"
        "Subnet mask: 10.0.0.0/24 or 10.0.0.0/16 or 10.0.0.0/8\n"
        "Office subnet: 192.168.1.0/24\n"
        "Documentation IPs: 192.0.2.1, 198.51.100.5, 203.0.113.10\n"
        "Loopback address: 127.0.0.1\n"
        "Fictitious domain: esxi-01.rainpole.net and win-build.rainpole.net\n"
    )
    assert _scan_text(tmp_path, text) == []


def test_rainpole_examples_are_clean(tmp_path):
    text = (
        "Configure your internal mirror at packages.rainpole.net\n"
        "Public example: https://portal.rainpole.io/login\n"
        "Scan BMC at 192.0.2.10 and 198.51.100.7\n"
        "Internal index: /artifactory/api/pypi/pypi-virtual/simple\n"
    )
    assert _scan_text(tmp_path, text) == []


def test_allowlisted_repo_url_is_clean(tmp_path):
    assert _scan_text(tmp_path, "Report bugs at https://github.com/johnnicholson-vmw/vcf-readiness/issues") == []
    assert _scan_text(tmp_path, "Report bugs at https://github.com/vmware/vcf-readiness/issues") == []


def test_public_broadcom_and_vmware_urls_are_clean(tmp_path):
    text = (
        "Search BCG at https://compatibilityguide.broadcom.com/\n"
        "KB reference: https://knowledge.broadcom.com/external/article/428874\n"
        "HCL data feed: https://vvs.broadcom.com/service/vsan/all.json\n"
        "Security center: https://www.broadcom.com/support/security-center\n"
        "Docs: https://docs.vmware.com/ or https://kb.vmware.com/s/article/330041\n"
        "Image: projects.registry.vmware.com/aria-operations-integration-sdk/python-base:0.9.0\n"
        "Contact: vsan-hcl.pdl@broadcom.com\n"
    )
    assert _scan_text(tmp_path, text) == []


def test_customer_facing_tree_is_currently_clean():
    """The real repo's customer-facing surfaces must scan clean (the actual gate)."""
    assert cdh.main([]) == 0
