"""
Tests for vcf_hci/logging_utils.py
"""
import json
import logging
import os
import socket
import tempfile
import unittest
import zipfile
from unittest import mock

from vcf_hci.logging_utils import (
    CloudMetadataBlocked,
    configure_logging,
    create_obfuscated_scan_zip_archive,
    create_pinned_connection,
    create_scan_zip_archive,
    get_nested,
    is_cloud_metadata_target,
    normalize_output_dir,
    parse_ip_targets,
    parse_version_tuple,
    resolve_pinned_addresses,
    sanitize_filename,
    update_latest_scan_aliases,
)


class TestSanitizeFilename(unittest.TestCase):
    def test_sanitize_filename_basic(self):
        self.assertEqual(sanitize_filename("10.0.0.1"), "10.0.0.1")
        self.assertEqual(sanitize_filename("host:port"), "host_port")
        self.assertEqual(sanitize_filename("a/b\\c*d?e\"f<g>h|i"), "a_b_c_d_e_f_g_h_i")

    def test_sanitize_filename_strips_whitespace(self):
        self.assertEqual(sanitize_filename("  test_file.txt  "), "test_file.txt")


class TestParseIPTargets(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(parse_ip_targets("10.0.0.1"), ["10.0.0.1"])

    def test_comma_separated_ips(self):
        self.assertEqual(
            parse_ip_targets("10.0.0.1, 10.0.0.2, 10.0.0.3"),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )

    def test_ip_range(self):
        self.assertEqual(
            parse_ip_targets("192.168.1.10-14"),
            [
                "192.168.1.10",
                "192.168.1.11",
                "192.168.1.12",
                "192.168.1.13",
                "192.168.1.14",
            ],
        )

    def test_cidr_notation(self):
        targets = parse_ip_targets("10.0.0.0/30")
        self.assertEqual(targets, ["10.0.0.1", "10.0.0.2"])

    def test_invalid_cidr_fallback(self):
        self.assertEqual(parse_ip_targets("invalid/cidr"), [])

    def test_deduplication(self):
        self.assertEqual(
            parse_ip_targets("10.0.0.1, 10.0.0.1, 10.0.0.2"),
            ["10.0.0.1", "10.0.0.2"],
        )

    def test_mixed_inputs(self):
        res = parse_ip_targets("10.0.0.1, 10.0.0.2-3, host.local")
        self.assertEqual(res, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "host.local"])


class TestParseVersionTuple(unittest.TestCase):
    def test_valid_versions(self):
        self.assertEqual(parse_version_tuple("6.10.1"), (6, 10, 1, 0))
        self.assertEqual(parse_version_tuple("9.1"), (9, 1, 0, 0))
        self.assertEqual(parse_version_tuple("2.0.0-rc1"), (2, 0, 0, 0))
        self.assertEqual(parse_version_tuple("7.20.10.50"), (7, 20, 10, 50))
        self.assertEqual(parse_version_tuple("7.20.10.181"), (7, 20, 10, 181))
        self.assertTrue(parse_version_tuple("7.20.10.50") < parse_version_tuple("7.20.10.181"))

    def test_invalid_and_empty_versions(self):
        self.assertEqual(parse_version_tuple(""), (0, 0, 0, 0))
        self.assertEqual(parse_version_tuple(None), (0, 0, 0, 0))
        self.assertEqual(parse_version_tuple("no_numbers"), (0, 0, 0, 0))


class TestGetNested(unittest.TestCase):
    def test_valid_nested_dict(self):
        d = {"Oem": {"Dell": {"DellProcessor": {"Cache": [{"Size": 1024}]}}}}
        self.assertEqual(
            get_nested(d, "Oem", "Dell", "DellProcessor", "Cache"),
            [{"Size": 1024}],
        )

    def test_intermediate_null_value(self):
        d = {"Oem": None}
        self.assertIsNone(get_nested(d, "Oem", "Dell", "DellProcessor", "Cache"))
        self.assertEqual(
            get_nested(d, "Oem", "Dell", "DellProcessor", "Cache", default=[]),
            [],
        )

    def test_nested_null_value(self):
        d = {"Oem": {"Dell": {"DellProcessor": None}}}
        self.assertEqual(
            get_nested(d, "Oem", "Dell", "DellProcessor", "Cache", default="N/A"),
            "N/A",
        )

    def test_non_dict_root_or_leaf(self):
        self.assertEqual(get_nested(None, "a", "b", default={}), {})
        self.assertEqual(get_nested("not_a_dict", "a", "b", default=123), 123)
        d = {"a": 42}
        self.assertEqual(get_nested(d, "a", "b", default="fallback"), "fallback")


class TestConfigureLogging(unittest.TestCase):
    def test_configure_logging_debug_and_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.log")
            configure_logging(debug=True, log_file=log_file)
            logger = logging.getLogger("vcf_assess")
            self.assertEqual(logger.level, logging.DEBUG)
            logger.debug("test debug message")
            self.assertTrue(os.path.exists(log_file))
            with open(log_file, encoding="utf-8") as f:
                content = f.read()
                self.assertIn("test debug message", content)

    def test_configure_logging_append_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test_append.log")
            configure_logging(debug=True, log_file=log_file, mode="w")
            logger = logging.getLogger("vcf_assess")
            logger.debug("first pass message")

            # Reconfigure in append mode
            configure_logging(debug=True, log_file=log_file, mode="a")
            logger = logging.getLogger("vcf_assess")
            logger.debug("second pass message")

            with open(log_file, encoding="utf-8") as f:
                content = f.read()
                self.assertIn("first pass message", content)
                self.assertIn("second pass message", content)

    def test_configure_logging_file_permissions_0o600(self):
        if os.name != "posix":
            self.skipTest("File permission 0o600 test is POSIX specific")
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "secure_test.log")
            configure_logging(debug=True, log_file=log_file)
            st_mode = os.stat(log_file).st_mode & 0o777
            self.assertEqual(st_mode, 0o600)


class TestScanOutputAndAliases(unittest.TestCase):
    def test_create_scan_zip_archive_default_location(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = os.path.join(tmpdir, "Scan_2026-08-19_1430_2hosts")
            os.makedirs(scan_dir, exist_ok=True)
            summary_path = os.path.join(scan_dir, "00_fleet_summary.html")
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write("<html>Summary</html>")

            zip_path = create_scan_zip_archive(scan_dir)

            expected_zip_path = os.path.join(scan_dir, "Scan_2026-08-19_1430_2hosts.zip")
            self.assertEqual(zip_path, expected_zip_path)
            self.assertTrue(os.path.isfile(zip_path))

            import zipfile
            with zipfile.ZipFile(zip_path, "r") as zf:
                namelist = zf.namelist()
                self.assertIn("Scan_2026-08-19_1430_2hosts/00_fleet_summary.html", namelist)
                self.assertNotIn("Scan_2026-08-19_1430_2hosts/Scan_2026-08-19_1430_2hosts.zip", namelist)

    def test_update_latest_scan_aliases_creates_and_removes_aliases(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = tmpdir
            scan_dir = os.path.join(base_dir, "Scan_2026-08-19_1430_2hosts")
            os.makedirs(scan_dir, exist_ok=True)

            # Pre-create a stale combined alias in base_dir
            stale_combined_alias = os.path.join(base_dir, "!00_LATEST_FLEET_COMBINED.html")
            with open(stale_combined_alias, "w", encoding="utf-8") as f:
                f.write("stale")

            # Create summary report only in scan_dir
            summary_file = os.path.join(scan_dir, "00_fleet_summary.html")
            with open(summary_file, "w", encoding="utf-8") as f:
                f.write("summary content")

            aliases = update_latest_scan_aliases(scan_dir=scan_dir, base_dir=base_dir)

            summary_alias = os.path.join(base_dir, "!00_LATEST_FLEET_SUMMARY.html")
            self.assertTrue(os.path.isfile(summary_alias))
            self.assertIn(summary_alias, aliases)

            with open(summary_alias, encoding="utf-8") as f:
                content = f.read()
                self.assertIn("Scan_2026-08-19_1430_2hosts/00_fleet_summary.html", content)
                self.assertIn('<meta http-equiv="refresh"', content)

            # Stale combined alias should be removed
            self.assertFalse(os.path.isfile(stale_combined_alias))

    def test_update_latest_scan_aliases_obfuscated_reports(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = tmpdir
            scan_dir = os.path.join(base_dir, "Scan_2026-08-19_1435_4hosts_obf")
            os.makedirs(scan_dir, exist_ok=True)

            with open(os.path.join(scan_dir, "00_fleet_summary.html"), "w") as f:
                f.write("summary")
            with open(os.path.join(scan_dir, "00_fleet_combined.html"), "w") as f:
                f.write("combined")
            with open(os.path.join(scan_dir, "00_OBFUSCATED_fleet_summary.html"), "w") as f:
                f.write("obf summary")
            with open(os.path.join(scan_dir, "00_OBFUSCATED_fleet_combined.html"), "w") as f:
                f.write("obf combined")

            update_latest_scan_aliases(scan_dir=scan_dir, base_dir=base_dir)

            self.assertTrue(os.path.isfile(os.path.join(base_dir, "!00_LATEST_FLEET_SUMMARY.html")))
            self.assertTrue(os.path.isfile(os.path.join(base_dir, "!00_LATEST_FLEET_COMBINED.html")))
            self.assertTrue(os.path.isfile(os.path.join(base_dir, "!00_LATEST_OBFUSCATED_FLEET_SUMMARY.html")))
            self.assertTrue(os.path.isfile(os.path.join(base_dir, "!00_LATEST_OBFUSCATED_FLEET_COMBINED.html")))

    def test_normalize_output_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            desktop = os.path.join(tmpdir, "Desktop")
            os.makedirs(desktop, exist_ok=True)
            norm = normalize_output_dir(desktop)
            self.assertTrue(norm.endswith("VCF-Scans"))
            self.assertEqual(norm, os.path.join(desktop, "VCF-Scans"))

            # Path that already ends in VCF-Scans
            vcf_scans = os.path.join(desktop, "VCF-Scans")
            norm_vcf = normalize_output_dir(vcf_scans)
            self.assertEqual(norm_vcf, os.path.abspath(vcf_scans))

            # Empty input falls back to get_default_output_dir
            self.assertTrue(normalize_output_dir("").endswith("VCF-Scans"))
            self.assertTrue(normalize_output_dir(None).endswith("VCF-Scans"))

    def test_update_latest_scan_aliases_debug_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = tmpdir
            scan_dir = os.path.join(base_dir, "Scan_2026-08-19_1440_1host")
            data_dir = os.path.join(scan_dir, "data")
            os.makedirs(data_dir, exist_ok=True)

            debug_file = os.path.join(data_dir, "vcf_assess_debug.log")
            with open(debug_file, "w", encoding="utf-8") as f:
                f.write("debug log contents")

            update_latest_scan_aliases(scan_dir=scan_dir, base_dir=base_dir)

            latest_dbg = os.path.join(base_dir, "!00_LATEST_vcf_assess_debug.log")
            self.assertTrue(os.path.isfile(latest_dbg))
            with open(latest_dbg, encoding="utf-8") as f:
                self.assertEqual(f.read(), "debug log contents")

            # Remove debug file in scan_dir and verify alias gets removed on next update
            os.remove(debug_file)
            update_latest_scan_aliases(scan_dir=scan_dir, base_dir=base_dir)
            self.assertFalse(os.path.isfile(latest_dbg))


class TestCreateObfuscatedScanZipArchive(unittest.TestCase):
    def test_create_obfuscated_scan_zip_archive_strict_filtering(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = os.path.join(tmpdir, "run-test-scan")
            reports_dir = os.path.join(scan_dir, "reports")
            data_dir = os.path.join(scan_dir, "data")
            hosts_dir = os.path.join(scan_dir, "hosts")
            os.makedirs(reports_dir, exist_ok=True)
            os.makedirs(data_dir, exist_ok=True)
            os.makedirs(hosts_dir, exist_ok=True)

            # 1. Un-obfuscated files (must be DENIED)
            with open(os.path.join(scan_dir, "00_fleet_summary.html"), "w", encoding="utf-8") as f:
                f.write("sensitive summary with 10.0.0.3")
            with open(os.path.join(scan_dir, "00_fleet_combined.html"), "w", encoding="utf-8") as f:
                f.write("sensitive combined with 10.0.0.3")
            with open(os.path.join(scan_dir, "vcf_readiness_2026.xlsx"), "w", encoding="utf-8") as f:
                f.write("sensitive excel")
            with open(os.path.join(scan_dir, "FAILURES.md"), "w", encoding="utf-8") as f:
                f.write("failed 10.0.0.99")
            with open(os.path.join(scan_dir, "digest.json"), "w", encoding="utf-8") as f:
                f.write('{"sensitive": true}')
            with open(os.path.join(hosts_dir, "host_10.0.0.3.json"), "w", encoding="utf-8") as f:
                f.write("sensitive host dump")
            with open(os.path.join(reports_dir, "vsphere_vsan_report_10.0.0.3.html"), "w", encoding="utf-8") as f:
                f.write("sensitive host report")
            with open(os.path.join(data_dir, "vcf_summary_10.0.0.3.json"), "w", encoding="utf-8") as f:
                f.write('{"target": "10.0.0.3"}')

            # 2. Obfuscated files (must be INCLUDED)
            with open(os.path.join(scan_dir, "00_OBFUSCATED_fleet_summary.html"), "w", encoding="utf-8") as f:
                f.write("sanitized summary")
            with open(os.path.join(scan_dir, "00_OBFUSCATED_fleet_combined.html"), "w", encoding="utf-8") as f:
                f.write("sanitized combined")
            with open(os.path.join(scan_dir, "00_OBFUSCATED_vcf_readiness_2026.xlsx"), "w", encoding="utf-8") as f:
                f.write("sanitized excel")
            with open(os.path.join(reports_dir, "OBFUSCATED_Host-1.html"), "w", encoding="utf-8") as f:
                f.write("sanitized host report")
            with open(os.path.join(data_dir, "OBFUSCATED_Host-1.json"), "w", encoding="utf-8") as f:
                json.dump({"target": "Host-1", "host": "Host-1", "obfuscated": True, "system": {"model": "R750"}}, f)

            zip_path = create_obfuscated_scan_zip_archive(scan_dir)
            self.assertTrue(os.path.isfile(zip_path))
            self.assertTrue(zip_path.endswith("_OBFUSCATED.zip"))

            with zipfile.ZipFile(zip_path, "r") as zf:
                self.assertIsNone(zf.testzip())
                names = zf.namelist()
                root = "run-test-scan_OBFUSCATED"

                # Check required sanitized artifacts
                self.assertIn(f"{root}/README.txt", names)
                self.assertIn(f"{root}/MANIFEST.json", names)
                self.assertIn(f"{root}/00_OBFUSCATED_fleet_summary.html", names)
                self.assertIn(f"{root}/00_OBFUSCATED_fleet_combined.html", names)
                self.assertIn(f"{root}/00_OBFUSCATED_vcf_readiness_2026.xlsx", names)
                self.assertIn(f"{root}/reports/OBFUSCATED_Host-1.html", names)
                self.assertIn(f"{root}/data/OBFUSCATED_Host-1.json", names)

                # Check that no sensitive un-obfuscated files entered the archive
                for n in names:
                    self.assertNotIn("10.0.0.3", n)
                    base_entry = os.path.basename(n)
                    self.assertNotEqual(base_entry, "00_fleet_summary.html")
                    self.assertNotEqual(base_entry, "00_fleet_combined.html")
                    self.assertNotEqual(base_entry, "vcf_readiness_2026.xlsx")
                    self.assertNotEqual(base_entry, "FAILURES.md")
                    self.assertNotEqual(base_entry, "digest.json")
                    self.assertNotIn("hosts/", n)
                    self.assertFalse(base_entry.startswith("vsphere_vsan_report_"))
                    self.assertFalse(base_entry.startswith("vcf_summary_"))

                # Check manifest has obfuscated: True
                manifest_content = json.loads(zf.read(f"{root}/MANIFEST.json").decode("utf-8"))
                self.assertTrue(manifest_content.get("obfuscated"))

                # Check README.txt content
                readme_text = zf.read(f"{root}/README.txt").decode("utf-8")
                self.assertIn("00_OBFUSCATED_fleet_combined.html", readme_text)
                self.assertIn("DATA PRIVACY & OBFUSCATION", readme_text.upper())



class TestCloudMetadataPin(unittest.TestCase):
    """Connect-time pin: the checked sockaddr is the one that is dialed."""

    def test_metadata_literal_is_blocked_without_dns(self):
        with mock.patch("vcf_hci.logging_utils.socket.getaddrinfo") as lookup:
            with self.assertRaises(CloudMetadataBlocked):
                resolve_pinned_addresses("169.254.169.254", 443)
            lookup.assert_not_called()
        self.assertTrue(is_cloud_metadata_target("metadata.google.internal"))
        self.assertTrue(is_cloud_metadata_target("::ffff:169.254.169.254"))
        with self.assertRaises(ValueError):
            parse_ip_targets("169.254.169.254")

    def test_metadata_lookup_does_not_open_a_socket(self):
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.11", port)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", port)),
            ]

        def fail_socket(*args, **kwargs):
            raise AssertionError("socket created for a metadata lookup")

        with mock.patch("vcf_hci.logging_utils.socket.getaddrinfo", fake_getaddrinfo), mock.patch(
            "vcf_hci.logging_utils.socket.socket", fail_socket
        ):
            with self.assertRaises(CloudMetadataBlocked):
                create_pinned_connection(("rebind.example", 80), timeout=1)

    def test_connection_dials_the_checked_literal_once(self):
        lookups = []
        dialed = []

        def fake_getaddrinfo(host, port, *args, **kwargs):
            lookups.append((host, port))
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.22", port)),
            ]

        class Sock:
            def __init__(self, family, socktype, proto):
                pass

            def settimeout(self, timeout):
                pass

            def connect(self, sockaddr):
                dialed.append(sockaddr)

            def close(self):
                pass

        with mock.patch("vcf_hci.logging_utils.socket.getaddrinfo", fake_getaddrinfo), mock.patch(
            "vcf_hci.logging_utils.socket.socket", Sock
        ):
            create_pinned_connection(("bmc.example", 443), timeout=1)
        self.assertEqual(lookups, [("bmc.example", 443)])
        self.assertEqual(dialed, [("192.0.2.22", 443)])

    def test_http_connection_uses_the_pin(self):
        from vcf_hci.tls_utils import MetadataPinnedHTTPConnection

        sentinel = mock.Mock()
        with mock.patch("vcf_hci.tls_utils.create_pinned_connection", return_value=sentinel) as pin:
            conn = MetadataPinnedHTTPConnection("bmc.example", port=80, timeout=2)
            conn.connect()
        pin.assert_called_once_with(("bmc.example", 80), 2, None)
        self.assertIs(conn.sock, sentinel)

    def test_jump_ssh_sets_hostname_to_the_literal(self):
        from vcf_hci.remote.executor import build_ssh_argv, probe_jump_host_key

        with mock.patch("vcf_hci.remote.executor.first_pinned_address", return_value="192.0.2.99"):
            argv = build_ssh_argv(
                {"host": "jump.example", "username": "root", "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey123"},
                control_path="",
                remote_command="true",
                known_hosts_file="/tmp/vcfr-known-hosts",
            )
        self.assertIn("HostName=192.0.2.99", argv)
        self.assertIn("root@jump.example", argv)

        seen = []

        def keyscan_run(cmd, timeout=0):
            seen.append(list(cmd))
            return (0, b"", b"")

        with mock.patch("vcf_hci.remote.executor.first_pinned_address", return_value="192.0.2.88"):
            probe_jump_host_key("jump.example", port=22, timeout=1, keyscan_run=keyscan_run)
        self.assertEqual(seen[0][-1], "192.0.2.88")
        self.assertNotIn("jump.example", seen[0])

        def must_not_scan(cmd, timeout=0):
            raise AssertionError("ssh-keyscan ran for a metadata target")

        with mock.patch(
            "vcf_hci.remote.executor.first_pinned_address",
            side_effect=CloudMetadataBlocked("blocked"),
        ):
            blocked = probe_jump_host_key("evil.example", keyscan_run=must_not_scan)
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked["category"], "security")


if __name__ == "__main__":
    unittest.main()
