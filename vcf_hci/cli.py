"""
VCF Readiness Tool — CLI entry point.

Provides the argparse-based command-line interface and the main scan loop
that drives UniversalRedfishCollector and WsManCollector instances.

Usage:
    python vcfr_collector.py [options]
    python -m vcf_hci [options]
    vcf-assess [options]                          # when installed via pip
    python redfish_collector.py [options]         # backward-compat shim
"""
import argparse
import getpass
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("vcf_assess")

from vcf_hci.constants import COMBINED_HTML_MAX_HOSTS, TOOL_VERSION
from vcf_hci.fleet_library import assemble_fleet, discover_scans, write_scan_manifest
from vcf_hci.hcl import (
    create_hcl_bundle,
    ensure_auto_hcl_bundle,
    import_hcl_bundle,
    load_optional_vsan_csv,
    load_vsan_hcl_json,
)
from vcf_hci.logging_utils import (
    normalize_output_dir,
    parse_ip_targets,
    sanitize_filename,
    update_latest_scan_aliases,
)
from vcf_hci.obfuscation import obfuscate_host_data
from vcf_hci.report import (
    _build_excel_sheets,
    _generate_combined_html,
    _write_xlsx,
    export_all_csvs,
    generate_host_html_report,
    generate_summary_html,
    write_scan_readme,
)
from vcf_hci.scan import scan_hosts
from vcf_hci.summary_io import load_summary, write_fleet_summary


def _open_cli_vault(args: argparse.Namespace, is_non_interactive: bool):
    """Open the optional encrypted credential vault for a CLI scan, or exit with a clear message.

    Only called when ``--vault`` was explicitly given.  Exit codes: 1 for vault
    errors (missing / wrong passphrase / corrupt), 2 for usage problems.
    """
    from vcf_hci.vault import (
        DEFAULT_VAULT_PATH,
        CredentialVault,
        VaultAuthError,
        VaultFormatError,
        VaultNotFoundError,
    )

    vault_path = DEFAULT_VAULT_PATH if args.vault == "__default__" else os.path.expanduser(args.vault)
    if args.vault_passphrase_env:
        passphrase = os.environ.get(args.vault_passphrase_env)
        if not passphrase:
            print(f"[✗] Vault passphrase environment variable {args.vault_passphrase_env} is not set.", file=sys.stderr)
            sys.exit(2)
    elif is_non_interactive:
        print("[✗] --vault requires --vault-passphrase-env <VAR> in non-interactive mode.", file=sys.stderr)
        sys.exit(2)
    else:
        passphrase = getpass.getpass(f"Vault passphrase ({vault_path}): ")
    try:
        return CredentialVault.open(vault_path, passphrase)
    except VaultNotFoundError:
        print(f"[✗] No credential vault at {vault_path}. Create one with: python -m vcf_hci.vault init", file=sys.stderr)
        sys.exit(1)
    except VaultAuthError:
        print("[✗] Vault passphrase incorrect (or vault file tampered with).", file=sys.stderr)
        sys.exit(1)
    except VaultFormatError as exc:
        print(f"[✗] Unreadable credential vault: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """Main CLI entry point for the VCF Readiness Assessment Tool."""
    # Windows consoles default to cp1252 which cannot encode the Unicode
    # arrows and checkmarks used in progress output. Reconfigure to UTF-8
    # with a replace fallback so the binary never crashes on a symbol.
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass
    parser = argparse.ArgumentParser(
        description=f"VCF / vSphere 9.1 Readiness Assessment Tool v{TOOL_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vcfr_collector.py --targets 192.0.2.10
  python vcfr_collector.py --targets "192.0.2.1-10"
  python vcfr_collector.py --targets "192.0.2.0/24" --threads 8
  python vcfr_collector.py --targets idrac-server01.rainpole.net
  python vcfr_collector.py --targets "idrac01.rainpole.net,idrac02.rainpole.net"
  python vcfr_collector.py --targets 192.0.2.10 --refresh-hcl --debug
        """,
    )
    parser.add_argument("--version", "-v", action="version", version=f"VCF HCI Readiness Tool v{TOOL_VERSION}")
    parser.add_argument("--targets", type=str, help="IP, hostname/FQDN, range (10.0.0.1-10), or CIDR (10.0.0.0/24); comma-separated list accepted")
    parser.add_argument("--username", "-u", type=str, default=None, help="BMC username")
    parser.add_argument("--password-env", type=str, default=None, help="Environment variable name containing the BMC password")
    parser.add_argument("--creds-stdin", action="store_true",
                        help="Read a JSON credential document from stdin. Passwords are not placed in argv.")
    parser.add_argument("--progress-ndjson", action="store_true",
                        help="Write scan progress as JSON lines on stdout (used by remote execution).")
    parser.add_argument("--no-input", action="store_true", help="Disable interactive prompts (non-interactive mode)")
    parser.add_argument("--vault", type=str, nargs="?", const="__default__", default=None, metavar="PATH",
                        help="OPT-IN: resolve per-host credentials from the encrypted local credential vault "
                             "(default path ~/.vcf-readiness/credentials.vault; manage with 'python -m vcf_hci.vault'). "
                             "Off unless specified.")
    parser.add_argument("--vault-passphrase-env", type=str, default=None, metavar="VAR",
                        help="Environment variable holding the vault passphrase (otherwise prompted)")
    parser.add_argument("--from-summary", type=str, default=None,
                        help="Path to saved host or fleet summary JSON file to render reports offline (skips live network scan)")
    parser.add_argument("--site", type=str, default=None,
                        help="Site name or identifier for the scan or fleet assembly (e.g. dc1, lab-east)")
    parser.add_argument("--assemble-only", action="store_true",
                        help="Assemble fleet reports from library or summary without generating individual host HTML reports")
    parser.add_argument("--csv", type=str, default=None, help="Path to offline Broadcom vSAN drive CSV")
    parser.add_argument("--refresh-hcl", action="store_true", help="Force refresh of live Broadcom HCL JSON")
    parser.add_argument("--bundle-hcl", nargs="?", const="DEFAULT", type=str, help="Package live Broadcom vSAN HCL dataset into a dark-site zip bundle (e.g. vcf_hcl_bundle_YYYYMMDD.zip)")
    parser.add_argument("--import-hcl", type=str, default=None, help="Path to offline air-gapped dark-site HCL zip bundle")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Enforce TLS certificate verification for BMC HTTPS connections (default: disabled / ignore self-signed)")
    parser.add_argument("--ca-bundle", type=str, default=None,
                        help="Path to custom enterprise CA certificate bundle (.pem/.crt) for BMC TLS verification")
    parser.add_argument("--legacy-tls", action="store_true",
                        help="Allow legacy TLS 1.0/1.1 protocols and older cipher suites for older BMC hardware (e.g. Dell 13G iDRAC 8, Supermicro X10)")
    parser.add_argument("--tls-min-version", type=str, default=None, choices=["1.0", "1.1", "1.2", "1.3"],
                        help="Minimum TLS protocol version required for BMC connections (default: runtime default, typically 1.2+)")
    parser.add_argument("--dns-lookup", action="store_true",
                        help="Perform Forward-Confirmed Reverse DNS (FCrDNS) lookups to resolve BMC hostnames and SANs")
    parser.add_argument("--enable-dash", action="store_true",
                        help="Enable probing for AMD DASH management interfaces on ports 624/623 (disabled by default)")
    parser.add_argument("--restrict-private-targets", action="store_true",
                        help="Restrict target range to RFC1918 private / local / loopback IP addresses only")
    parser.add_argument("--profile", type=str, choices=["readiness-full", "readiness-lean", "inventory-lite"], default="readiness-full",
                        help="Tiered scan depth profile: 'readiness-full' (exhaustive audit, default), 'readiness-lean' (high-speed VCF 9.1 / vSAN ESA audit), or 'inventory-lite' (rapid hardware inventory pre-screening)")
    parser.add_argument("--lean", action="store_true", help="Lean scan mode (alias for --profile readiness-lean)")
    parser.add_argument("--threads", type=int, default=8, help="Concurrent host scan threads (default: 8, max: 96)")
    parser.add_argument("--two-pass", action="store_true",
                        help="Enable Pass 1 fast pre-qualification probe & Longest-Job-First (LJF) priority scheduling")
    parser.add_argument("--discover-only", action="store_true",
                        help="Run Pass 1 fast discovery across --targets, output discovered responsive BMCs and write discovery cache, then exit (skips deep audit)")
    parser.add_argument("--discovery-cache", type=str, default=None,
                        help="Path to read or write discovery cache JSON (saves discovered active BMCs or loads prior active targets to skip subnet sweeping)")
    parser.add_argument("--prune-inactive", action="store_true",
                        help="Prune unresponsive/dark BMC IP addresses discovered during Pass 1 from the full assessment queue")
    parser.add_argument("--no-auto-throttle", action="store_true",
                        help="Disable dynamic CPU/RAM auto-stepdown concurrency throttling")
    parser.add_argument("--output-dir", type=str, default=None, help="Base directory for generated HTML reports (default: ~/Desktop/VCF-Scans)")
    parser.add_argument("--obfuscate", action="store_true",
                        help="Write obfuscated report copies alongside normal reports "
                             "(IPs→Host-N, MACs/S/Ns/WWNs→hash tokens) and automatically package a "
                             "sanitized <scan_name>_OBFUSCATED.zip containing all obfuscated deliverables, "
                             "sub-reports, Excel, CSVs, and customer-safe README.txt.")
    parser.add_argument("--save-json", action="store_true",
                        help="Save raw and structured host and fleet summary JSON files for offline import or analysis")
    parser.add_argument("--include-raw", action="store_true",
                        help="Include raw Redfish API payloads in output summary JSON files")
    parser.add_argument("--no-combined", action="store_true",
                        help="Skip generating combined tabbed HTML report")
    parser.add_argument("--excel", action="store_true", default=True,
                        help="Export assessment results to Excel workbook (.xlsx) (default: True)")
    parser.add_argument("--no-excel", action="store_false", dest="excel",
                        help="Skip exporting assessment results to Excel workbook (.xlsx)")
    parser.add_argument("--csv-export", action="store_true",
                        help="Export assessment results to standardized CSV files (fleet_summary.csv, etc.)")
    parser.add_argument("--host-timeout", type=int, default=300,
                        help="Maximum scan duration per host in seconds before skipping remaining collection (default: 300s / 5m; set to 0 to disable)")
    parser.add_argument("--allow-partial", action="store_true",
                        help="Allow generation of assessment reports even if non-critical Redfish sections time out or fail")
    parser.add_argument("--oem", action="store_true",
                        help="Enable OEM Import preset: deep Redfish crawling, raw API capture, summary JSON export, full readiness audit, and 15-minute host timeout")
    parser.add_argument("--crawl", "--crawl-endpoints", action="store_true", dest="crawl",
                        help="Deep Redfish crawl: discover and catalog all OEM and standard Redfish endpoints, generating endpoint manifests and offline mockup zip archives")
    parser.add_argument("--force", action="store_true", help="Bypass target expansion caps and allow large CIDR scans (/8, /16)")
    parser.add_argument("--force-threads", action="store_true", help="Bypass automatic VPN/high-latency concurrency throttling")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging to vcf_assess_debug.log & summary JSONs")
    args = parser.parse_args()
    args.threads = max(1, min(96, args.threads))

    if args.oem:
        args.crawl = True
        args.include_raw = True
        args.save_json = True
        args.allow_partial = True
        args.profile = "readiness-full"
        args.lean = False
        if args.host_timeout == 300:
            args.host_timeout = 900
        print("[🔬] OEM Import Mode active: deep Redfish crawling enabled, raw capture enabled, 15m timeout.")

    hcl_bundle_metadata = None
    if args.bundle_hcl:
        bundle_path = create_hcl_bundle(args.bundle_hcl)
        print(f"\n[✓] Air-Gapped Dark-Site HCL Bundle created: {bundle_path}")
        if not args.targets and not sys.stdin.isatty():
            print("Bundle creation complete. Use --import-hcl <file.zip> during offline scans.")
            sys.exit(0)
        args.import_hcl = bundle_path

    csv_db = {}
    json_hcl = {}
    hcl_bundle_metadata = None
    if args.import_hcl:
        json_hcl, csv_db, hcl_bundle_metadata = import_hcl_bundle(args.import_hcl)
        print(
            f"[🔒] Dark-Site HCL Bundle Active: {hcl_bundle_metadata.get('bundle_filename')} "
            f"(Age: {hcl_bundle_metadata.get('dataset_age_days')} days, "
            f"{hcl_bundle_metadata.get('json_models_count', 0) + hcl_bundle_metadata.get('csv_models_count', 0)} drive models indexed)\n"
        )
    else:
        auto_bundle_path = ensure_auto_hcl_bundle(max_age_days=30)
        if auto_bundle_path:
            json_hcl, csv_db, hcl_bundle_metadata = import_hcl_bundle(auto_bundle_path)
            if json_hcl or csv_db:
                print(
                    f"[🔒] Auto Dark-Site HCL Bundle Active: {hcl_bundle_metadata.get('bundle_filename')} "
                    f"(Age: {hcl_bundle_metadata.get('dataset_age_days')} days, "
                    f"{hcl_bundle_metadata.get('json_models_count', 0) + hcl_bundle_metadata.get('csv_models_count', 0)} drive models indexed)\n"
                )

        if not json_hcl:
            json_hcl = load_vsan_hcl_json(refresh_live=args.refresh_hcl, max_age_days=30)
            csv_db = load_optional_vsan_csv(args.csv)

    # ── Offline summary import mode ─────────────────────────────────────────
    if args.from_summary:
        if not os.path.exists(args.from_summary):
            print(f"[✗] Error: Summary JSON file not found: {args.from_summary}")
            sys.exit(1)

        is_library_parent = False
        discovered_scans = []
        if os.path.isdir(args.from_summary):
            discovered_scans = discover_scans(args.from_summary)
            if len(discovered_scans) > 1:
                is_library_parent = True
            elif len(discovered_scans) == 1:
                cand_path = os.path.abspath(discovered_scans[0]["path"])
                if cand_path != os.path.abspath(args.from_summary):
                    is_library_parent = True

        if is_library_parent:
            print(f"\n[📚] Fleet Library Mode — Discovered {len(discovered_scans)} scan(s) in {args.from_summary}...")
            policy = {"site": args.site} if args.site else None
            assemble_res = assemble_fleet(discovered_scans, policy=policy)
            results = assemble_res["results"]
            print(f"  [✓] Assembled {assemble_res['total_hosts_unique']} unique host(s) ({assemble_res['duplicates_count']} duplicate(s) deduplicated)")
        else:
            try:
                results = load_summary(args.from_summary)
                if args.site:
                    for h in results:
                        if isinstance(h, dict):
                            h["site"] = h.get("site") or args.site
            except Exception as exc:
                print(f"[✗] Error reading summary: {exc}")
                sys.exit(1)

        if not results:
            print("[✗] Error: No valid host scan data found in summary file.")
            sys.exit(1)

        base_outdir = normalize_output_dir(args.output_dir)
        if is_library_parent and not args.output_dir:
            outdir = os.path.join(base_outdir, f"assembled_{time.strftime('%Y%m%d_%H%M%S')}")
        else:
            outdir = base_outdir
        os.makedirs(outdir, exist_ok=True)

        if args.assemble_only:
            print(f"\n[📁] Assemble-Only Mode — Assembling fleet reports for {len(results)} host(s) (skipping individual host HTML)...")
        else:
            print(f"\n[📁] Offline Summary Mode — Rendering reports for {len(results)} host(s)...")

        _obf_salt = os.urandom(16).hex() if args.obfuscate else ""

        def _render_host(idx_host):
            idx, host_data = idx_host
            res_dict = {
                "idx": idx,
                "filepath": None,
                "obf_filepath": None,
                "logs": [],
            }
            try:
                sys_data = host_data.get("system") or {}
                ip_or_host = sys_data.get("bmc_ip") or sys_data.get("hostname") or host_data.get("host") or "host"
                filename = sanitize_filename(f"vcf_readiness_{ip_or_host}.html")
                filepath = os.path.join(outdir, filename)
                generate_host_html_report(
                    host_data,
                    filepath,
                    json_hcl=json_hcl,
                    hcl_bundle_metadata=hcl_bundle_metadata,
                )
                res_dict["filepath"] = filepath
                res_dict["logs"].append(f"  [✓] Generated: {filepath}")

                if args.obfuscate:
                    _alias = f"Host-{idx}"
                    _obf_filepath = os.path.join(outdir, f"OBFUSCATED_{_alias}.html")
                    _obf_data = obfuscate_host_data(host_data, _alias, _obf_salt)
                    generate_host_html_report(
                        _obf_data,
                        _obf_filepath,
                        json_hcl=json_hcl,
                        hcl_bundle_metadata=hcl_bundle_metadata,
                        obfuscated=True,
                    )
                    res_dict["obf_filepath"] = _obf_filepath
                    res_dict["logs"].append(f"  [🔒] Obfuscated: {_obf_filepath}")
            except Exception as exc:
                res_dict["logs"].append(f"  [✗] Failed to generate report for host {idx}: {exc}")
            return res_dict

        report_paths = []
        obf_report_paths = []

        if args.assemble_only:
            # Assemble-only mode: quickly reuse source reports if available without re-rendering
            import shutil
            reports_dir = os.path.join(outdir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            scans_meta = assemble_res.get("scans") or [] if is_library_parent else []
            scan_path_map = {sm.get("scan_id"): sm.get("path") for sm in scans_meta if sm.get("scan_id") and sm.get("path")}
            for idx, host in enumerate(results, 1):
                sys_info = host.get("system") or {}
                ip = str(sys_info.get("bmc_ip") or sys_info.get("ip") or host.get("host") or "").strip()
                src_path = scan_path_map.get(str(host.get("source_scan") or ""))
                dest_report = ""
                if ip and src_path:
                    cand_names = [
                        f"vcf_readiness_{sanitize_filename(ip)}.html",
                        f"vsphere_vsan_report_{sanitize_filename(ip)}.html",
                    ]
                    if os.path.isdir(src_path):
                        for cname in cand_names:
                            for sub in ("reports", ""):
                                cand_file = os.path.join(src_path, sub, cname) if sub else os.path.join(src_path, cname)
                                if os.path.isfile(cand_file):
                                    dest_report = os.path.join(reports_dir, f"vcf_readiness_{sanitize_filename(ip)}.html")
                                    try:
                                        if not os.path.exists(dest_report):
                                            shutil.copy2(cand_file, dest_report)
                                    except Exception:
                                        pass
                                    break
                            if dest_report:
                                break
                report_paths.append(dest_report)
        else:
            indexed_hosts = list(enumerate(results, 1))
            max_workers = min(32, max(4, (os.cpu_count() or 4) * 2))
            if len(indexed_hosts) <= 1:
                rendered = [_render_host(item) for item in indexed_hosts]
            else:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    rendered = list(executor.map(_render_host, indexed_hosts))

            for item in rendered:
                for log_line in item.get("logs", []):
                    print(log_line)
                if item.get("filepath"):
                    report_paths.append(item["filepath"])
                if item.get("obf_filepath"):
                    obf_report_paths.append(item["obf_filepath"])

        if len(results) > 1:
            try:
                summary_path = os.path.join(outdir, "00_fleet_summary.html")
                generate_summary_html(results, summary_path, hcl_bundle_metadata=hcl_bundle_metadata)
                print(f"  [✓] Fleet Summary Dashboard: {summary_path}")
            except Exception as exc:
                print(f"  [✗] Failed to generate fleet summary report: {exc}")

            if args.obfuscate:
                try:
                    obf_summary_path = os.path.join(outdir, "00_OBFUSCATED_fleet_summary.html")
                    obf_results = [obfuscate_host_data(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
                    generate_summary_html(obf_results, obf_summary_path, hcl_bundle_metadata=hcl_bundle_metadata, obfuscated=True)
                    print(f"  [🔒] Obfuscated Fleet Summary Dashboard: {obf_summary_path}")
                except Exception as exc:
                    print(f"  [✗] Failed to generate obfuscated fleet summary report: {exc}")

            if not args.no_combined and len(results) >= 1:
                if len(results) > COMBINED_HTML_MAX_HOSTS:
                    logger.info("Host count (%d) exceeds soft limit (%d) for combined report", len(results), COMBINED_HTML_MAX_HOSTS)
                try:
                    combined_path = _generate_combined_html(results, report_paths, outdir)
                    if combined_path:
                        print(f"  [✓] Fleet Combined Tabbed Report: {combined_path}")
                except Exception as exc:
                    print(f"  [✗] Failed to generate combined tabbed report: {exc}")

                if args.obfuscate:
                    try:
                        obf_results = [obfuscate_host_data(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
                        obf_combined_path = _generate_combined_html(obf_results, obf_report_paths, outdir, obfuscated=True)
                        if obf_combined_path:
                            print(f"  [🔒] Obfuscated Combined Tabbed Report: {obf_combined_path}")
                    except Exception as exc:
                        print(f"  [✗] Failed to generate obfuscated combined report: {exc}")

        if (args.excel or args.csv_export) and results:
            if args.excel:
                try:
                    sheets = _build_excel_sheets(results)
                    xlsx_bytes = _write_xlsx(sheets)
                    excel_fname = sanitize_filename(f"vcf_readiness_{time.strftime('%Y%m%d_%H%M%S')}.xlsx")
                    excel_path = os.path.join(outdir, excel_fname)
                    with open(excel_path, "wb") as f:
                        f.write(xlsx_bytes)
                    print(f"  [✓] Excel Report: {excel_path}")
                except Exception as exc:
                    print(f"  [✗] Failed to generate Excel report: {exc}")

            if args.csv_export:
                try:
                    export_all_csvs(results, outdir, obfuscated=False)
                    print(f"  [✓] CSV Summary: {os.path.join(outdir, '00_fleet_summary.csv')}")
                except Exception as exc:
                    print(f"  [✗] Failed to generate CSV exports: {exc}")

            if args.obfuscate:
                if args.excel:
                    try:
                        obf_results = [obfuscate_host_data(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
                        obf_sheets = _build_excel_sheets(obf_results)
                        obf_xlsx_bytes = _write_xlsx(obf_sheets)
                        obf_excel_fname = sanitize_filename(f"00_OBFUSCATED_vcf_readiness_{time.strftime('%Y%m%d_%H%M%S')}.xlsx")
                        obf_excel_path = os.path.join(outdir, obf_excel_fname)
                        with open(obf_excel_path, "wb") as f:
                            f.write(obf_xlsx_bytes)
                        print(f"  [🔒] Obfuscated Excel Report: {obf_excel_path}")
                    except Exception as exc:
                        print(f"  [✗] Failed to generate obfuscated Excel report: {exc}")

                if args.csv_export:
                    try:
                        obf_results = [obfuscate_host_data(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
                        export_all_csvs(obf_results, outdir, obfuscated=True)
                        print(f"  [🔒] Obfuscated CSV Summary: {os.path.join(outdir, '00_OBFUSCATED_fleet_summary.csv')}")
                    except Exception as exc:
                        print(f"  [✗] Failed to generate obfuscated CSV exports: {exc}")

        if args.save_json or is_library_parent or args.assemble_only:
            try:
                data_dir = os.path.join(outdir, "data")
                os.makedirs(data_dir, exist_ok=True)
                write_fleet_summary(results, data_dir, prefix="fleet_summary")
                write_scan_manifest(
                    outdir=outdir,
                    host_count=len(results),
                    site=args.site,
                    scan_profile="assembled",
                    obfuscated=args.obfuscate,
                )
                print(f"  [✓] Assembled Fleet Summary JSON: {os.path.join(data_dir, 'fleet_summary.json')}")
            except Exception as exc:
                print(f"  [✗] Failed to write assembled fleet summary: {exc}")

        try:
            write_scan_readme(
                outdir=outdir,
                host_count=len(results),
                site=args.site,
                scan_profile="assembled" if (is_library_parent or args.assemble_only) else "imported",
                obfuscated=args.obfuscate,
            )
            print(f"  [✓] Scan Index Guide: {os.path.join(outdir, 'Readme.txt')}")
        except Exception as exc:
            print(f"  [✗] Failed to write scan Readme.txt: {exc}")

        try:
            update_latest_scan_aliases(scan_dir=outdir)
        except Exception:
            pass

        if args.obfuscate:
            try:
                from vcf_hci.logging_utils import create_obfuscated_scan_zip_archive
                obf_zip = create_obfuscated_scan_zip_archive(outdir)
                print(f"  [📦] Obfuscated Archive: {obf_zip}")
            except Exception as exc:
                print(f"  [✗] Failed to create obfuscated archive: {exc}")

        print("\n[✔] Offline summary import complete. (0 network probes executed)\n")
        sys.exit(0)

    stdin_creds = None
    if getattr(args, "creds_stdin", False):
        if sys.stdin.isatty():
            print("[✗] --creds-stdin requires a piped JSON document, not a terminal.", file=sys.stderr)
            sys.exit(2)
        from vcf_hci.creds_stdin import load_creds_document
        try:
            _creds_doc = load_creds_document(sys.stdin.buffer)
        except ValueError as exc:
            print("[✗] %s" % exc, file=sys.stderr)
            sys.exit(2)
        stdin_creds = _creds_doc["creds"]
        if not args.targets:
            if not _creds_doc["targets"]:
                print("[✗] --creds-stdin document has no targets.", file=sys.stderr)
                sys.exit(2)
            args.targets = ",".join(_creds_doc["targets"])

    is_non_interactive = args.no_input or not sys.stdin.isatty() or stdin_creds is not None

    target_ips = []
    if args.discovery_cache and os.path.exists(args.discovery_cache) and not args.targets and not args.discover_only:
        from vcf_hci.fleet_discovery import load_discovery_cache
        try:
            target_ips, _, cache_meta = load_discovery_cache(args.discovery_cache, only_active=True)
            print(
                f"[⚡] Loaded {len(target_ips)} active target(s) from discovery cache: {args.discovery_cache} "
                f"(cached: {cache_meta.get('timestamp')})"
            )
        except Exception as _c_exc:
            print(f"  [✗] Failed loading discovery cache '{args.discovery_cache}': {_c_exc}", file=sys.stderr)
            sys.exit(1)

    if not target_ips:
        if args.targets:
            raw_input = args.targets
        elif is_non_interactive:
            raw_input = "10.0.0.1"
        else:
            raw_input = input("Enter Target IP/Hostname/Range/CIDR [10.0.0.1]: ").strip() or "10.0.0.1"

        try:
            target_ips = parse_ip_targets(
                raw_input,
                force=args.force,
                restrict_private=args.restrict_private_targets,
            )
        except ValueError as exc:
            print(f"  [✗] Target validation error: {exc}")
            sys.exit(1)

    # ── Optional encrypted credential vault (OFF unless --vault is given) ──
    vault = None
    vault_coverage: dict = {}
    if args.vault:
        vault = _open_cli_vault(args, is_non_interactive)
        vault_coverage = vault.coverage(target_ips)
        cipher_label = f" [{vault.cipher_display}]" if hasattr(vault, "cipher_display") else ""
        print(
            f"[🔐] Vault{cipher_label}: {vault_coverage['matched']}/{vault_coverage['total']} target(s) matched "
            f"(exact {vault_coverage['exact']}, cidr {vault_coverage['cidr']}, default {vault_coverage['default']})"
        )
        if vault_coverage["unmatched"]:
            sample = ", ".join(vault_coverage["unmatched"][:5])
            more = f" (+{len(vault_coverage['unmatched']) - 5} more)" if len(vault_coverage["unmatched"]) > 5 else ""
            print(f"  [!] {len(vault_coverage['unmatched'])} target(s) have no vault entry: {sample}{more}")

    if stdin_creds is not None:
        user = args.username or "root"
        passwd = ""
        scan_creds = stdin_creds
    else:
        # Username
        user = args.username or os.environ.get("REDFISH_USERNAME") or os.environ.get("BMC_USERNAME")
        if not user:
            if is_non_interactive or vault is not None:
                user = "root"
            else:
                user = input("Username [root]: ").strip() or "root"

        # Password
        if args.password_env:
            passwd = os.environ.get(args.password_env, "")
        else:
            env_pwd = os.environ.get("REDFISH_PASSWORD") or os.environ.get("BMC_PASSWORD")
            if env_pwd is not None:
                passwd = env_pwd
            elif is_non_interactive:
                passwd = ""
            elif vault is not None:
                # Vault mode: the global password is only an optional fallback for unmatched targets.
                if vault_coverage.get("unmatched"):
                    passwd = getpass.getpass(
                        f"Fallback password for {len(vault_coverage['unmatched'])} unmatched target(s) "
                        f"(user '{user}', blank to skip): "
                    )
                else:
                    passwd = ""
            else:
                passwd = getpass.getpass("Password: ")

        if vault is None and is_non_interactive and not passwd:
            print(
                "[✗] No BMC password provided in non-interactive mode. "
                "Set --password-env <VAR>, REDFISH_PASSWORD, BMC_PASSWORD, or use --vault.",
                file=sys.stderr,
            )
            sys.exit(2)

        if vault is None and not is_non_interactive and not passwd:
            print("  [!] WARNING: No BMC password was entered.")
            print("      Most BMCs require authentication. Queries will likely fail with 401 Unauthorized.")
            confirm_ans = input("Continue unauthenticated anyway? [y/N]: ").strip().lower()
            if confirm_ans not in ("y", "yes"):
                print("Aborted. Please re-run and enter a BMC password or configure --vault.")
                sys.exit(1)

        if vault is not None:
            scan_creds: object = vault.resolve_for_targets(target_ips)
            if passwd:
                scan_creds.setdefault("default", (user, passwd))  # type: ignore[union-attr]
            elif vault_coverage.get("unmatched") and not vault_coverage.get("has_default"):
                print("  [!] Unmatched targets will be skipped (no fallback password and no vault default entry).")
        else:
            scan_creds = (user, passwd)

    base_outdir = normalize_output_dir(args.output_dir)

    # Debug log checkbox — skip prompt when --debug set or non-interactive
    debug_mode = args.debug
    if not debug_mode and not is_non_interactive:
        _dbg_ans = input("Enable debug log? [y/N]: ").strip().lower()
        debug_mode = _dbg_ans in ("y", "yes")

    scan_profile = args.profile
    if args.lean:
        scan_profile = "readiness-lean"

    _ndjson_cb = {}
    if getattr(args, "progress_ndjson", False):
        from vcf_hci.remote.progress import ndjson_scan_callbacks
        _ndjson_cb = ndjson_scan_callbacks()

    scan_res = scan_hosts(
        target_ips=target_ips,
        creds=scan_creds,
        outdir=base_outdir,
        threads=args.threads,
        profile=scan_profile,
        lean=args.lean,
        obfuscate=args.obfuscate,
        debug=debug_mode,
        save_json=(args.save_json or args.include_raw),
        include_raw=args.include_raw,
        combined=not args.no_combined,
        csv_path=args.csv,
        excel=args.excel,
        export_sheets=(args.excel or args.csv_export),
        host_timeout=args.host_timeout,
        allow_partial=args.allow_partial,
        force_threads=args.force_threads,
        verify_ssl=args.verify_ssl,
        ca_bundle=args.ca_bundle,
        legacy_tls=args.legacy_tls,
        tls_min_version=args.tls_min_version,
        dns_lookup=args.dns_lookup,
        enable_dash=args.enable_dash,
        two_pass=(args.two_pass or args.discover_only or bool(args.discovery_cache)),
        auto_throttle=not args.no_auto_throttle,
        crawl_endpoints=bool(args.crawl or args.oem),
        discovery_cache=args.discovery_cache,
        discover_only=args.discover_only,
        prune_inactive=args.prune_inactive,
        site=args.site,
        **_ndjson_cb,
    )

    if vault is not None:
        vault.lock()
        scan_creds = None

    if scan_res.get("discover_only"):
        probe_res = scan_res.get("probe_results", {})
        active_targets = scan_res.get("active_targets", [])
        inactive_targets = scan_res.get("inactive_targets", [])
        cache_path = scan_res.get("discovery_cache_path", "")

        print("\n" + "=" * 80)
        print("                 DISCOVERED OUT-OF-BAND BMC TARGETS")
        print("=" * 80)
        print(f"{'Target IP':<18} {'Status':<10} {'Vendor':<14} {'Model':<22} {'Weight':<10} {'Est. Time':<10}")
        print("-" * 80)
        for ip in target_ips:
            info = probe_res.get(ip, {})
            is_active = info.get("reachable", False)
            status_str = "Active" if is_active else "Unreachable"
            vendor_str = str(info.get("vendor") or "-")[:13]
            model_str = str(info.get("model") or "-")[:21]
            weight_str = str(info.get("weight") or "-")
            dur_val = info.get("estimated_duration_sec")
            dur_str = f"{int(dur_val)}s" if (is_active and dur_val is not None) else "-"
            print(f"{ip:<18} {status_str:<10} {vendor_str:<14} {model_str:<22} {weight_str:<10} {dur_str:<10}")
        print("-" * 80)
        print(f"Summary: {len(active_targets)} Active / {len(inactive_targets)} Unreachable ({len(target_ips)} Total Targets)")
        if cache_path:
            print(f"Discovery Cache: {cache_path}")
            print("\nTo run the full assessment using this discovery cache:")
            print(f"  python vcfr_collector.py --discovery-cache {cache_path}")
        print("=" * 80 + "\n")
        sys.exit(0)

    results = scan_res.get("results", [])
    effective_outdir = scan_res.get("outdir", base_outdir)
    zip_path = scan_res.get("zip_path", "")

    if zip_path:
        print(f"  [📦] Zip Archive: {zip_path}")

    print(f"\n[✓] Assessment complete. {len(results)}/{len(target_ips)} hosts reported successfully.")


if __name__ == "__main__":
    main()
