"""
VCF Readiness Tool — Host scan completion handler.

Processes the result of an individual host scan, applies Dell warranty
lookups, generates per-host HTML reports (and obfuscated copies if enabled),
exports crawler manifests and DMTF mockups, and fires progress callbacks.
"""

import copy
import csv
import gc
import json
import logging
import os
import time
import zipfile
from typing import Any

logger = logging.getLogger("vcf_assess")

from vcf_hci.enrichment import enrich_host_result
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.obfuscation import obfuscate_host_data
from vcf_hci.report import generate_host_html_report

try:
    from vcf_hci.servicetag import summarise_warranty
except ImportError:
    summarise_warranty: Any = None  # type: ignore[assignment]


def _scan_log(ctx: Any, msg: str, event: str = "log") -> None:
    log_fn = getattr(ctx, "log", None)
    if callable(log_fn):
        try:
            log_fn(msg, event=event)
        except Exception:
            pass
    else:
        logger.info(msg)


def _handle_completed_host(future: Any, ip: str, ctx: Any) -> None:
    ctx.completed += 1
    debug = getattr(ctx, "debug", False)
    debug_log = getattr(ctx, "debug_log", None)
    _debug_hint = f" (see {debug_log})" if (debug and debug_log) else " (enable debug log for details)"

    try:
        res_tuple = future.result()
        fail_info = None
        if isinstance(res_tuple, tuple) and len(res_tuple) == 4:
            data, auth_failed, timed_out, fail_info = res_tuple
        elif isinstance(res_tuple, tuple) and len(res_tuple) == 3:
            data, auth_failed, timed_out = res_tuple
        elif isinstance(res_tuple, tuple) and len(res_tuple) == 2:
            data, auth_failed = res_tuple
            timed_out = False
        else:
            data, auth_failed, timed_out = None, False, False
    except Exception as e:
        logger.exception(f"Unexpected error in host scan thread for {ip}")
        _scan_log(ctx, f"  [✗] {ip}  — unexpected error: {e}{_debug_hint}")
        data, auth_failed, timed_out, fail_info = None, False, False, {"ip": ip, "error": str(e), "error_type": "exception"}

    if data:
        data_items = data if isinstance(data, list) else [data]
        for item_idx, raw_item in enumerate(data_items):
            if not isinstance(raw_item, dict):
                continue
            raw_item = copy.deepcopy(raw_item)
            raw_item["host"] = ip
            if isinstance(raw_item.get("system"), dict):
                raw_item["system"]["ip"] = ip
            enrich_fn = getattr(ctx, "enrich_host_result", enrich_host_result)
            if not raw_item.get("_enriched"):
                item = enrich_fn(raw_item, json_hcl=getattr(ctx, "json_hcl", None), csv_db=getattr(ctx, "csv_db", None))
            else:
                item = raw_item
            if not isinstance(item, dict):
                continue
            if timed_out:
                item["timed_out"] = True
            dell_client = getattr(ctx, "dell_client", None)
            warranty_cache = getattr(ctx, "warranty_cache", None)
            if dell_client is not None and summarise_warranty is not None and warranty_cache is not None:
                _vendor = str((item.get("system") or {}).get("vendor", "")).upper()
                _stag = str((item.get("system") or {}).get("serial_number", "")).strip().upper()
                if "DELL" in _vendor and _stag and len(_stag) >= 5:
                    if _stag not in warranty_cache:
                        try:
                            _w = dell_client.get_warranty([_stag])
                            if _w and isinstance(_w, list):
                                warranty_cache[_stag] = summarise_warranty(_w[0])
                            else:
                                warranty_cache[_stag] = None
                        except Exception:
                            warranty_cache[_stag] = None
                    if warranty_cache.get(_stag):
                        item["warranty"] = warranty_cache[_stag]

            ctx.results.append(item)
            dns_name = (item.get("system") or {}).get("dns_name")
            sled_id = str((item.get("system") or {}).get("serial_number") or (item.get("system") or {}).get("hostname") or "").strip()
            if len(data_items) > 1 and sled_id and sled_id != ip:
                host_label = f"{ip} [{sled_id}]"
                fname = f"vsphere_vsan_report_{sanitize_filename(ip)}_{sanitize_filename(sled_id)}.html"
            else:
                host_label = f"{ip}  ({dns_name})" if dns_name else ip
                fname = f"vsphere_vsan_report_{sanitize_filename(ip)}.html"
            reports_dir = getattr(ctx, "reports_dir", "")
            out_path = os.path.join(reports_dir, fname)

            generate_report_fn = getattr(ctx, "generate_host_html_report", generate_host_html_report)
            try:
                generate_report_fn(
                    item,
                    out_path,
                    json_hcl=getattr(ctx, "json_hcl", None),
                    csv_path=getattr(ctx, "csv_path", None),
                    quick_mode=getattr(ctx, "quick", False),
                    hcl_bundle_metadata=getattr(ctx, "hcl_bundle_metadata", None),
                )
                ctx.report_paths.append(out_path)
                rem = item.get("remediation") or {}
                rem_status = rem.get("status")
                if rem_status == "fully_remediated":
                    _res_sec = [s.replace('_', ' ').title() for s in (rem.get("resolved_sections") or [])]
                    _scan_log(ctx, f"  [🔄✓] {host_label} — FULLY REMEDIATED (recovered: {', '.join(_res_sec)})  →  reports/{fname}")
                elif rem_status == "partially_remediated":
                    _res_sec = [s.replace('_', ' ').title() for s in (rem.get("resolved_sections") or [])]
                    _rem_sec = [s.replace('_', ' ').title() for s in (rem.get("remaining_sections") or [])]
                    _scan_log(ctx, f"  [🔄⚠️] {host_label} — PARTIALLY REMEDIATED (recovered: {', '.join(_res_sec)}; missing: {', '.join(_rem_sec)})  →  reports/{fname}")
                elif item.get("partial_scan"):
                    _p_sec = [s.replace('_', ' ').title() for s in (item.get("partial_sections") or [])]
                    _p_str = f" (missing: {', '.join(_p_sec)})" if _p_sec else ""
                    _scan_log(ctx, f"  [⚠️] {host_label} (Partial Scan{_p_str})  →  reports/{fname}")
                else:
                    _scan_log(ctx, f"  [✓] {host_label}  →  reports/{fname}")
            except Exception as e:
                _scan_log(ctx, f"  [⚠] {host_label} — data collected but report failed: {e}{_debug_hint}")
                logger.exception(f"Report generation error for {ip}")

            obfuscate = getattr(ctx, "obfuscate", False)
            _obf_data = None
            if obfuscate:
                _alias = f"Host-{len(ctx.results)}"
                _obf_path = os.path.join(reports_dir, f"OBFUSCATED_{_alias}.html")
                try:
                    _obf_data = obfuscate_host_data(item, _alias, getattr(ctx, "obf_salt", ""))
                    generate_report_fn(
                        _obf_data,
                        _obf_path,
                        json_hcl=getattr(ctx, "json_hcl", None),
                        csv_path=getattr(ctx, "csv_path", None),
                        quick_mode=getattr(ctx, "quick", False),
                        hcl_bundle_metadata=getattr(ctx, "hcl_bundle_metadata", None),
                        obfuscated=True,
                    )
                    ctx.obf_report_paths.append(_obf_path)
                    _scan_log(ctx, f"  [🔒] Obfuscated  →  reports/OBFUSCATED_{_alias}.html")
                except Exception as e:
                    _scan_log(ctx, f"  [⚠] {host_label} — obfuscated report failed: {e}{_debug_hint}")
                    logger.exception(f"Obfuscation error for {ip}")

            include_raw = getattr(ctx, "include_raw", False)
            crawl_endpoints = getattr(ctx, "crawl_endpoints", False)
            if not (debug or include_raw or crawl_endpoints):
                item.pop("raw_redfish_capture", None)

            data_dir = getattr(ctx, "data_dir", "")
            # Export endpoint manifest and DMTF mockup archive when deep crawl is run
            manifest = item.get("endpoint_manifest")
            _suffix = f"_{sanitize_filename(sled_id)}" if (len(data_items) > 1 and sled_id and sled_id != ip) else ""
            if manifest:
                _mf_json_name = f"endpoints_manifest_{sanitize_filename(ip)}{_suffix}.json"
                _mf_json_path = os.path.join(data_dir, _mf_json_name)
                try:
                    with open(_mf_json_path, "w", encoding="utf-8", errors="replace") as _mf:
                        json.dump(manifest, _mf, indent=2)
                    _scan_log(ctx, f"  [🔬] Discovered {manifest.get('total_endpoints_discovered', 0)} endpoints ({manifest.get('coverage_percentage', 0)}% mapped)  →  data/{_mf_json_name}")
                except Exception as _exc:
                    _scan_log(ctx, f"  [!] Failed writing endpoint manifest JSON: {_exc}")

                _mf_csv_name = f"endpoints_manifest_{sanitize_filename(ip)}{_suffix}.csv"
                _mf_csv_path = os.path.join(data_dir, _mf_csv_name)
                try:
                    entries = manifest.get("endpoints", [])
                    fieldnames = ["uri", "category", "is_mapped", "status_code", "content_length", "odata_type"]
                    with open(_mf_csv_path, "w", newline="", encoding="utf-8", errors="replace") as _cf:
                        writer = csv.DictWriter(_cf, fieldnames=fieldnames)
                        writer.writeheader()
                        for row in entries:
                            writer.writerow({
                                "uri": row.get("uri", ""),
                                "category": row.get("category", "Other"),
                                "is_mapped": "Yes" if row.get("is_mapped") else "No",
                                "status_code": row.get("status_code", 0),
                                "content_length": row.get("content_length", 0),
                                "odata_type": row.get("odata_type", ""),
                            })
                    _scan_log(ctx, f"  [🔬] Endpoint manifest CSV  →  data/{_mf_csv_name}")
                except Exception as _exc:
                    _scan_log(ctx, f"  [!] Failed writing endpoint manifest CSV: {_exc}")

            actions_catalog = ((manifest or {}).get("actions") or (item.get("actions_manifest") or {}).get("actions") or [])
            if actions_catalog:
                _act_json_name = f"actions_manifest_{sanitize_filename(ip)}{_suffix}.json"
                _act_json_path = os.path.join(data_dir, _act_json_name)
                try:
                    actions_summary = (item.get("actions_manifest") or (manifest or {}).get("actions_summary") or {
                        "host": ip,
                        "total_actions": len(actions_catalog),
                        "actions": actions_catalog,
                    })
                    if "actions" not in actions_summary:
                        actions_summary["actions"] = actions_catalog
                    with open(_act_json_path, "w", encoding="utf-8", errors="replace") as _af:
                        json.dump(actions_summary, _af, indent=2)
                    _scan_log(ctx, f"  [🔬] Discovered {len(actions_catalog)} write actions (POST/PATCH)  →  data/{_act_json_name}")
                except Exception as _exc:
                    _scan_log(ctx, f"  [!] Failed writing actions manifest JSON: {_exc}")

                _act_csv_name = f"actions_manifest_{sanitize_filename(ip)}{_suffix}.csv"
                _act_csv_path = os.path.join(data_dir, _act_csv_name)
                try:
                    fieldnames = [
                        "action_name",
                        "category",
                        "http_method",
                        "operation_type",
                        "target_uri",
                        "parent_uri",
                        "is_oem",
                        "parameters",
                        "action_info",
                    ]
                    with open(_act_csv_path, "w", newline="", encoding="utf-8", errors="replace") as _acf:
                        writer = csv.DictWriter(_acf, fieldnames=fieldnames)
                        writer.writeheader()
                        for act in actions_catalog:
                            params_str = json.dumps(act.get("parameters", {}), separators=(",", ":"))
                            writer.writerow({
                                "action_name": act.get("action_name", ""),
                                "category": act.get("category", "GeneralAction"),
                                "http_method": act.get("http_method", "POST"),
                                "operation_type": act.get("operation_type", "Action"),
                                "target_uri": act.get("target_uri", ""),
                                "parent_uri": act.get("parent_uri", ""),
                                "is_oem": "Yes" if act.get("is_oem") else "No",
                                "parameters": params_str,
                                "action_info": act.get("action_info") or "",
                            })
                    _scan_log(ctx, f"  [🔬] Actions manifest CSV  →  data/{_act_csv_name}")
                except Exception as _exc:
                    _scan_log(ctx, f"  [!] Failed writing actions manifest CSV: {_exc}")

            raw_cap = item.get("raw_redfish_capture")
            if crawl_endpoints and raw_cap:
                _mk_zip_name = f"redfish_mockup_{sanitize_filename(ip)}{_suffix}.zip"
                _mk_zip_path = os.path.join(data_dir, _mk_zip_name)
                try:
                    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                    vendor_str = str((item.get("system") or {}).get("vendor", "")).strip()
                    model_str = str((item.get("system") or {}).get("model", "")).strip()
                    desc_text = f"Captured from {ip} ({vendor_str} {model_str}) by VCF Readiness Redfish Crawler"
                    readme_content = (
                        f"Redfish Mockup Archive\n"
                        f"======================\n"
                        f"Created:     {now_str}\n"
                        f"Host:        {ip}\n"
                        f"Endpoints:   {len(raw_cap)}\n"
                        f"Description: {desc_text}\n"
                        f"\n"
                        f"Structure conforms to standard DMTF Redfish Mockup folder specifications.\n"
                    )
                    with zipfile.ZipFile(_mk_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        zf.writestr("README", readme_content)
                        if manifest:
                            zf.writestr("endpoints_manifest.json", json.dumps(manifest, indent=2))
                        if actions_catalog:
                            act_summary_to_zip = (item.get("actions_manifest") or {
                                "host": ip,
                                "total_actions": len(actions_catalog),
                                "actions": actions_catalog,
                            })
                            zf.writestr("actions_manifest.json", json.dumps(act_summary_to_zip, indent=2))
                        for uri, payload in raw_cap.items():
                            clean_path = uri.lstrip("/")
                            archive_name = f"{clean_path}/index.json"
                            formatted_json = json.dumps(payload, indent=2, separators=(",", ": "))
                            zf.writestr(archive_name, formatted_json)
                    _scan_log(ctx, f"  [📦] DMTF Redfish Mockup Archive ({len(raw_cap)} endpoints)  →  data/{_mk_zip_name}")
                except Exception as _exc:
                    _scan_log(ctx, f"  [!] Failed writing redfish mockup archive: {_exc}")

            save_json = getattr(ctx, "save_json", False)
            if debug or save_json or crawl_endpoints:
                _suffix = f"_{sanitize_filename(sled_id)}" if (len(data_items) > 1 and sled_id and sled_id != ip) else ""
                _host_json_fname = f"vcf_summary_{sanitize_filename(ip)}{_suffix}.json"
                _host_json_path = os.path.join(data_dir, _host_json_fname)
                _indent = 2 if debug else None
                _separators = None if debug else (",", ":")
                try:
                    with open(_host_json_path, "w", encoding="utf-8", errors="replace") as _jf:
                        json.dump(item, _jf, indent=_indent, separators=_separators, default=str)
                    _scan_log(ctx, f"  [✓] Host summary JSON  →  data/{_host_json_fname}")
                except Exception as _exc:
                    _scan_log(ctx, f"  [!] Failed writing host summary JSON: {_exc}")

                if obfuscate:
                    if _obf_data is None:
                        _alias = f"Host-{len(ctx.results)}"
                        _obf_data = obfuscate_host_data(item, _alias, getattr(ctx, "obf_salt", ""))
                    else:
                        _alias = f"Host-{len(ctx.results)}"
                    _obf_json_fname = f"OBFUSCATED_vcf_summary_{_alias}.json"
                    _obf_json_path = os.path.join(data_dir, _obf_json_fname)
                    try:
                        with open(_obf_json_path, "w", encoding="utf-8", errors="replace") as _sjf:
                            json.dump(_obf_data, _sjf, indent=_indent, separators=_separators, default=str)
                    except Exception:
                        pass

            # Drop heavy raw crawler payloads from in-memory item now that all per-host
            # disk artifacts (vcf_summary JSON, mockup zip, manifests) have been committed.
            # This prevents multi-gigabyte memory bloat in fleet-wide results aggregation.
            item.pop("raw_redfish_capture", None)
            item.pop("endpoint_manifest", None)
            item.pop("actions_manifest", None)

            host_done_callback = getattr(ctx, "host_done_callback", None)
            if host_done_callback:
                try:
                    host_done_callback({
                        "ip": ip,
                        "report": fname,
                        "obf_report": f"OBFUSCATED_Host-{len(ctx.results)}.html" if obfuscate else "",
                        "hostname": (item.get("system") or {}).get("hostname") or (item.get("system") or {}).get("dns_name") or ip,
                        "vendor": (item.get("system") or {}).get("vendor", ""),
                        "model": (item.get("system") or {}).get("model", ""),
                        "verdict": ((item.get("system") or {}).get("cpu_summary") or {}).get("verdict", ""),
                        "msg": f"  [⚠️] {host_label} (Partial)" if item.get("partial_scan") else f"  [✓] {host_label}",
                        "timed_out": timed_out,
                        "partial_scan": bool(item.get("partial_scan")),
                        "partial_stage": item.get("partial_stage", ""),
                        "partial_reason": item.get("partial_reason", ""),
                        "remediation": item.get("remediation"),
                    })
                except Exception:
                    pass
    else:
        failed_hosts = getattr(ctx, "failed_hosts", None)
        failed_hosts_lock = getattr(ctx, "failed_hosts_lock", None)
        if fail_info and failed_hosts is not None and failed_hosts_lock is not None:
            with failed_hosts_lock:
                if not any(f.get("ip") == ip for f in failed_hosts):
                    failed_hosts.append(fail_info)
        if auth_failed:
            _scan_log(ctx, f"  [✗] {ip}  — bad credentials (HTTP 401/403)")
        elif timed_out:
            _scan_log(ctx, f"  [✗] {ip}  — timed out (unresponsive BMC / request timeout)")
        elif fail_info and fail_info.get("reason_code") == "no_credentials":
            pass
        else:
            _scan_log(ctx, f"  [✗] {ip}  — no data (check credentials / connectivity)")
        host_done_callback = getattr(ctx, "host_done_callback", None)
        if host_done_callback:
            try:
                cb_payload = {
                    "ip": ip,
                    "error": True,
                    "timed_out": timed_out,
                    "auth_failed": auth_failed,
                    "msg": f"  [✗] {ip} — {fail_info.get('reason_label') if fail_info else 'no data'}",
                }
                if fail_info:
                    cb_payload.update(fail_info)
                host_done_callback(cb_payload)
            except Exception:
                pass
    gc.collect()
    progress_callback = getattr(ctx, "progress_callback", None)
    if progress_callback:
        try:
            target_ips = getattr(ctx, "target_ips", [])
            total = len(target_ips)
            safe_completed = min(ctx.completed, total) if total > 0 else ctx.completed
            progress_callback(safe_completed, total)
        except Exception:
            pass
