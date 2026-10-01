"""
VCF Readiness Tool — Pure stdlib Redfish hypermedia crawler (crawler.py).

Discovers and catalogs all available Redfish endpoints on an enterprise BMC
using safe, read-only hypermedia traversal (@odata.id links) with cycle
detection, action target exclusion, collection member capping, and depth bounding.

Generates DMTF-compliant mockup zip archives and structured endpoint manifests
for offline testing and future feature development with zero external dependencies.
"""
import csv
import datetime
import json
import logging
import os
import time
import zipfile
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vcf_assess")

# ── Safe link filter patterns ────────────────────────────────────────────────
# Actions or state mutation endpoints must NEVER be queried with GET
_ACTION_PATTERNS = (
    "/actions/",
    "/action/",
)

# High-volume collection types or paths where pagination/member walking
# must be strictly capped to prevent hours-long crawls on 10,000+ log records.
_HIGH_VOLUME_KEYWORDS = (
    "logservice",
    "logservices",
    "logentries",
    "entries",
    "taskservice",
    "tasks",
    "jobservice",
    "jobs",
    "eventservice",
    "subscriptions",
    "auditlog",
    "eventlog",
)

# Endpoints that are already evaluated/mapped by the readiness assessment tool.
_MAPPED_PATH_FRAGMENTS = (
    "/redfish",
    "/redfish/v1",
    "/systems",
    "/processors",
    "/memory",
    "/bios",
    "/secureboot",
    "/storage",
    "/simplestorage",
    "/smartstorage",
    "/chassis",
    "/networkadapters",
    "/networkdevicefunctions",
    "/networkinterfaces",
    "/ports",
    "/ethernetinterfaces",
    "/power",
    "/thermal",
    "/powersubsystem",
    "/thermalsubsystem",
    "/managers",
    "/networkprotocol",
    "/logservices",
    "/pciedevices",
    "/pciefunctions",
    "/updateservice",
    "/firmwareinventory",
    "/licenseservice",
    "/telemetryservice",
    "/metricreports",
)


def normalize_redfish_uri(uri: str) -> Optional[str]:
    """Normalize a raw Redfish URI into a clean relative path (e.g. /redfish/v1/Systems/1).

    Strips scheme/host, query strings, fragments, and trailing slashes.
    Returns None if the URI is invalid, external, or not a Redfish path.
    """
    if not isinstance(uri, str):
        return None
    cleaned = uri.strip()
    if not cleaned:
        return None

    # Strip scheme and authority (e.g. https://10.0.0.1:443/redfish/v1/... -> /redfish/v1/...)
    if "://" in cleaned:
        parts = cleaned.split("://", 1)[-1].split("/", 1)
        if len(parts) > 1:
            cleaned = "/" + parts[1]
        else:
            return None

    # Strip query parameters (?...) and fragments (#...)
    cleaned = cleaned.split("?", 1)[0].split("#", 1)[0].strip()

    # Normalize slashes
    cleaned = "/" + cleaned.strip("/")

    # Must start with /redfish
    if not cleaned.startswith("/redfish"):
        return None

    # Ignore action targets or endpoints explicitly intended for actions
    cleaned_lower = cleaned.lower()
    for pat in _ACTION_PATTERNS:
        if pat in cleaned_lower:
            return None
    if cleaned_lower.endswith("/actions") or cleaned_lower.endswith("/action"):
        return None

    # Ignore session instance links to prevent invalidating active sessions
    if "/sessionservice/sessions/" in cleaned_lower:
        return None

    return cleaned


def is_endpoint_mapped(uri: str) -> bool:
    """Return True if the URI represents a resource category currently mapped by vcf_hci."""
    cleaned = normalize_redfish_uri(uri)
    if not cleaned:
        return False
    lower = cleaned.lower()

    # Explicit unmapped service roots
    for unmapped_prefix in (
        "/redfish/v1/accountservice",
        "/redfish/v1/certificateservice",
        "/redfish/v1/eventservice",
        "/redfish/v1/fabrics",
        "/redfish/v1/jobservice",
        "/redfish/v1/taskservice",
        "/redfish/v1/componentintegrity",
        "/redfish/v1/keyservice",
        "/redfish/v1/securityservice",
        "/redfish/v1/cables",
        "/redfish/v1/aggregationservice",
        "/redfish/v1/virtualmedia",
        "/redfish/v1/sensors",
    ):
        if lower.startswith(unmapped_prefix):
            return False

    # Check known mapped prefixes
    return any(frag in lower for frag in _MAPPED_PATH_FRAGMENTS)


def categorize_endpoint(uri: str) -> str:
    """Categorize a Redfish URI into a high-level subsystem domain."""
    cleaned = normalize_redfish_uri(uri)
    if not cleaned:
        return "Other"
    lower = cleaned.lower()

    if lower in ("/redfish", "/redfish/v1", "/redfish/v1/odata"):
        return "ServiceRoot"
    if "/accountservice" in lower or "/certificateservice" in lower or "/keyservice" in lower or "/securityservice" in lower or "/componentintegrity" in lower:
        return "Security"
    if "/storage" in lower or "/simplestorage" in lower or "/smartstorage" in lower or "/drives" in lower or "/volumes" in lower:
        return "Storage"
    if "/networkadapters" in lower or "/ethernetinterfaces" in lower or "/ports" in lower:
        return "Networking"
    if "/power" in lower or "/thermal" in lower or "/sensors" in lower:
        return "PowerThermal"
    if "/telemetryservice" in lower or "/metricreports" in lower:
        return "Telemetry"
    if "/updateservice" in lower or "/firmwareinventory" in lower:
        return "FirmwareUpdate"
    if "/logservices" in lower or "/eventservice" in lower:
        return "LogsEvents"
    if "/fabrics" in lower or "/cables" in lower:
        return "FabricsCables"
    if "/taskservice" in lower or "/jobservice" in lower:
        return "TasksJobs"
    if "/licenseservice" in lower:
        return "License"
    if "/oem" in lower:
        return "OEM"
    if "/systems" in lower:
        return "Systems"
    if "/chassis" in lower:
        return "Chassis"
    if "/managers" in lower:
        return "Managers"
    return "Other"


def categorize_action(action_name: str, target_uri: str, is_oem: bool = False) -> str:
    """Categorize a Redfish Action into a functional domain."""
    name_lower = action_name.lower()
    target_lower = target_uri.lower()

    if any(k in name_lower or k in target_lower for k in ("reset", "power", "reboot", "nmi", "chassis.reset", "system.reset")):
        return "SystemPower"
    if any(k in name_lower or k in target_lower for k in ("bios", "secureboot", "bootorder")):
        return "BIOSConfig"
    if any(k in name_lower or k in target_lower for k in ("storage", "drive", "volume", "raid", "controller", "array")):
        return "StorageConfig"
    if any(k in name_lower or k in target_lower for k in ("firmware", "update", "simpleupdate", "install", "swinventory")):
        return "FirmwareUpdate"
    if any(k in name_lower or k in target_lower for k in ("log", "clearlog", "sel", "eventlog", "dumplog")):
        return "LogManagement"
    if any(k in name_lower or k in target_lower for k in ("export", "import", "backup", "restore", "scp", "systemconfiguration")):
        return "ConfigurationImportExport"
    if any(k in name_lower or k in target_lower for k in ("diag", "diagnostic", "collect", "support", "tsr", "supportassist")):
        return "Diagnostics"
    if any(k in name_lower or k in target_lower for k in ("account", "user", "cert", "certificate", "key", "security", "factoryreset", "clearcmos")):
        return "SecurityAndAccounts"
    if any(k in name_lower or k in target_lower for k in ("virtualmedia", "insertmedia", "ejectmedia")):
        return "VirtualMedia"
    if any(k in name_lower or k in target_lower for k in ("telemetry", "metric", "report")):
        return "Telemetry"
    if is_oem or "/oem/" in target_lower or "oem" in name_lower:
        return "OEM"
    return "GeneralAction"


def extract_resource_actions(resource_uri: str, data: Any) -> List[Dict[str, Any]]:
    """Extract all available non-GET (write / action) operations defined on a Redfish resource.

    Identifies HTTP POST action targets, allowable parameter values, and staged
    configuration settings endpoints (@Redfish.Settings). Strictly catalogs without calling.
    """
    if not isinstance(data, dict):
        return []

    actions: List[Dict[str, Any]] = []

    def _clean_action_name(raw_k: str) -> str:
        s = raw_k.strip()
        if "#" in s:
            s = s.split("#")[-1]
        return s.lstrip("#")

    def _parse_action_dict(raw_key: str, act_dict: dict, is_oem_context: bool):
        target = act_dict.get("target")
        if not target or not isinstance(target, str):
            return

        clean_name = _clean_action_name(raw_key)
        target_clean = target.strip()
        if "://" in target_clean:
            parts = target_clean.split("://", 1)[-1].split("/", 1)
            target_clean = "/" + parts[1] if len(parts) > 1 else target_clean

        is_oem = is_oem_context or "/oem/" in target_clean.lower() or "oem" in raw_key.lower()
        category = categorize_action(clean_name, target_clean, is_oem=is_oem)

        action_info = act_dict.get("@Redfish.ActionInfo")
        if action_info and isinstance(action_info, str):
            if "://" in action_info:
                parts = action_info.split("://", 1)[-1].split("/", 1)
                action_info = "/" + parts[1] if len(parts) > 1 else action_info

        parameters: Dict[str, Any] = {}
        for pk, pv in act_dict.items():
            if pk in ("target", "@Redfish.ActionInfo") or pk.startswith("@odata."):
                continue
            if "@Redfish.AllowableValues" in pk:
                param_name = pk.split("@", 1)[0]
                parameters[param_name] = {"allowable_values": pv}
            else:
                parameters[pk] = pv

        actions.append({
            "action_name": clean_name,
            "raw_key": raw_key,
            "target_uri": target_clean,
            "http_method": "POST",
            "parent_uri": resource_uri,
            "category": category,
            "is_oem": is_oem,
            "parameters": parameters,
            "action_info": action_info if isinstance(action_info, str) else None,
            "operation_type": "Action",
        })

    def _walk_actions_dict(d: dict, is_oem_ctx: bool = False):
        for k, v in d.items():
            k_lower = str(k).lower()
            if isinstance(v, dict):
                if "target" in v:
                    _parse_action_dict(k, v, is_oem_ctx or "oem" in k_lower)
                else:
                    _walk_actions_dict(v, is_oem_ctx=is_oem_ctx or "oem" in k_lower)

    # 1. Standard Actions container
    actions_obj = data.get("Actions")
    if isinstance(actions_obj, dict):
        _walk_actions_dict(actions_obj, is_oem_ctx=False)

    # 2. Top-level action definitions (e.g. #ComputerSystem.Reset at top-level)
    for k, v in data.items():
        if k == "Actions":
            continue
        if (str(k).startswith("#") or "action" in str(k).lower()) and isinstance(v, dict) and "target" in v:
            _parse_action_dict(k, v, "oem" in str(k).lower())

    # 3. Check for @Redfish.Settings (staged configuration writes via PATCH/PUT)
    settings_dict = data.get("@Redfish.Settings")
    if isinstance(settings_dict, dict):
        settings_obj = settings_dict.get("SettingsObject") or {}
        target_id = settings_obj.get("@odata.id") if isinstance(settings_obj, dict) else None
        if target_id and isinstance(target_id, str):
            clean_target = target_id.strip()
            if "://" in clean_target:
                parts = clean_target.split("://", 1)[-1].split("/", 1)
                clean_target = "/" + parts[1] if len(parts) > 1 else clean_target

            apply_times = settings_dict.get("SupportedApplyTimes") or []
            actions.append({
                "action_name": "Settings.ModifyPending",
                "raw_key": "@Redfish.Settings",
                "target_uri": clean_target,
                "http_method": "PATCH",
                "parent_uri": resource_uri,
                "category": "PendingSettings",
                "is_oem": False,
                "parameters": {
                    "SupportedApplyTimes": apply_times,
                },
                "action_info": None,
                "operation_type": "Settings",
            })

    return actions


def extract_hypermedia_links(data: Any, parent_key: str = "", max_members: int = 50) -> List[str]:
    """Recursively extract candidate @odata.id links from a parsed Redfish JSON object.

    Safely skips Action targets, state mutation keys, and truncates large collections.
    """
    links: List[str] = []

    if isinstance(data, dict):
        for k, v in data.items():
            k_lower = str(k).lower()

            # Skip Action definitions and POST targets
            if k_lower == "actions" or "action" in k_lower or k_lower == "target":
                continue
            if k_lower.startswith("#") and "action" in k_lower:
                continue

            if (k == "@odata.id" and isinstance(v, str)) or (k in ("@odata.nextLink", "Members@odata.nextLink") and isinstance(v, str)):
                normalized = normalize_redfish_uri(v)
                if normalized:
                    links.append(normalized)

            elif k == "Members" and isinstance(v, list):
                # Apply member capping on collections
                capped_list = v[:max_members]
                for member in capped_list:
                    links.extend(extract_hypermedia_links(member, parent_key="Members", max_members=max_members))

            elif isinstance(v, (dict, list)):
                links.extend(extract_hypermedia_links(v, parent_key=k, max_members=max_members))

    elif isinstance(data, list):
        capped_items = data[:max_members]
        for item in capped_items:
            links.extend(extract_hypermedia_links(item, parent_key=parent_key, max_members=max_members))

    return links


class RedfishCrawler:
    """Safe, read-only Redfish hypermedia crawler and mockup exporter.

    Walks a Redfish service tree using GET operations only, collects all valid
    JSON endpoints, builds a coverage manifest, and can bundle the results into a
    DMTF-compliant offline mockup directory or zip archive.
    """

    def __init__(
        self,
        get_fn: Callable[[str], Optional[dict]],
        host_label: str = "host",
        max_depth: int = 8,
        max_requests: int = 2500,
        max_log_members: int = 20,
        max_general_members: int = 100,
        is_cancelled_fn: Optional[Callable[[], bool]] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ):
        """Initialize crawler.

        Args:
            get_fn: Callable taking a relative or absolute URI and returning parsed JSON dict (or None).
            host_label: Friendly host IP or name for logging and metadata.
            max_depth: Maximum recursion depth from service root.
            max_requests: Maximum total HTTP GET requests to prevent runaway runs.
            max_log_members: Maximum members to walk in high-volume log/task collections.
            max_general_members: Maximum members to walk in hardware collections (DIMMs, drives).
            is_cancelled_fn: Optional callback returning True if scan was aborted/cancelled.
            progress_callback: Optional callback(stage_message, visited_count, queued_count).
        """
        self.get_fn = get_fn
        self.host_label = host_label
        self.max_depth = max_depth
        self.max_requests = max_requests
        self.max_log_members = max_log_members
        self.max_general_members = max_general_members
        self.is_cancelled_fn = is_cancelled_fn
        self.progress_callback = progress_callback

        self.visited_uris: Set[str] = set()
        self.crawl_results: Dict[str, dict] = {}
        self.manifest_entries: List[dict] = []
        self.actions_catalog: List[dict] = []
        self._seen_action_keys: Set[Tuple[str, str]] = set()
        self._request_count = 0

    def _is_cancelled(self) -> bool:
        return bool(self.is_cancelled_fn and self.is_cancelled_fn())

    def _record_actions(self, resource_uri: str, data: Any) -> None:
        """Extract and record non-GET write/action commands from a resource payload."""
        if not isinstance(data, dict):
            return
        extracted = extract_resource_actions(resource_uri, data)
        for act in extracted:
            key = (str(act.get("target_uri", "")), str(act.get("action_name", "")))
            if key not in self._seen_action_keys:
                self._seen_action_keys.add(key)
                self.actions_catalog.append(act)

    def preseed_cache(self, cached_items: Dict[str, dict]) -> None:
        """Preseed crawler with already-fetched endpoints from earlier scan phases.

        This avoids re-requesting endpoints that the main collector already retrieved.
        """
        for raw_uri, payload in cached_items.items():
            if not isinstance(payload, dict):
                continue
            normalized = normalize_redfish_uri(raw_uri)
            if not normalized or normalized in self.visited_uris:
                continue

            self.visited_uris.add(normalized)
            self.crawl_results[normalized] = payload
            self._record_actions(normalized, payload)

            # Add to manifest
            odata_type = str(payload.get("@odata.type") or "")
            body_bytes = len(json.dumps(payload, separators=(",", ":")))
            self.manifest_entries.append({
                "uri": normalized,
                "odata_type": odata_type,
                "status_code": 200,
                "content_length": body_bytes,
                "is_mapped": is_endpoint_mapped(normalized),
                "category": categorize_endpoint(normalized),
            })

    def crawl(
        self,
        entry_points: Optional[List[str]] = None,
    ) -> Dict[str, dict]:
        """Perform a breadth-first search of all discovered hypermedia links.

        Returns:
            Dict mapping normalized URI -> parsed JSON payload.
        """
        if entry_points is None:
            entry_points = ["/redfish", "/redfish/v1"]

        # Queue items: (normalized_uri, current_depth)
        queue: List[Tuple[str, int]] = []
        enqueued: Set[str] = set(self.visited_uris)

        # 1. Enqueue seed entry points
        for ep in entry_points:
            norm = normalize_redfish_uri(ep)
            if norm and norm not in enqueued:
                queue.append((norm, 0))
                enqueued.add(norm)

        # 2. Extract links from preseeded items so we can follow them into unvisited trees
        for visited_uri, payload in list(self.crawl_results.items()):
            is_log_col = any(kw in visited_uri.lower() for kw in _HIGH_VOLUME_KEYWORDS)
            max_m = self.max_log_members if is_log_col else self.max_general_members
            child_links = extract_hypermedia_links(payload, max_members=max_m)
            for cl in child_links:
                if cl not in enqueued:
                    queue.append((cl, 1))
                    enqueued.add(cl)

        logger.info(
            "[%s] RedfishCrawler starting: %d preseeded endpoints, %d initial targets in queue",
            self.host_label, len(self.visited_uris), len(queue)
        )

        last_progress_time = time.time()

        while queue:
            if self._is_cancelled():
                logger.info("[%s] RedfishCrawler stopped early: cancellation requested", self.host_label)
                break

            if self._request_count >= self.max_requests:
                logger.warning(
                    "[%s] RedfishCrawler reached request limit (%d requests). Stopping.",
                    self.host_label, self.max_requests
                )
                break

            current_uri, depth = queue.pop(0)

            # If already visited via preseed or earlier step, skip GET
            if current_uri in self.visited_uris:
                continue

            self.visited_uris.add(current_uri)
            self._request_count += 1

            if time.time() - last_progress_time > 5.0:
                last_progress_time = time.time()
                if self.progress_callback:
                    msg = f"Crawling endpoints ({len(self.visited_uris)} visited, {len(queue)} queued)"
                    self.progress_callback(msg, len(self.visited_uris), len(queue))
                logger.debug(
                    "[%s] Crawl progress: %d visited, %d queued, current depth %d",
                    self.host_label, len(self.visited_uris), len(queue), depth
                )

            # Perform read-only HTTP GET
            data = None
            status_code = 0
            try:
                data = self.get_fn(current_uri)
                status_code = 200 if (data is not None) else 404
            except Exception as exc:
                logger.debug("[%s] GET %s error: %s", self.host_label, current_uri, exc)
                status_code = 500

            if not isinstance(data, dict):
                # Record manifest entry for failed / non-JSON responses
                self.manifest_entries.append({
                    "uri": current_uri,
                    "odata_type": "",
                    "status_code": status_code,
                    "content_length": 0,
                    "is_mapped": is_endpoint_mapped(current_uri),
                    "category": categorize_endpoint(current_uri),
                })
                continue

            # Valid response
            self.crawl_results[current_uri] = data
            self._record_actions(current_uri, data)
            odata_type = str(data.get("@odata.type") or "")
            body_bytes = len(json.dumps(data, separators=(",", ":")))

            self.manifest_entries.append({
                "uri": current_uri,
                "odata_type": odata_type,
                "status_code": 200,
                "content_length": body_bytes,
                "is_mapped": is_endpoint_mapped(current_uri),
                "category": categorize_endpoint(current_uri),
            })

            # Follow child links if within depth limit
            if depth < self.max_depth:
                is_log_col = any(kw in current_uri.lower() for kw in _HIGH_VOLUME_KEYWORDS)
                max_m = self.max_log_members if is_log_col else self.max_general_members
                children = extract_hypermedia_links(data, max_members=max_m)
                for child_uri in children:
                    if child_uri not in enqueued:
                        enqueued.add(child_uri)
                        queue.append((child_uri, depth + 1))

        logger.info(
            "[%s] RedfishCrawler completed: %d total endpoints discovered (%d requests made)",
            self.host_label, len(self.crawl_results), self._request_count
        )
        return self.crawl_results

    def generate_actions_summary(self) -> dict:
        """Return structured summary statistics of discovered write actions and commands."""
        total = len(self.actions_catalog)
        oem_count = sum(1 for a in self.actions_catalog if a.get("is_oem"))
        standard_count = total - oem_count
        by_category: Dict[str, int] = {}
        by_method: Dict[str, int] = {}
        for a in self.actions_catalog:
            cat = a.get("category", "GeneralAction")
            by_category[cat] = by_category.get(cat, 0) + 1
            meth = a.get("http_method", "POST")
            by_method[meth] = by_method.get(meth, 0) + 1

        return {
            "host": self.host_label,
            "total_actions": total,
            "standard_actions": standard_count,
            "oem_actions": oem_count,
            "by_category": by_category,
            "by_method": by_method,
            "actions": sorted(self.actions_catalog, key=lambda x: (x.get("category", ""), x.get("action_name", ""))),
        }

    def generate_manifest_summary(self) -> dict:
        """Return structured summary statistics of the endpoint manifest."""
        total = len(self.manifest_entries)
        mapped = sum(1 for e in self.manifest_entries if e.get("is_mapped"))
        unmapped = total - mapped
        cov_pct = round((mapped / total * 100.0), 1) if total > 0 else 0.0

        categories: Dict[str, int] = {}
        for e in self.manifest_entries:
            cat = e.get("category", "Other")
            categories[cat] = categories.get(cat, 0) + 1

        actions_sum = self.generate_actions_summary()

        return {
            "host": self.host_label,
            "crawl_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_endpoints_discovered": total,
            "mapped_endpoints_count": mapped,
            "unmapped_endpoints_count": unmapped,
            "coverage_percentage": cov_pct,
            "categories": categories,
            "actions_summary": {
                "total_actions": actions_sum["total_actions"],
                "standard_actions": actions_sum["standard_actions"],
                "oem_actions": actions_sum["oem_actions"],
                "by_category": actions_sum["by_category"],
                "by_method": actions_sum["by_method"],
            },
            "actions": actions_sum["actions"],
            "endpoints": sorted(self.manifest_entries, key=lambda x: x.get("uri", "")),
        }

    def export_actions_json(self, file_path: str) -> None:
        """Export the write actions catalog to a JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        summary = self.generate_actions_summary()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
            f.write("\n")

    def export_actions_csv(self, file_path: str) -> None:
        """Export the write actions catalog to a CSV file."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        entries = sorted(self.actions_catalog, key=lambda x: (x.get("category", ""), x.get("action_name", "")))
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
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in entries:
                params_str = json.dumps(row.get("parameters", {}), separators=(",", ":"))
                writer.writerow({
                    "action_name": row.get("action_name", ""),
                    "category": row.get("category", "GeneralAction"),
                    "http_method": row.get("http_method", "POST"),
                    "operation_type": row.get("operation_type", "Action"),
                    "target_uri": row.get("target_uri", ""),
                    "parent_uri": row.get("parent_uri", ""),
                    "is_oem": "Yes" if row.get("is_oem") else "No",
                    "parameters": params_str,
                    "action_info": row.get("action_info") or "",
                })

    def export_manifest_json(self, file_path: str) -> None:
        """Export the endpoint discovery manifest to a JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        summary = self.generate_manifest_summary()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
            f.write("\n")

    def export_manifest_csv(self, file_path: str) -> None:
        """Export the endpoint discovery manifest to a CSV file."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        entries = sorted(self.manifest_entries, key=lambda x: x.get("uri", ""))
        fieldnames = ["uri", "category", "is_mapped", "status_code", "content_length", "odata_type"]
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
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

    def export_mockup_zip(self, zip_path: str, description: Optional[str] = None) -> None:
        """Package all crawled JSON payloads into a DMTF-compliant mockup zip archive.

        Inside the archive, each endpoint /redfish/v1/Systems/1 is stored as
        redfish/v1/Systems/1/index.json, with a top-level README descriptor.
        """
        os.makedirs(os.path.dirname(os.path.abspath(zip_path)), exist_ok=True)
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        desc_text = description or f"Captured from {self.host_label} by VCF Readiness Redfish Crawler"

        readme_content = (
            f"Redfish Mockup Archive\n"
            f"======================\n"
            f"Created:     {now_str}\n"
            f"Host:        {self.host_label}\n"
            f"Endpoints:   {len(self.crawl_results)}\n"
            f"Actions:     {len(self.actions_catalog)}\n"
            f"Description: {desc_text}\n"
            f"\n"
            f"Structure conforms to standard DMTF Redfish Mockup folder specifications.\n"
        )

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README", readme_content)
            zf.writestr("endpoints_manifest.json", json.dumps(self.generate_manifest_summary(), indent=2))
            zf.writestr("actions_manifest.json", json.dumps(self.generate_actions_summary(), indent=2))

            for uri, payload in self.crawl_results.items():
                clean_path = uri.lstrip("/")
                # Standard DMTF structure: /redfish/v1/Systems -> redfish/v1/Systems/index.json
                archive_name = f"{clean_path}/index.json"
                formatted_json = json.dumps(payload, indent=2, separators=(",", ": "))
                zf.writestr(archive_name, formatted_json)
