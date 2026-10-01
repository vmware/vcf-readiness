"""
VCF Readiness Tool — system event log (SEL) collection mixin.
"""
import logging
import re
from typing import TYPE_CHECKING, Any, Optional, Tuple

if TYPE_CHECKING:
    class _CollectorBase:
        sys_uri: Optional[str]
        chassis_uri: Optional[str]
        mgr_uri: Optional[str]
        sys_sku: str
        host: str
        port: int
        username: str
        password: str
        session_token: Optional[str]
        verify_ssl: bool
        ca_bundle: Optional[str]
        timeout: float
        host_timeout: float
        scan_start_time: Optional[float]
        cancel_event: Any
        skip_host_set: Any
        skipped: bool
        timed_out: bool
        auth_failed: bool
        chassis_management_info: dict
        stage_callback: Any
        _PCIE_SWITCH_NAMES: tuple
        def _get(self, endpoint: str, _retry: bool = True, timeout: int = 15, critical: bool = True) -> Optional[dict]: ...
        def _get_members(self, endpoint_or_data: Any, limit: int = 0, max_pages: int = 100) -> list: ...
        def _get_oem_raw(self, uri: str, timeout: Optional[float] = None) -> Optional[dict]: ...
        def _is_cancelled_or_skipped(self) -> bool: ...
        @staticmethod
        def _is_license_blocked(data: Optional[dict]) -> Optional[str]: ...
        def _resolve_product_name(self, raw_obj: dict, pcie_cache: Optional[list] = None) -> str: ...
        def oem_bios_date(self, sys_data: dict) -> str: ...
        def oem_sku(self, sys_data: dict) -> str: ...
        def oem_storage_endpoints(self) -> list: ...
        def oem_drive_endurance(self, drive_json: dict) -> Optional[float]: ...
        def oem_drive_metrics(self, drive_json: dict) -> dict: ...
        def oem_nic_firmware(self, adapter_json: dict) -> str: ...
        def oem_cpu_cache(self, proc_json: dict) -> list: ...
        def oem_memory_usage(self, sys_data: dict) -> dict: ...
        def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict: ...
        def oem_handle_retry(self, data: dict, endpoint: str) -> bool: ...
        def oem_manager_paths(self) -> list: ...
        def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]: ...
else:
    _CollectorBase = object

logger = logging.getLogger("vcf_assess")



class _LogsMixin(_CollectorBase):
    """Collection methods: System Event Log (SEL / IML / ActiveLog / FaultList)."""

    def collect_system_event_log(self, max_entries: int = 10) -> list:
        """Fetch last N unique warning/critical active faults or SEL/IML events.

        Checks active fault list services (FaultList, ActiveLog) first so active
        hardware issues take priority over cleared historical log entries.
        Cisco IMC places the SEL under /Chassis/1/LogServices/SEL, not /Systems.
        We check both System and Manager log services, plus Chassis as a fallback.
        """
        base_eps = []
        if self.sys_uri:
            base_eps.append(f"{self.sys_uri}/LogServices")
        if self.mgr_uri:
            base_eps.append(f"{self.mgr_uri}/LogServices")
        # Cisco IMC / some Intel BMCs place SEL at Chassis level
        if self.chassis_uri:
            base_eps.append(f"{self.chassis_uri}/LogServices")
        entries = []
        for base_ep in base_eps:
            svc = self._get(base_ep)
            if svc and isinstance(svc.get("Members"), list):
                raw_members = self._get_members(svc)

                # Prioritize active fault lists (FaultList, ActiveLog) before historical logs (SEL, IML)
                def _log_priority(m: dict) -> int:
                    u = str(m.get("@odata.id") or "").lower()
                    if "fault" in u or "activelog" in u or "activeevent" in u:
                        return 0
                    if "sel" in u or "iml" in u:
                        return 1
                    return 2

                sorted_members = sorted(
                    [m for m in raw_members if isinstance(m, dict) and m.get("@odata.id")],
                    key=_log_priority,
                )

                for m in sorted_members:
                    uri = m.get("@odata.id")
                    if not uri:
                        continue
                    if any(t in uri.lower() for t in [
                        "fault", "activelog", "sel", "iml",
                        "platform", "eventlog", "auditlog",
                    ]):
                        ep_data = self._get(f"{uri}/Entries?$top=50", timeout=10, critical=False)
                        if not ep_data:
                            ep_data = self._get(f"{uri}/Entries", timeout=10, critical=False)
                        if ep_data and isinstance(ep_data.get("Members"), list):
                            # Follow pagination; cap total entries pulled to limit memory
                            pulled = self._get_members(ep_data, limit=min(50, max_entries * 5))
                            if pulled:
                                entries.extend(pulled)
                                # If active fault entries were found, prioritize them
                                if "fault" in uri.lower() or "activelog" in uri.lower():
                                    break
                if entries:
                    break
        unique, seen = [], set()
        for e in sorted(entries, key=lambda x: str(x.get("Created", "")), reverse=True):
            sev = str(e.get("Severity", "OK")).strip()
            msg = str(e.get("Message", "")).strip()
            if msg.lower() in ("log cleared.", "log cleared", "sel cleared.", "sel cleared"):
                continue
            if sev.lower() in ["warning", "critical", "fatal", "major"] and msg not in seen:
                seen.add(msg)
                badge = "<span class='badge danger'>🔴 Critical</span>" if sev.lower() in ["critical", "fatal"] else "<span class='badge warning'>🟡 Warning</span>"

                # Extract MessageId attribute cleanly from entry, checking Redfish standard,
                # OEM Dell extensions, EventId, and Id fallbacks
                oem_dell = (
                    e.get("Oem", {}).get("Dell", {})
                    if isinstance(e.get("Oem"), dict) and isinstance(e.get("Oem", {}).get("Dell"), dict)
                    else {}
                )
                raw_msg_id = (
                    e.get("MessageId")
                    or e.get("EventId")
                    or oem_dell.get("MessageId")
                    or oem_dell.get("EventId")
                    or e.get("Id")
                )
                msg_id = str(raw_msg_id).strip() if raw_msg_id is not None else ""
                if not msg_id or msg_id.lower() in ("none", "null", "unknown"):
                    # Check if message text starts with code pattern like 'MEM0001:' or 'CPU0001 -'
                    m_code = re.match(r"^([A-Za-z]{3,6}\d{3,5})\b", msg)
                    msg_id = m_code.group(1).upper() if m_code else "N/A"

                unique.append({
                    "severity": sev,
                    "message": msg,
                    "timestamp": str(e.get("Created", "Unknown")).strip(),
                    "message_id": msg_id,
                    "badge": badge,
                })
                limit = max_entries if max_entries is not None and max_entries > 0 else 10
                if len(unique) >= limit:
                    break
        return unique
