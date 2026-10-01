"""
VCF Readiness Tool — logging configuration and shared utility helpers.
"""
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import zipfile
from typing import Optional, Tuple

logger = logging.getLogger("vcf_assess")


def configure_logging(debug: bool = False, log_file: Optional[str] = None, mode: str = "w"):
    level = logging.DEBUG if debug else logging.WARNING
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")

    # Reset the named logger directly so repeated calls (GUI multi-scan) work correctly.
    # logging.basicConfig() is a no-op when the root logger already has handlers, so we
    # configure the "vcf_assess" logger explicitly instead.
    log = logging.getLogger("vcf_assess")
    for _h in list(log.handlers):
        try:
            _h.close()
        except Exception:
            pass
        log.removeHandler(_h)
    log.setLevel(level)
    log.propagate = False

    _stdout_h = logging.StreamHandler(sys.stdout)
    _stdout_h.setFormatter(fmt)
    log.addHandler(_stdout_h)

    if log_file:
        file_mode = mode if mode in ("w", "a") else "w"
        _file_h = logging.FileHandler(log_file, mode=file_mode, encoding="utf-8")
        try:
            os.chmod(log_file, 0o600)
        except Exception:
            pass
        _file_h.setFormatter(fmt)
        log.addHandler(_file_h)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def get_nested(d, *keys, default=None):
    """Safely traverse nested dictionaries even if intermediate keys map to None or non-dict values."""
    curr = d
    for k in keys:
        if not isinstance(curr, dict):
            return default
        curr = curr.get(k)
    return curr if curr is not None else default


def sanitize_filename(name: str) -> str:
    """Make a string safe for use as a filename on all platforms (Windows included)."""
    for ch in r':*?"<>|/\\' + "'":
        name = name.replace(ch, "_")
    # Strip control characters
    name = "".join(c if ord(c) >= 32 else "_" for c in name)
    # Windows: no trailing dots/spaces, no reserved device names
    name = name.strip().rstrip(". ")
    stem = name.split(".")[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL",
                *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}:
        name = f"_{name}"
    return name or "_"


def is_private_or_local_target(target: str) -> bool:
    """Check if a target IP address or hostname is a private/local/loopback network address.

    Recognizes:
      - RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
      - Loopback (127.0.0.0/8, ::1)
      - Link-Local (169.254.0.0/16, fe80::/10)
      - RFC6598 Shared Carrier (100.64.0.0/10)
      - Private IPv6 (fc00::/7)
      - Local hostnames (.local, .internal, localhost, .lan)
    """
    if not target or not isinstance(target, str):
        return False
    clean = target.strip().lower()
    if clean in ("localhost", "127.0.0.1", "::1"):
        return True
    if clean.endswith((".local", ".internal", ".lan", ".home.arpa")):
        return True

    # Try parsing as IP
    try:
        ip_obj = ipaddress.ip_address(clean)
        return bool(ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved)
    except ValueError:
        # If hostname, try resolving IP address
        try:
            resolved = socket.gethostbyname(clean)
            ip_obj = ipaddress.ip_address(resolved)
            return bool(ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved)
        except Exception:
            return False


_CLOUD_METADATA_IPS = {
    "169.254.169.254",
    "169.254.169.253",
    "169.254.169.123",
    "169.254.170.2",
    "fd00:ec2::254",
}
_CLOUD_METADATA_HOSTNAMES = {
    "instance-data",
    "metadata.google.internal",
    "metadata",
}


def _is_cloud_metadata_ip(ip_str: str) -> bool:
    if ip_str in _CLOUD_METADATA_IPS:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip_obj, ipaddress.IPv4Address):
        octets = ip_obj.exploded.split(".")
        return octets[0] == "169" and octets[1] == "254" and octets[2] in ("169", "170")
    if isinstance(ip_obj, ipaddress.IPv6Address):
        return ip_obj.exploded == ipaddress.ip_address("fd00:ec2::254").exploded
    return False


def is_cloud_metadata_target(target: str) -> bool:
    """Check if a target IP or hostname (including its DNS resolution) is a prohibited cloud metadata service (SSRF protection)."""
    if not target or not isinstance(target, str):
        return False
    clean = target.strip().lower().rstrip(".")
    if clean in _CLOUD_METADATA_HOSTNAMES:
        return True
    if _is_cloud_metadata_ip(clean):
        return True
    # Not an IP literal → resolve and check every address (DNS-based bypass protection)
    try:
        ipaddress.ip_address(clean)
        return False  # valid IP literal, already checked above
    except ValueError:
        pass
    # Guard against pathological inputs: only resolve plausible hostname strings
    if not clean or len(clean) > 253 or not re.match(r"^[a-z0-9.\-_]+$", clean):
        return False
    # Note: TOCTOU caveat — DNS may re-resolve differently at connect time (DNS rebinding).
    # Full pinning of resolved IPs is out of scope; this closes trivial static-DNS bypass.
    try:
        infos = socket.getaddrinfo(clean, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError):
        return False
    for info in infos:
        addr = info[4][0]
        # strip IPv6 zone id if present
        if isinstance(addr, str):
            addr = addr.split("%", 1)[0]
        if _is_cloud_metadata_ip(str(addr)):
            return True
    return False


_DNS_LOCK = threading.Lock()
_DNS_CACHE = {}


def resolve_target_fqdn(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Resolve IP to hostname via PTR lookup and perform Forward-Confirmed Reverse DNS (FCrDNS).

    Returns verified FQDN string if reverse lookup and forward confirmation match;
    returns None if lookup fails, forward confirmation does not match the IP, or host is not resolvable.
    """
    if not ip or not isinstance(ip, str):
        return None
    clean_ip = ip.strip()
    with _DNS_LOCK:
        if clean_ip in _DNS_CACHE:
            return _DNS_CACHE[clean_ip]

    try:
        # Check if clean_ip is an IP address
        try:
            ipaddress.ip_address(clean_ip)
            is_ip = True
        except ValueError:
            is_ip = False

        if not is_ip:
            # It is already a hostname; verify forward resolution
            old_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(timeout)
                socket.gethostbyname(clean_ip)
            finally:
                socket.setdefaulttimeout(old_timeout)
            with _DNS_LOCK:
                _DNS_CACHE[clean_ip] = clean_ip
            return clean_ip

        # Reverse PTR lookup
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
            hostname, _, _ = socket.gethostbyaddr(clean_ip)
        finally:
            socket.setdefaulttimeout(old_timeout)

        if not hostname:
            with _DNS_LOCK:
                _DNS_CACHE[clean_ip] = None
            return None

        # Forward confirmation check (FCrDNS)
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
            resolved_ip = socket.gethostbyname(hostname)
        finally:
            socket.setdefaulttimeout(old_timeout)

        if resolved_ip == clean_ip:
            logger.debug("FCrDNS verified: %s -> %s", clean_ip, hostname)
            with _DNS_LOCK:
                _DNS_CACHE[clean_ip] = hostname
            return hostname
        else:
            logger.debug("FCrDNS mismatch for IP %s: reverse PTR %s resolved to %s", clean_ip, hostname, resolved_ip)
            with _DNS_LOCK:
                _DNS_CACHE[clean_ip] = None
            return None
    except Exception as exc:
        logger.debug("DNS resolution lookup failed for %s: %s", clean_ip, exc)
        with _DNS_LOCK:
            _DNS_CACHE[clean_ip] = None
        return None


def strip_url_userinfo(host: str) -> str:
    """Return a host with URL userinfo removed.

    Embedded credentials are discarded. The password stays on the separate
    argument, which is supplied by getpass, an environment variable, or stdin.
    """
    from urllib.parse import urlsplit

    text = str(host or "").strip()
    if "@" not in text:
        return text
    parsed = urlsplit("//" + text)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("target must not include embedded credentials")
    if ":" in hostname:
        hostname = "[%s]" % hostname
    if parsed.port:
        return "%s:%s" % (hostname, parsed.port)
    return hostname


def parse_ip_targets(
    target_str: str,
    max_targets: int = 1024,
    force: bool = False,
    restrict_private: bool = False,
    block_metadata: bool = True,
) -> list:
    if not target_str or not isinstance(target_str, str):
        return []

    # Strip dangerous HTML/control characters for hygiene
    clean_raw = re.sub(r"[<>\"'`;]", "", target_str)
    targets = []
    parts = [p.strip() for p in clean_raw.split(",") if p.strip()]
    for part in parts:
        if "@" in part:
            raise ValueError(
                "target must not include embedded credentials; "
                "pass the password via getpass, an environment variable, or --creds-stdin"
            )
        if len(part) > 255:
            raise ValueError(f"Target entry '{part[:30]}...' is excessively long (>255 characters).")
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)-(\d+)$", part)
        if m:
            o1, o2, o3, start, end = (
                int(m.group(1)),
                int(m.group(2)),
                int(m.group(3)),
                int(m.group(4)),
                int(m.group(5)),
            )
            if not (0 <= o1 <= 255 and 0 <= o2 <= 255 and 0 <= o3 <= 255):
                raise ValueError(f"Invalid IP octet in range '{part}': octets must be between 0 and 255.")
            if not (0 <= start <= 255 and 0 <= end <= 255):
                raise ValueError(f"Invalid range octet in '{part}': range bounds must be between 0 and 255.")
            if start > end:
                raise ValueError(f"Invalid range in '{part}': start value ({start}) cannot be greater than end value ({end}).")
            targets.extend([f"{o1}.{o2}.{o3}.{i}" for i in range(start, end + 1)])
        elif "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                if net.prefixlen <= 16 and not force:
                    raise ValueError(f"Refusing to scan CIDR '{part}' with prefix length /{net.prefixlen} (<= /16). Use --force to override.")
                if net.num_addresses == 1:
                    targets.append(str(net.network_address))
                else:
                    targets.extend([str(ip) for ip in net.hosts()])
            except ValueError as exc:
                if "Refusing to scan CIDR" in str(exc):
                    raise
                pass
        else:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", part):
                octets = [int(x) for x in part.split(".")]
                if any(o > 255 for o in octets):
                    raise ValueError(f"Invalid IP address '{part}': octets must be between 0 and 255.")
            targets.append(part)

    unique_targets = list(dict.fromkeys(targets))
    if len(unique_targets) > max_targets and not force:
        raise ValueError(
            f"Target count ({len(unique_targets)}) exceeds maximum limit of {max_targets}. "
            "Use --force to bypass this limit or specify a smaller target range."
        )

    if block_metadata:
        metadata_targets = [t for t in unique_targets if is_cloud_metadata_target(t)]
        if metadata_targets:
            sample = ", ".join(metadata_targets[:3])
            raise ValueError(
                f"Target range includes prohibited cloud metadata endpoint(s): {sample}. "
                "Scanning cloud instance metadata services is blocked for security."
            )

    if restrict_private:
        public_targets = [t for t in unique_targets if not is_private_or_local_target(t)]
        if public_targets:
            sample = ", ".join(public_targets[:3])
            more = f" and {len(public_targets) - 3} more" if len(public_targets) > 3 else ""
            raise ValueError(
                f"Target range includes public IP address(es): {sample}{more}. "
                "Scanning public targets is blocked because private target restriction is enabled."
            )

    return unique_targets


def parse_version_tuple(v_str: str) -> tuple:
    if not v_str:
        return (0, 0, 0, 0)
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v_str))
    if m:
        g1 = int(m.group(1))
        g2 = int(m.group(2))
        g3 = int(m.group(3)) if m.group(3) else 0
        g4 = int(m.group(4)) if m.group(4) else 0
        return (g1, g2, g3, g4)
    return (0, 0, 0, 0)


def is_root_user() -> Tuple[bool, Optional[str]]:
    """
    Check if the process is running as root / superuser.
    Returns (True, sudo_user) if root, where sudo_user is $SUDO_USER if launched via sudo, else None.
    Returns (False, None) if running as a standard non-root user.
    """
    try:
        euid_fn = getattr(os, "geteuid", None)
        if euid_fn is not None and euid_fn() == 0:
            sudo_user = os.environ.get("SUDO_USER")
            return True, sudo_user
    except Exception:
        pass
    return False, None


def normalize_output_dir(dir_path: Optional[str] = None) -> str:
    """
    Normalize output directory path, ensuring all output lands inside a 'VCF-Scans' or 'Redfish-Library' container folder.
    Expands '~' and resolves relative paths. If dir_path is empty/None, returns default output dir.
    """
    if not dir_path or not str(dir_path).strip():
        return get_default_output_dir()

    expanded = os.path.abspath(os.path.expanduser(str(dir_path).strip()))
    # If the path already has a 'vcf-scans' or 'redfish-library' container component, do not nest another VCF-Scans
    path_parts = [p.lower() for p in expanded.split(os.sep)]
    if "vcf-scans" in path_parts or "redfish-library" in path_parts:
        return expanded

    if os.path.basename(expanded).lower() not in ("vcf-scans", "redfish-library"):
        expanded = os.path.join(expanded, "VCF-Scans")
    return expanded


def get_default_output_dir() -> str:
    """
    Determine a safe and sensible default output directory for generated reports.

    When running as a standard user, defaults to `~/Desktop/VCF-Scans` if `~/Desktop` exists.
    Supports REDFISH_LIBRARY_DIR environment override or fallback to ~/Documents/Redfish-Library.
    When running as root (or via sudo), attempts to find the real user's Desktop, `/Users/Shared`,
    or fallback to current working directory, appended with `VCF-Scans`.
    """
    env_dir = os.environ.get("REDFISH_LIBRARY_DIR")
    if env_dir and os.path.isdir(os.path.expanduser(env_dir)):
        return os.path.abspath(os.path.expanduser(env_dir))

    is_root, sudo_user = is_root_user()

    base_dir = None
    if sudo_user:
        candidate_paths = [
            f"/Users/{sudo_user}/Desktop",
            f"/home/{sudo_user}/Desktop",
        ]
        for c in candidate_paths:
            if os.path.isdir(c):
                base_dir = c
                break

    if not base_dir:
        user_desktop = os.path.expanduser("~/Desktop")
        if not is_root and os.path.isdir(user_desktop):
            base_dir = user_desktop
        elif os.path.isdir("/Users/Shared"):
            base_dir = "/Users/Shared"
        elif os.path.isdir(user_desktop):
            base_dir = user_desktop
        else:
            base_dir = os.getcwd()

    if os.path.basename(base_dir).lower() != "vcf-scans":
        return os.path.join(base_dir, "VCF-Scans")
    return base_dir


def generate_scan_dirname(
    host_count: int,
    quick: bool = False,
    obfuscate: bool = False,
    lean: bool = False,
    save_json: bool = False,
    now: Optional[time.struct_time] = None,
) -> str:
    """
    Generate a concise, descriptive directory name for a scan execution.
    Schema: Scan_YYYY-MM-DD_HHMM_[N]hosts_[flags]

    Examples:
      Scan_2026-08-19_1430_4hosts
      Scan_2026-08-19_1435_10hosts_quick_obf
    """
    t = now or time.localtime()
    timestamp_str = time.strftime("%Y-%m-%d_%H%M", t)
    host_label = f"{host_count}host" if host_count == 1 else f"{host_count}hosts"

    flags = []
    if quick:
        flags.append("quick")
    if obfuscate:
        flags.append("obf")
    if lean:
        flags.append("lean")
    if save_json:
        flags.append("json")

    parts = ["Scan", timestamp_str, host_label] + flags
    return "_".join(parts)


def create_scan_output_dir(
    base_dir: str,
    host_count: int,
    quick: bool = False,
    obfuscate: bool = False,
    lean: bool = False,
    save_json: bool = False,
    now: Optional[time.struct_time] = None,
) -> str:
    """
    Create a unique per-scan subfolder inside `base_dir`.
    Handles name collisions by appending `_01`, `_02`, etc. if a scan
    with identical parameters runs in the exact same minute.
    Returns the created absolute/normalized directory path.
    """
    base_dir = os.path.expanduser(base_dir)
    os.makedirs(base_dir, exist_ok=True)

    folder_name = generate_scan_dirname(
        host_count=host_count,
        quick=quick,
        obfuscate=obfuscate,
        lean=lean,
        save_json=save_json,
        now=now,
    )

    candidate = os.path.join(base_dir, folder_name)
    if not os.path.exists(candidate):
        os.makedirs(candidate, exist_ok=True)
        return candidate

    for seq in range(1, 100):
        seq_candidate = os.path.join(base_dir, f"{folder_name}_{seq:02d}")
        if not os.path.exists(seq_candidate):
            os.makedirs(seq_candidate, exist_ok=True)
            return seq_candidate

    os.makedirs(candidate, exist_ok=True)
    return candidate


def create_scan_zip_archive(scan_dir: str, zip_filepath: Optional[str] = None) -> str:
    """
    Compress all files in `scan_dir` into a .zip archive.
    If `zip_filepath` is not provided, defaults to placing the zip archive inside `scan_dir`.
    Returns the created zip archive path.
    """
    scan_dir = os.path.abspath(scan_dir)
    if not zip_filepath:
        zip_filepath = os.path.join(scan_dir, f"{os.path.basename(scan_dir)}.zip")
    else:
        zip_filepath = os.path.abspath(zip_filepath)

    parent_dir = os.path.dirname(scan_dir)

    with zipfile.ZipFile(zip_filepath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(scan_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                if os.path.abspath(abs_path) == zip_filepath:
                    continue
                rel_path = os.path.relpath(abs_path, parent_dir)
                zf.write(abs_path, arcname=rel_path)

    return zip_filepath


OBFUSCATED_PACKAGE_README = """================================================================================
VCF / vSphere 9.1 HCI Readiness Assessment — Obfuscated Fleet Scan Package
================================================================================

HOW TO VIEW THE ASSESSMENT REPORTS:
--------------------------------------------------------------------------------
1. Interactive Fleet Dashboard:
   -> Open "00_OBFUSCATED_fleet_combined.html" in any modern web browser.
      Features:
      - Executive summary tiles (CPU support, TPM 2.0, vSAN ESA/OSA readiness)
      - Detailed Inventory SE Decision Matrix with search and filtering
      - Host selection dropdown for instant hardware specification views
      - Dynamic sub-report drill-downs for each host

2. High-Level Executive Summary Only:
   -> Open "00_OBFUSCATED_fleet_summary.html" for a concise, printable overview.

3. Tabular Hardware & Component Spreadsheets:
   -> Open "00_OBFUSCATED_vcf_readiness_*.xlsx" in Excel or compatible viewer.
   -> Standardized CSV tables:
      - 00_OBFUSCATED_fleet_summary.csv
      - 00_OBFUSCATED_drives_inventory.csv
      - 00_OBFUSCATED_nics_inventory.csv
      - 00_OBFUSCATED_gpus_inventory.csv (if GPUs present)
      - 00_OBFUSCATED_failed_hosts.csv (if unreachable targets exist)

4. Individual Host Sub-Reports:
   -> Located in the "reports/" folder (e.g., reports/OBFUSCATED_Host-1.html).
      These are loaded dynamically by the combined fleet dashboard.

5. Raw Sanitized JSON Telemetry:
   -> Located in the "data/" folder (e.g., data/OBFUSCATED_Host-1.json).


DATA SANITIZATION & PRIVACY POLICY:
--------------------------------------------------------------------------------
This archive has been thoroughly sanitized and is safe for external review:
- Target IP addresses have been replaced with anonymous identifiers (Host-1..N).
- Hostnames, DNS names, and asset tags have been scrubbed or masked.
- Hardware serial numbers and service tags are replaced with salted hash tokens.
- Network MAC addresses and WWNs are normalized to private documentation prefixes.
- Hardware architectures, CPU models, RAM topologies, firmware baselines, and
  vSAN ESA compatibility rules reflect 100% authentic Redfish telemetry.
================================================================================
"""


def create_obfuscated_scan_zip_archive(
    scan_dir: str,
    zip_filepath: Optional[str] = None,
    failed_hosts: Optional[list] = None,
    results: Optional[list] = None,
    include_excel: Optional[bool] = None,
    include_csv: Optional[bool] = None,
) -> str:
    """
    Compress exclusively sanitized/obfuscated files from `scan_dir` into an isolated
    .zip archive, ensuring zero leakage of real IPs, serial numbers, or private metadata.

    The archive contains:
      - 00_OBFUSCATED_fleet_combined.html (interactive fleet hub)
      - 00_OBFUSCATED_fleet_summary.html (executive summary)
      - 00_OBFUSCATED_vcf_readiness_*.xlsx (Excel workbook)
      - 00_OBFUSCATED_*.csv (standardized CSV tables)
      - reports/OBFUSCATED_Host-*.html (sub-reports)
      - data/OBFUSCATED_Host-*.json & fleet summary JSON parts
      - README.txt (viewer guide & data sanitization policy)
      - MANIFEST.json (fleet drop metadata with obfuscated: True)

    Returns the created zip archive path.
    """
    from vcf_hci.constants import TOOL_VERSION

    scan_dir = os.path.abspath(scan_dir)
    scan_basename = os.path.basename(scan_dir)
    archive_root_name = (
        scan_basename if scan_basename.endswith("_OBFUSCATED")
        else f"{scan_basename}_OBFUSCATED"
    )

    if not zip_filepath:
        zip_filepath = os.path.join(scan_dir, f"{archive_root_name}.zip")
    else:
        zip_filepath = os.path.abspath(zip_filepath)

    # 1. Determine if obfuscated results exist or can be loaded
    obf_results = results
    if obf_results is None:
        data_dir = os.path.join(scan_dir, "data")
        if os.path.isdir(data_dir):
            loaded = []
            json_files = sorted(
                [
                    f for f in os.listdir(data_dir)
                    if (f.startswith("OBFUSCATED_Host-") or f.startswith("OBFUSCATED_vcf_summary_Host-"))
                    and f.endswith(".json")
                ],
                key=lambda x: [
                    int(t) if t.isdigit() else t
                    for t in re.split(r"(\d+)", x)
                ],
            )
            for jf in json_files:
                try:
                    with open(os.path.join(data_dir, jf), encoding="utf-8") as f:
                        loaded.append(json.load(f))
                except Exception:
                    pass
            if loaded:
                obf_results = loaded

    # If still no obfuscated results, check if un-obfuscated data exists to obfuscate
    if obf_results is None and not os.path.isfile(os.path.join(scan_dir, "00_OBFUSCATED_fleet_combined.html")):
        data_dir = os.path.join(scan_dir, "data")
        if os.path.isdir(data_dir):
            raw_loaded = []
            for jf in sorted(os.listdir(data_dir)):
                if (jf.startswith("vcf_summary_") or (jf.startswith("Host-") and not jf.startswith("OBFUSCATED_"))) and jf.endswith(".json"):
                    try:
                        with open(os.path.join(data_dir, jf), encoding="utf-8") as f:
                            raw_loaded.append(json.load(f))
                    except Exception:
                        pass
            if raw_loaded:
                from vcf_hci.obfuscation import obfuscate_host_data
                obf_salt = os.urandom(16).hex()
                obf_results = [obfuscate_host_data(r, f"Host-{i+1}", obf_salt) for i, r in enumerate(raw_loaded)]

    # If results are passed as un-obfuscated, obfuscate them
    if obf_results and not any(r.get("obfuscated") for r in obf_results):
        from vcf_hci.obfuscation import obfuscate_host_data
        obf_salt = os.urandom(16).hex()
        obf_results = [obfuscate_host_data(r, f"Host-{i+1}", obf_salt) for i, r in enumerate(obf_results)]

    # Generate missing HTML reports if needed
    if obf_results and not os.path.isfile(os.path.join(scan_dir, "00_OBFUSCATED_fleet_combined.html")):
        try:
            from vcf_hci.report import _generate_combined_html, generate_host_html_report, generate_summary_html
            obf_report_paths = []
            reports_dir = os.path.join(scan_dir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            data_dir = os.path.join(scan_dir, "data")
            os.makedirs(data_dir, exist_ok=True)
            for i, r in enumerate(obf_results):
                t = r.get("target") or f"Host-{i+1}"
                r_path = os.path.join(reports_dir, f"OBFUSCATED_{t}.html")
                generate_host_html_report(r, r_path, obfuscated=True)
                obf_report_paths.append(r_path)
                with open(os.path.join(data_dir, f"OBFUSCATED_{t}.json"), "w", encoding="utf-8") as f:
                    json.dump(r, f, indent=2)
            _generate_combined_html(obf_results, obf_report_paths, scan_dir, obfuscated=True)
            generate_summary_html(obf_results, os.path.join(scan_dir, "00_OBFUSCATED_fleet_summary.html"), obfuscated=True)
        except Exception as _rep_exc:
            logger.debug("Could not auto-generate missing obfuscated HTML reports: %s", _rep_exc)

    # Generate missing CSV exports if needed
    if include_csv is None:
        raw_csv = [
            f for f in os.listdir(scan_dir)
            if f.endswith(".csv") and not f.startswith("00_OBFUSCATED_")
        ]
        should_include_csv = bool(raw_csv)
    else:
        should_include_csv = bool(include_csv)

    csv_summary_path = os.path.join(scan_dir, "00_OBFUSCATED_fleet_summary.csv")
    if should_include_csv and not os.path.isfile(csv_summary_path) and obf_results:
        try:
            from vcf_hci.report.csv_export import export_all_csvs
            export_all_csvs(obf_results, scan_dir, obfuscated=True, failed_hosts=failed_hosts)
        except Exception as _csv_exc:
            logger.debug("Could not auto-generate obfuscated CSVs: %s", _csv_exc)

    # Generate missing obfuscated Excel if needed
    if include_excel is None:
        raw_xlsx = [
            f for f in os.listdir(scan_dir)
            if f.endswith(".xlsx") and not f.startswith("00_OBFUSCATED_")
        ]
        should_include_excel = bool(raw_xlsx)
    else:
        should_include_excel = bool(include_excel)

    existing_xlsx = [
        f for f in os.listdir(scan_dir)
        if f.startswith("00_OBFUSCATED_") and f.endswith(".xlsx")
    ]
    if should_include_excel and not existing_xlsx and obf_results:
        try:
            from vcf_hci.report.excel_export import export_to_excel
            export_to_excel(obf_results, scan_dir, failed_hosts=failed_hosts, obfuscated=True)
        except Exception as _xlsx_exc:
            logger.debug("Could not auto-generate obfuscated Excel: %s", _xlsx_exc)

    # 2. Prepare sanitized MANIFEST.json
    manifest_data = None
    manifest_src = os.path.join(scan_dir, "MANIFEST.json")
    if os.path.isfile(manifest_src):
        try:
            with open(manifest_src, encoding="utf-8") as f:
                manifest_data = json.load(f)
        except Exception:
            manifest_data = None

    if isinstance(manifest_data, dict):
        manifest_data = dict(manifest_data)
        manifest_data["obfuscated"] = True
    else:
        rep_dir = os.path.join(scan_dir, "reports")
        n_hosts = len(obf_results) if obf_results else 0
        if not n_hosts and os.path.isdir(rep_dir):
            n_hosts = len([f for f in os.listdir(rep_dir) if f.startswith("OBFUSCATED_") and f.endswith(".html")])
        manifest_data = {
            "tool_version": TOOL_VERSION,
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host_count": n_hosts,
            "collector_id": "vcf-fleet-collector",
            "site": "sanitized",
            "scan_profile": "readiness-full",
            "obfuscated": True,
        }

    # 3. Build the zip archive with strict sanitization deny-list
    os.makedirs(os.path.dirname(zip_filepath), exist_ok=True)

    # Generate sanitized Readme.txt
    try:
        from vcf_hci.report.readme import generate_scan_readme
        readme_content = generate_scan_readme(
            outdir=scan_dir,
            host_count=manifest_data.get("host_count", 0),
            site=manifest_data.get("site", "sanitized"),
            collector_id=manifest_data.get("collector_id", "vcf-fleet-collector"),
            scan_profile=manifest_data.get("scan_profile", "readiness-full"),
            obfuscated=True,
            tool_version=manifest_data.get("tool_version", TOOL_VERSION),
            failed_count=len(failed_hosts) if failed_hosts else 0,
        )
    except Exception:
        readme_content = OBFUSCATED_PACKAGE_README

    with zipfile.ZipFile(zip_filepath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Write root metadata files
        zf.writestr(f"{archive_root_name}/README.txt", readme_content)
        zf.writestr(f"{archive_root_name}/MANIFEST.json", json.dumps(manifest_data, indent=2))

        # Root files: strictly starting with 00_OBFUSCATED_ or OBFUSCATED_
        for f in sorted(os.listdir(scan_dir)):
            if f.endswith(".zip"):
                continue
            abs_p = os.path.join(scan_dir, f)
            if not os.path.isfile(abs_p):
                continue
            if abs_p == zip_filepath:
                continue
            if f.startswith("00_OBFUSCATED_") or f.startswith("OBFUSCATED_"):
                zf.write(abs_p, arcname=f"{archive_root_name}/{f}")

        # reports/ folder: strictly starting with OBFUSCATED_
        reports_dir = os.path.join(scan_dir, "reports")
        if os.path.isdir(reports_dir):
            for f in sorted(os.listdir(reports_dir)):
                abs_p = os.path.join(reports_dir, f)
                if os.path.isfile(abs_p) and f.startswith("OBFUSCATED_"):
                    zf.write(abs_p, arcname=f"{archive_root_name}/reports/{f}")

        # data/ folder: strictly starting with OBFUSCATED_
        data_dir = os.path.join(scan_dir, "data")
        if os.path.isdir(data_dir):
            for f in sorted(os.listdir(data_dir)):
                abs_p = os.path.join(data_dir, f)
                if os.path.isfile(abs_p) and f.startswith("OBFUSCATED_"):
                    zf.write(abs_p, arcname=f"{archive_root_name}/data/{f}")

    return zip_filepath


def update_latest_scan_aliases(scan_dir: str, base_dir: Optional[str] = None) -> dict:
    """
    Maintain root-level HTML redirect alias files in `base_dir` pointing to the
    latest reports inside `scan_dir`.

    Aliases created if corresponding report exists in `scan_dir`:
      - `!00_LATEST_FLEET_SUMMARY.html` -> `<scan_dir>/00_fleet_summary.html`
      - `!00_LATEST_FLEET_COMBINED.html` -> `<scan_dir>/00_fleet_combined.html`
      - `!00_LATEST_OBFUSCATED_FLEET_SUMMARY.html` -> `<scan_dir>/00_OBFUSCATED_fleet_summary.html`
      - `!00_LATEST_OBFUSCATED_FLEET_COMBINED.html` -> `<scan_dir>/00_OBFUSCATED_fleet_combined.html`

    Removes any alias file in `base_dir` if the corresponding report does NOT exist in `scan_dir`.
    Returns dict mapping alias file path to target relative path.
    """
    scan_dir = os.path.abspath(scan_dir)
    if not base_dir:
        base_dir = os.path.dirname(scan_dir)
    else:
        base_dir = os.path.abspath(os.path.expanduser(base_dir))

    alias_map = {
        "!00_LATEST_FLEET_SUMMARY.html": "00_fleet_summary.html",
        "!00_LATEST_FLEET_COMBINED.html": "00_fleet_combined.html",
        "!00_LATEST_OBFUSCATED_FLEET_SUMMARY.html": "00_OBFUSCATED_fleet_summary.html",
        "!00_LATEST_OBFUSCATED_FLEET_COMBINED.html": "00_OBFUSCATED_fleet_combined.html",
    }

    created_aliases = {}
    rel_scan_dir = os.path.relpath(scan_dir, base_dir)

    for alias_name, target_name in alias_map.items():
        target_abs = os.path.join(scan_dir, target_name)
        alias_abs = os.path.join(base_dir, alias_name)

        if os.path.isfile(target_abs):
            rel_target = os.path.join(rel_scan_dir, target_name).replace("\\", "/")
            html_content = (
                f'<!DOCTYPE html>\n'
                f'<html>\n'
                f'<head>\n'
                f'<meta charset="utf-8">\n'
                f'<meta http-equiv="refresh" content="0; url={rel_target}">\n'
                f'<script>window.location.replace("{rel_target}");</script>\n'
                f'<title>Redirecting to Latest Report...</title>\n'
                f'</head>\n'
                f'<body>\n'
                f'<p>Redirecting to latest report: <a href="{rel_target}">{rel_target}</a></p>\n'
                f'</body>\n'
                f'</html>\n'
            )
            try:
                with open(alias_abs, "w", encoding="utf-8") as f:
                    f.write(html_content)
                time.sleep(0.01)
                os.utime(alias_abs, None)
                created_aliases[alias_abs] = rel_target
            except Exception as exc:
                logger.debug(f"Failed writing alias file {alias_abs}: {exc}")
        else:
            if os.path.exists(alias_abs):
                try:
                    os.remove(alias_abs)
                except Exception as exc:
                    logger.debug(f"Failed removing stale alias file {alias_abs}: {exc}")

    # Copy latest debug log if available in scan_dir, or remove stale debug alias
    dbg_candidates = [
        os.path.join(scan_dir, "data", "vcf_assess_debug.log"),
        os.path.join(scan_dir, "vcf_assess_debug.log"),
    ]
    dbg_source = None
    for cand in dbg_candidates:
        if os.path.isfile(cand):
            dbg_source = cand
            break

    latest_dbg_aliases = [
        os.path.join(base_dir, "!00_LATEST_vcf_assess_debug.log"),
        os.path.join(base_dir, "vcf_assess_debug.log"),
    ]

    if dbg_source:
        try:
            with open(dbg_source, "rb") as sf:
                dbg_data = sf.read()
            for dst in latest_dbg_aliases:
                with open(dst, "wb") as df:
                    df.write(dbg_data)
                time.sleep(0.01)
                os.utime(dst, None)
                created_aliases[dst] = os.path.relpath(dbg_source, base_dir).replace("\\", "/")
        except Exception as exc:
            logger.debug(f"Failed copying latest debug log from {dbg_source}: {exc}")
    else:
        for dst in latest_dbg_aliases:
            if os.path.exists(dst):
                try:
                    os.remove(dst)
                except Exception as exc:
                    logger.debug(f"Failed removing stale debug log alias {dst}: {exc}")

    return created_aliases



