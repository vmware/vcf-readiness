"""Zero-dependency IPMI 2.0 RMCP+ Cipher Suite 0 probe.

Pure Python 3.9+ standard library implementation (socket and struct)
per DMTF / IPMI v2.0 Specification Section 13.6, 13.14, 13.15, and 13.16.

Evaluates Control C27 (IPMI fallback hardening / Cipher 0) without requiring
external vendor CLI binaries (ipmitool, racadm, ilorest).
"""

import logging
import socket
import struct
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("vcf_assess")

# RMCP Header: ver=0x06, reserved=0x00, seq=0xff, class=0x07 (IPMI)
RMCP_IPMI_HEADER = b"\x06\x00\xff\x07"

# RMCP+ Status Codes (IPMI v2.0 Section 13.16, Table 13-15)
RMCP_STATUS_SUCCESS = 0x00
RMCP_STATUS_INSUFFICIENT_RESOURCES = 0x01
RMCP_STATUS_INVALID_SESSION_ID = 0x02
RMCP_STATUS_INVALID_PAYLOAD_TYPE = 0x03
RMCP_STATUS_INVALID_AUTH_ALGO = 0x04
RMCP_STATUS_INVALID_INTEGRITY_ALGO = 0x05
RMCP_STATUS_NO_MATCHING_AUTH = 0x06
RMCP_STATUS_NO_MATCHING_INTEG = 0x07
RMCP_STATUS_INACTIVE_SESSION_ID = 0x08
RMCP_STATUS_INVALID_ROLE_CIPHER = 0x09
RMCP_STATUS_UNAUTHORIZED_ROLE = 0x0A


def build_rmcp_cipher0_open_session_request(console_session_id: int = 0x11223344) -> bytes:
    """Build a 47-byte IPMI 2.0 RMCP+ Open Session Request for Cipher Suite 0.

    Request parameters:
    - Privilege: 0x00 (Highest allowable privilege)
    - Authentication Algorithm: 0x00 (RAKP-none)
    - Integrity Algorithm: 0x00 (none)
    - Confidentiality Algorithm: 0x00 (none)
    """
    # RMCP+ Header: Payload Type 0x00 (Open Session Request), Session ID 0, Seq 0, Payload Length 32
    rmcp_plus_hdr = struct.pack("<BIIH", 0x00, 0x00000000, 0x00000000, 32)

    # Open Session Request Payload (32 bytes)
    # Message Tag (0x01), Max Privilege Level (0x00), Reserved (0x0000), Remote Console Session ID
    tag_priv_sid = struct.pack("<BBHI", 0x01, 0x00, 0x0000, console_session_id)

    # Authentication Payload: type=0x00 (Auth), len=0x08, algo=0x00 (RAKP-none)
    auth = struct.pack("<BHBB3s", 0x00, 0x0000, 0x08, 0x00, b"\x00\x00\x00")

    # Integrity Payload: type=0x01 (Integrity), len=0x08, algo=0x00 (none)
    integ = struct.pack("<BHBB3s", 0x01, 0x0000, 0x08, 0x00, b"\x00\x00\x00")

    # Confidentiality Payload: type=0x02 (Confidentiality), len=0x08, algo=0x00 (none)
    conf = struct.pack("<BHBB3s", 0x02, 0x0000, 0x08, 0x00, b"\x00\x00\x00")

    return RMCP_IPMI_HEADER + rmcp_plus_hdr + tag_priv_sid + auth + integ + conf


def parse_rmcp_cipher0_open_session_response(data: bytes) -> Tuple[Optional[int], str]:
    """Parse RMCP+ Open Session Response datagram.

    Returns:
        (status_code, description)
    """
    if len(data) < 16:
        return None, f"Response too short ({len(data)} bytes, expected >= 16)"

    # Validate RMCP header
    if data[0:2] != b"\x06\x00" or data[3] != 0x07:
        return None, f"Invalid RMCP header: {data[0:4].hex()}"

    # Validate Payload Type in RMCP+ header (byte 4)
    # 0x01 = RMCP+ Open Session Response
    payload_type = data[4] & 0x3F
    if payload_type != 0x01:
        return None, f"Unexpected RMCP+ payload type: {payload_type:#04x}"

    # Payload starts at byte 14:
    # byte 14: message tag
    # byte 15: RMCP+ status code
    status_code = data[15]

    status_descriptions = {
        RMCP_STATUS_SUCCESS: "No error (Cipher Suite 0 accepted)",
        RMCP_STATUS_INSUFFICIENT_RESOURCES: "Insufficient resources to create session",
        RMCP_STATUS_INVALID_SESSION_ID: "Invalid Session ID",
        RMCP_STATUS_INVALID_PAYLOAD_TYPE: "Invalid payload type",
        RMCP_STATUS_INVALID_AUTH_ALGO: "Invalid authentication algorithm",
        RMCP_STATUS_INVALID_INTEGRITY_ALGO: "Invalid integrity algorithm",
        RMCP_STATUS_NO_MATCHING_AUTH: "No matching authentication payload",
        RMCP_STATUS_NO_MATCHING_INTEG: "No matching integrity payload",
        RMCP_STATUS_INACTIVE_SESSION_ID: "Inactive Session ID",
        RMCP_STATUS_INVALID_ROLE_CIPHER: "Invalid role or cipher suite",
        RMCP_STATUS_UNAUTHORIZED_ROLE: "Unauthorized role or privilege level requested",
    }
    desc = status_descriptions.get(status_code, f"RMCP+ status code {status_code:#04x}")
    return status_code, desc


def probe_ipmi_cipher0(
    host: str,
    port: int = 623,
    timeout: float = 2.0,
    ipmi_lan_enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    """Probe BMC UDP port 623 for IPMI 2.0 RMCP+ Cipher Suite 0 support.

    Args:
        host: Target BMC IP address or hostname.
        port: IPMI RMCP+ port (default 623).
        timeout: Socket recv timeout in seconds (default 2.0).
        ipmi_lan_enabled: Optional boolean indicating if IPMI over LAN is enabled
            according to Redfish NetworkProtocol.

    Returns:
        Dict with keys:
            - supported (bool): True if Cipher Suite 0 accepted (vulnerable); False otherwise.
            - status_code (Optional[int]): Raw RMCP+ status code if received.
            - detail (str): Human-readable diagnosis.
            - error (Optional[str]): Error message if socket/network failed.
    """
    if ipmi_lan_enabled is False:
        return {
            "supported": False,
            "status_code": None,
            "detail": "IPMI-over-LAN is disabled in BMC network settings; Cipher Suite 0 inactive",
            "error": None,
        }

    request_bytes = build_rmcp_cipher0_open_session_request()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(request_bytes, (host, port))
        response, _ = sock.recvfrom(1024)
        status_code, desc = parse_rmcp_cipher0_open_session_response(response)

        if status_code == RMCP_STATUS_SUCCESS:
            return {
                "supported": True,
                "status_code": status_code,
                "detail": f"VULNERABLE: Cipher Suite 0 accepted ({desc})",
                "error": None,
            }
        elif status_code is not None:
            return {
                "supported": False,
                "status_code": status_code,
                "detail": f"Hardened: Cipher Suite 0 rejected ({desc})",
                "error": None,
            }
        else:
            return {
                "supported": False,
                "status_code": None,
                "detail": f"Unrecognized RMCP response: {desc}",
                "error": desc,
            }
    except socket.timeout:
        return {
            "supported": False,
            "status_code": None,
            "detail": "Cipher Suite 0 probe timed out (BMC dropped or ignored unauthenticated request)",
            "error": "timed_out",
        }
    except ConnectionRefusedError:
        return {
            "supported": False,
            "status_code": None,
            "detail": "Connection refused on UDP port 623 (IPMI port closed or unreachable)",
            "error": "connection_refused",
        }
    except OSError as exc:
        return {
            "supported": False,
            "status_code": None,
            "detail": f"Network error probing UDP port 623: {exc}",
            "error": str(exc),
        }
    finally:
        sock.close()
