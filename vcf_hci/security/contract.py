"""BMC Security Audit neutral contract schema.

Defines the core evidence and finding contracts, schema versioning,
valid control ID boundaries (C01-C59, O01-O16, I01-I09), allowed
evaluation statuses, and sanitizing constructors.
"""

import re
from typing import Any, Dict, List, Optional, Set

EVIDENCE_SCHEMA_VERSION = 1

# Allowed normalized statuses for control findings
CONTROL_STATUSES: Set[str] = {
    "pass",
    "fail",
    "unknown_not_collected",
    "unknown_not_exposed",
    "unknown_write_only",
    "unknown_insufficient_privilege",
    "unknown_unlicensed",
    "unknown_unsupported",
    "unknown_ambiguous",
    "not_applicable",
}

# Allowed transports for evidence items
VALID_TRANSPORTS: Set[str] = {
    "standard_redfish",
    "oem_redfish",
    "vendor_tool",
    "external",
}

# Valid control ID populations
# Configuration controls: C01-C59 (59 total)
VALID_CONFIGURATION_IDS: Set[str] = {f"C{i:02d}" for i in range(1, 60)}

# Operational recommendations: O01-O16 (16 total)
VALID_OPERATIONAL_IDS: Set[str] = {f"O{i:02d}" for i in range(1, 17)}

# Assurance capabilities: I01-I09 (9 total)
VALID_ASSURANCE_IDS: Set[str] = {f"I{i:02d}" for i in range(1, 10)}

# All valid control IDs (84 total)
ALL_VALID_CONTROL_IDS: Set[str] = (
    VALID_CONFIGURATION_IDS | VALID_OPERATIONAL_IDS | VALID_ASSURANCE_IDS
)


class ReasonCode:
    """Standard audit finding reason codes."""

    # Passes
    STANDARD_REDFISH_PASS = "STANDARD_REDFISH_PASS"
    OEM_REDFISH_PASS = "OEM_REDFISH_PASS"

    # Fails
    STANDARD_REDFISH_FAIL = "STANDARD_REDFISH_FAIL"
    OEM_REDFISH_FAIL = "OEM_REDFISH_FAIL"

    # Unknowns
    NOT_COLLECTED = "NOT_COLLECTED"
    ENDPOINT_NOT_EXPOSED = "ENDPOINT_NOT_EXPOSED"
    PROPERTY_NOT_EXPOSED = "PROPERTY_NOT_EXPOSED"
    WRITE_ONLY_SECRET = "WRITE_ONLY_SECRET"
    INSUFFICIENT_PRIVILEGE = "INSUFFICIENT_PRIVILEGE"
    FEATURE_UNLICENSED = "FEATURE_UNLICENSED"
    FEATURE_UNSUPPORTED = "FEATURE_UNSUPPORTED"
    AMBIGUOUS_EVIDENCE = "AMBIGUOUS_EVIDENCE"
    EXTERNAL_PROCESS_REQUIRED = "EXTERNAL_PROCESS_REQUIRED"
    CLIENT_BEHAVIOR_REQUIRED = "CLIENT_BEHAVIOR_REQUIRED"

    # Not applicable
    NOT_APPLICABLE = "NOT_APPLICABLE"


_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _assert_no_html(field_name: str, value: Any) -> None:
    """Ensure a string field contains no HTML markup."""
    if isinstance(value, str) and _HTML_TAG_RE.search(value):
        raise ValueError(
            f"HTML tags are not allowed in normalized contract field '{field_name}': {value!r}"
        )


def is_valid_control_id(control_id: str) -> bool:
    """Check whether a control ID is in the recognized C01-C59, O01-O16, I01-I09 set."""
    return isinstance(control_id, str) and control_id in ALL_VALID_CONTROL_IDS


def validate_control_id(control_id: str) -> None:
    """Validate that control_id is in C01-C59, O01-O16, or I01-I09.

    Raises ValueError if invalid.
    """
    if not is_valid_control_id(control_id):
        raise ValueError(
            f"Invalid control ID '{control_id}'. Must be one of C01-C59, O01-O16, or I01-I09."
        )


def validate_status(status: str) -> None:
    """Validate that status is one of the recognized CONTROL_STATUSES.

    Raises ValueError if invalid.
    """
    if status not in CONTROL_STATUSES:
        raise ValueError(
            f"Invalid status '{status}'. Must be one of: {sorted(CONTROL_STATUSES)}"
        )


def empty_security_evidence(vendor: str) -> Dict[str, Any]:
    """Construct a clean, versioned dictionary for host security evidence.

    Guarantees fresh dictionaries and lists on each call.
    """
    _assert_no_html("vendor", vendor)
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "vendor": str(vendor) if vendor is not None else "generic",
        "standard": {},
        "oem": {},
        "capabilities": {},
        "collection_issues": [],
    }


def evidence_item(
    transport: str,
    uri: str,
    property: str,
    raw_value: Optional[Any] = None,
    normalized_value: Optional[Any] = None,
    http_status: Optional[int] = None,
    odata_type: Optional[str] = None,
    firmware: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct a normalized evidence reference item.

    Guarantees no HTML in string fields and returns a clean dictionary.
    """
    _assert_no_html("transport", transport)
    _assert_no_html("uri", uri)
    _assert_no_html("property", property)
    if odata_type is not None:
        _assert_no_html("odata_type", odata_type)
    if firmware is not None:
        _assert_no_html("firmware", firmware)

    return {
        "transport": transport,
        "uri": uri,
        "property": property,
        "raw_value": raw_value,
        "normalized_value": normalized_value,
        "http_status": http_status,
        "odata_type": odata_type,
        "firmware": firmware,
    }


def collection_issue(
    endpoint: str,
    reason: str,
    http_status: Optional[int] = None,
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct a collection issue entry for missing, denied, or errored endpoints."""
    _assert_no_html("endpoint", endpoint)
    _assert_no_html("reason", reason)
    if detail is not None:
        _assert_no_html("detail", detail)

    return {
        "endpoint": endpoint,
        "reason": reason,
        "http_status": http_status,
        "detail": detail,
    }


def control_finding(
    control_id: str,
    status: str,
    expected: str,
    observed: Optional[Any],
    reason_code: str,
    evidence: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Construct a validated, normalized control finding.

    - Validates control_id against C01-C59, O01-O16, I01-I09.
    - Validates status against CONTROL_STATUSES.
    - Rejects HTML tags in string fields.
    - Preserves None, False, 0, and other observed values without coercion.
    - Returns fresh dictionaries and lists.
    """
    validate_control_id(control_id)
    validate_status(status)
    _assert_no_html("control_id", control_id)
    _assert_no_html("status", status)
    _assert_no_html("expected", expected)
    _assert_no_html("reason_code", reason_code)

    fresh_evidence: List[Dict[str, Any]] = []
    if evidence is not None:
        for item in evidence:
            if isinstance(item, dict):
                fresh_evidence.append(dict(item))
            else:
                fresh_evidence.append(item)

    return {
        "control_id": control_id,
        "status": status,
        "expected": expected,
        "observed": observed,
        "reason_code": reason_code,
        "evidence": fresh_evidence,
    }
