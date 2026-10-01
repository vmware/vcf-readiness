"""
VCF Readiness Tool — Intel BMC (server platform management) OEM adapter.

Handles Intel Server Platform Services (SPS) BMC Redfish quirks.

Known Intel BMC behaviour:
  • Redfish root at standard path /redfish/v1.
  • Some models expose SystemBoardMemoryUsage via TelemetryService.
  • CPU string may be generic — use Processor.Model field when available.
  • Systems URI may be serial (e.g. /Systems/BQKL92700DXF) or RackMount —
    handled by _discover_roots, not hardcoded.
  • Existing samples/intel-bmc/ capture used hardcoded /Systems/1 and failed;
    recapture with tools/redfishMockupCreate.py.
"""
from .generic import GenericCollector


class IntelBMCCollector(GenericCollector):
    """Intel BMC Redfish adapter."""

    VENDOR_MATCH = ("INTEL",)  # matched against Manufacturer string upper()
    vendor: str = "intel"

    def oem_manager_paths(self) -> list:
        """Intel BMC Manager Id varies: BMC, 1, hostname, or CIMC-like.
        Discovery still uses Members[0]; these are fallbacks when /Managers/1 is missing.
        """
        return [
            "/redfish/v1/Managers/BMC",
            "/redfish/v1/Managers/1",
        ]
