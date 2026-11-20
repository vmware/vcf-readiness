"""Which wizard steps and credential blocks a scope selection requires.

Step indexes match the Scan Wizard rail:

0 scope, 1 credentials, 2 discovery, 3 HCL, 4 options, 5 review.
"""

from __future__ import annotations

from dataclasses import dataclass

LAST_STEP = 5
HCL_STEP = 3


@dataclass(frozen=True)
class Scope:
    vcfr: bool = True
    vinv: bool = True
    mtat: bool = True
    vdt: bool = False
    hardware_access: str = "bmc"
    vault: bool = False
    jump_host: bool = False
    mtat_source: str = "vcenter"
    mtat_engine: str = "embedded"
    mtat_mode: str = "live"

    def __post_init__(self) -> None:
        if self.mtat_engine not in ("embedded", "upstream") or self.mtat_mode not in ("live", "import", "saved"):
            raise ValueError("Select a supported MTAT engine and workflow.")
        if self.mtat_engine == "embedded" and self.mtat_mode != "live":
            raise ValueError("Import and saved workflows require the upstream MTAT engine.")
        if self.mtat_source not in ("vcenter", "operations-rest"):
            raise ValueError("Select one MTAT source: vcenter or operations-rest")
        if self.hardware_access not in ("bmc", "esxi_ssh"):
            raise ValueError("hardware_access must be bmc or esxi_ssh")
        if not any((self.vcfr, self.vinv, self.mtat, self.vdt)):
            raise ValueError("Select at least one discovery or diagnostic tool.")

    @property
    def bmc(self) -> bool:
        return self.vcfr and self.hardware_access == "bmc"

    @property
    def esxi_ssh(self) -> bool:
        return self.vcfr and self.hardware_access == "esxi_ssh"

    @property
    def vcenter_readonly(self) -> bool:
        return self.vinv or (self.mtat and self.mtat_mode == "live" and self.mtat_source == "vcenter") or self.esxi_ssh

    @property
    def vcenter_admin(self) -> bool:
        return self.vdt

    @property
    def operations(self) -> bool:
        return self.mtat and self.mtat_mode == "live" and self.mtat_source == "operations-rest"

    @property
    def appliance_ssh(self) -> bool:
        return self.vdt


def credentials_needed(scope: Scope) -> dict:
    """Blocks required by the selected tools and single MTAT source."""
    return {
        "bmc": scope.bmc,
        "esxi_ssh": scope.esxi_ssh,
        "vcenter_readonly": scope.vcenter_readonly,
        "vcenter_admin": scope.vcenter_admin,
        "operations_optional": False,
        "operations_required": scope.operations,
        "appliance_ssh": scope.appliance_ssh,
        "vault": scope.vault or scope.jump_host,
        "jump_host": scope.jump_host,
    }


def hcl_required(scope: Scope) -> bool:
    return scope.vcfr


def next_step(current: int, scope: Scope) -> int:
    step = min(LAST_STEP, current + 1)
    if step == HCL_STEP and not hcl_required(scope):
        step = HCL_STEP + 1
    return step


def previous_step(current: int, scope: Scope) -> int:
    step = max(0, current - 1)
    if step == HCL_STEP and not hcl_required(scope):
        step = HCL_STEP - 1
    return step
