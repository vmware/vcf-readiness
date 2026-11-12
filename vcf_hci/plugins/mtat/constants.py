"""Frozen identifiers. Change only in a new contract revision."""

from __future__ import annotations

CONTRACT_REVISION = "2026-11-10"
SCHEMA_VERSION = "1.0.0"
MTAT_CONTRACT = "3.2"
FEATURE_ID = "mtat-workload-assessment"
FEATURE_NAME = "MTAT Workload Assessment (Experimental)"
LIFECYCLE = "experimental"
WARNING = (
    "Experimental workload assessment. Validate against MTAT 3.2 before sizing "
    "or deployment decisions."
)
ENABLE_FLAG = "--enable-experimental-mtat"
ENABLE_ENV = "VCF_READINESS_EXPERIMENTAL_MTAT"
PUBLIC_BASELINE_COMMIT = "3094eb3075ff3887db3e61406bf2210c064a1798"
PYVMOMI_DISTRIBUTION = "pyvmomi"
PYVMOMI_VERSION = "9.0.0.0"
PYVMOMI_FILENAME = "pyvmomi-9.0.0.0-py3-none-any.whl"
PYVMOMI_SHA256 = "7812642a62b6ce2b439d7e4856d27101ad102734bce41daf77bedfb3e2d9cbf2"
POLICY_MTAT_32 = "mtat-3.2"
POLICY_VSPHERE_CURRENT = "vsphere-current-2026-11-10"
DEFAULT_CSV_POLICY = POLICY_MTAT_32
HOST_CSV_HEADER = (
    "Cluster,HostName,Tiering,CPU_Pct,Physical_RAM,Consumed_GB,Active_GB,Active_Pct,"
    "TierRatioPct,Active_Avg_GB,NVMe_GB,Missing_Metrics,CPU_MHz,Memory_Unit"
)
VM_CSV_HEADER = (
    "Host,VMName,Provisioned_GB,Active_GB,Active_Pct,DRAM_Only,Pages_1GB,Pages_2MB,"
    "Missing_Metrics,Memory_Unit"
)
HOST_HISTORY_HEADER = (
    "Cluster,RangeName,ClusterContext,HostName,Tiering,CPU_Pct,Physical_RAM,Consumed_GB,"
    "Active_GB,Active_Pct,TierRatioPct,Active_Avg_GB,NVMe_GB,Missing_Metrics,CPU_MHz,"
    "Memory_Unit,Source"
)
VM_HISTORY_HEADER = (
    "Cluster,RangeName,ClusterContext,Host,VMName,Provisioned_GB,Active_GB,Active_Pct,"
    "DRAM_Only,Pages_1GB,Pages_2MB,Missing_Metrics,Memory_Unit,Source"
)
MEMORY_UNIT = "GB"
MISSING_ORDER = ("CPU", "Active", "Consumed")
COLLECTION_FAILED = "Collection failed"
VCENTER_FULL_PROPERTIES = (
    "name",
    "runtime.connectionState",
    "summary.hardware.cpuMhz",
    "summary.hardware.numCpuCores",
    "hardware.memorySize",
    "hardware.memoryTieringType",
    "hardware.memoryTierInfo",
    "config.product.version",
)
VCENTER_LEGACY_PROPERTIES = tuple(
    item for item in VCENTER_FULL_PROPERTIES
    if item not in {"hardware.memoryTieringType", "hardware.memoryTierInfo"}
)
AGGREGATE_INSTANCE = ""
HISTORICAL_COUNTERS = ("cpu.usage.average", "mem.active.average", "mem.consumed.average")
MIN_HISTORICAL_LEVEL = 2
DEFERRED_SOURCES = (
    "linux-ssh", "windows-winrm", "kvm", "hyper-v", "ahv", "ovirt", "kubernetes", "telegraf",
)
SECRET_FRAGMENTS = (
    "password", "passwd", "secret", "token", "authorization", "cookie", "privatekey", "private_key",
)
