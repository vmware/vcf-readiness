"""Pure drive SMART normalization over already-acquired Metrics/OEM maps."""
from typing import Any, Optional, Union

from vcf_hci.collector.pci_utils import normalize_pcie_errors


def _first_present(*values):
    """Select a known value without discarding zero counters or false flags."""
    return next((value for value in values if value is not None), None)


def sanitize_endurance_pct(val: Any) -> Optional[Union[int, float]]:
    """Sanitize SSD endurance / media life percentage.

    Returns None if value is null, 255 (standard 1-byte IPMI/Redfish unavailable sentinel),
    less than 0, or greater than 100.
    """
    if val is None:
        return None
    try:
        f_val = float(val)
    except (ValueError, TypeError):
        return None
    if f_val == 255.0 or f_val < 0.0 or f_val > 100.0:
        return None
    return int(f_val) if f_val.is_integer() else round(f_val, 2)


def parse_drive_telemetry(drive_json: dict, metrics: dict, oem_metrics: dict, dell_oem: dict, hpe_oem: dict, lnv_oem: dict, smc_oem: dict, cisco_oem: dict, is_boot: bool) -> dict:
    """Normalize supplied SMART evidence; zero/false values and raw spare remain distinct."""
    # SMART Telemetry (20 Metrics)
    temp_c = _first_present(
        drive_json.get("TemperatureCelsius"),
        drive_json.get("CurrentTemperatureCelsius"),
        metrics.get("TemperatureCelsius"),
        oem_metrics.get("temperature_c"),
        dell_oem.get("TemperatureCelsius"),
        hpe_oem.get("CurrentTemperatureCelsius"),
        lnv_oem.get("Temperature"),
        smc_oem.get("TemperatureCelsius"),
        smc_oem.get("Temperature"),
    )
    if temp_c is not None:
        try:
            temp_c = float(temp_c)
        except (ValueError, TypeError):
            temp_c = None
    poh = _first_present(
        drive_json.get("PowerOnHours"),
        metrics.get("PowerOnHours"),
        oem_metrics.get("power_on_hours"),
        dell_oem.get("PowerOnHours"),
        dell_oem.get("OperationHours"),
        dell_oem.get("PowerOnHoursCount"),
        hpe_oem.get("PowerOnHours"),
        lnv_oem.get("PowerOnHours"),
        lnv_oem.get("OperationHours"),
        smc_oem.get("PowerOnHours"),
        smc_oem.get("OperationHours"),
        cisco_oem.get("PowerOnHours"),
        cisco_oem.get("OperationHours"),
    )
    critical_warnings = _first_present(
        oem_metrics.get("critical_warnings"),
        drive_json.get("CriticalWarnings"),
        drive_json.get("CriticalWarningsCount"),
        metrics.get("CriticalWarnings"),
        metrics.get("CriticalWarningsCount"),
    )

    failure_predicted = bool(
        drive_json.get("FailurePredicted")
        or (drive_json.get("FailurePredicted") is not False and (
            (drive_json.get("Status") or {}).get("HealthRollup") == "Critical"
            or (drive_json.get("Status") or {}).get("Health") == "Critical"
        ))
        or oem_metrics.get("predictive_failure")
        or dell_oem.get("PredictiveFailure")
        or lnv_oem.get("FailurePredicted")
        or (isinstance(critical_warnings, (int, float)) and critical_warnings > 0)
    )

    unsafe_shutdowns = _first_present(
        drive_json.get("UnsafeShutdowns"),
        metrics.get("UnsafeShutdowns"),
        oem_metrics.get("unsafe_shutdowns"),
        dell_oem.get("UnsafeShutdowns"),
        dell_oem.get("AbruptPowerOffCount"),
        hpe_oem.get("UnsafeShutdowns"),
        lnv_oem.get("UnsafeShutdowns"),
        cisco_oem.get("UnsafeShutdowns"),
    )
    media_errors = _first_present(
        drive_json.get("MediaAndDataIntegrityErrors"),
        drive_json.get("MediaErrors"),
        metrics.get("MediaAndDataIntegrityErrors"),
        metrics.get("LifeTimeErrorCount"),
        oem_metrics.get("media_errors"),
        dell_oem.get("MediaAndDataIntegrityErrors"),
        dell_oem.get("MediaErrorCount"),
        hpe_oem.get("UncorrectableReadErrors"),
        hpe_oem.get("MediaErrors"),
        lnv_oem.get("DriveErrorCount"),
        cisco_oem.get("MediaErrors"),
    )
    thermal_throttled_raw = _first_present(
        drive_json.get("ThermalThrottling"),
        metrics.get("ThermalThrottling"),
        dell_oem.get("ThermalThrottled"),
        hpe_oem.get("ThermalThrottled"),
    )
    thermal_throttled = None
    if thermal_throttled_raw is not None:
        if isinstance(thermal_throttled_raw, bool):
            thermal_throttled = thermal_throttled_raw
        elif isinstance(thermal_throttled_raw, (int, float)):
            thermal_throttled = thermal_throttled_raw > 0
        elif isinstance(thermal_throttled_raw, str):
            thermal_throttled = thermal_throttled_raw.lower() not in ("none", "false", "0", "unthrottled", "ok")

    plp_cap = (
        drive_json.get("CapacitorHealth") or drive_json.get("PowerLossProtectionStatus")
        or metrics.get("CapacitorHealth")
        or dell_oem.get("PowerLossProtectionStatus") or dell_oem.get("CapacitorHealth")
        or hpe_oem.get("PowerLossProtection")
    )

    tbw_val = oem_metrics.get("tbw_written")
    if tbw_val is None:
        raw_tbw = _first_present(
            drive_json.get("DataUnitsWritten"),
            drive_json.get("BytesWritten"),
            drive_json.get("LifetimeWritesBytes"),
            metrics.get("DataUnitsWritten"),
            metrics.get("BytesWritten"),
            dell_oem.get("DataUnitsWritten"),
            hpe_oem.get("TotalBytesWritten"),
        )
        if isinstance(raw_tbw, (int, float)) and raw_tbw >= 0:
            if raw_tbw > 1_000_000_000_000:
                tbw_val = round(raw_tbw / (1024 ** 4), 2)
            elif raw_tbw > 100_000_000:
                tbw_val = round((raw_tbw * 512 * 1000) / (1024 ** 4), 2)
            else:
                tbw_val = round(raw_tbw, 2)

    tbr_val = oem_metrics.get("tbr_read")
    if tbr_val is None:
        raw_tbr = _first_present(
            drive_json.get("DataUnitsRead"),
            drive_json.get("BytesRead"),
            drive_json.get("LifetimeReadsBytes"),
            metrics.get("DataUnitsRead"),
            metrics.get("BytesRead"),
            dell_oem.get("DataUnitsRead"),
            hpe_oem.get("TotalBytesRead"),
        )
        if isinstance(raw_tbr, (int, float)) and raw_tbr >= 0:
            if raw_tbr > 1_000_000_000_000:
                tbr_val = round(raw_tbr / (1024 ** 4), 2)
            elif raw_tbr > 100_000_000:
                tbr_val = round((raw_tbr * 512 * 1000) / (1024 ** 4), 2)
            else:
                tbr_val = round(raw_tbr, 2)

    power_cycles = _first_present(
        oem_metrics.get("power_cycles"),
        drive_json.get("PowerCycleCount"),
        drive_json.get("PowerCycles"),
        metrics.get("PowerCycles"),
        metrics.get("PowerCycleCount"),
        dell_oem.get("PowerCycleCount"),
    )
    controller_busy_time = _first_present(
        oem_metrics.get("controller_busy_time"),
        drive_json.get("ControllerBusyTimeMinutes"),
        drive_json.get("ControllerBusyTime"),
        metrics.get("ControllerBusyTime"),
        metrics.get("ControllerBusyTimeMinutes"),
    )
    controller_duty_cycle_pct = None
    if isinstance(controller_busy_time, (int, float)) and isinstance(poh, (int, float)) and poh > 0:
        controller_duty_cycle_pct = round(min(100.0, max(0.0, (float(controller_busy_time) / (float(poh) * 60.0)) * 100.0)), 1)

    host_read_commands = _first_present(
        oem_metrics.get("host_read_commands"),
        drive_json.get("HostReadCommandsCount"),
        drive_json.get("HostReadCommands"),
        metrics.get("HostReadCommands"),
    )
    host_write_commands = _first_present(
        oem_metrics.get("host_write_commands"),
        drive_json.get("HostWriteCommandsCount"),
        drive_json.get("HostWriteCommands"),
        metrics.get("HostWriteCommands"),
    )
    avail_spare_thresh = _first_present(
        oem_metrics.get("available_spare_threshold"),
        drive_json.get("AvailableSpareThresholdPercent"),
        drive_json.get("AvailableSpareThreshold"),
        metrics.get("AvailableSpareThresholdPercent"),
        metrics.get("AvailableSpareThreshold"),
    )
    error_log_entries = _first_present(
        oem_metrics.get("error_log_entries"),
        drive_json.get("ErrorInfoCount"),
        drive_json.get("NumOfErrorInfoLogEntries"),
        metrics.get("NumOfErrorInfoLogEntries"),
    )
    max_temp_c = _first_present(
        oem_metrics.get("max_temp_c"),
        drive_json.get("MaximumTemperatureCelsius"),
        hpe_oem.get("MaximumTemperatureCelsius"),
    )

    pcie_raw = None
    for cand in (
        drive_json.get("PCIeErrors"),
        metrics.get("PCIeErrors"),
        dell_oem.get("PCIeErrors"),
        oem_metrics.get("pcie_errors"),
        drive_json.get("PCIeCorrectableErrorCount"),
        metrics.get("PCIeCorrectableErrors"),
        metrics.get("PCIeCorrectableErrorCount"),
        oem_metrics.get("pcie_bus_errors"),
    ):
        if cand is not None and cand != {}:
            pcie_raw = cand
            if isinstance(cand, dict):
                break

    pcie_errors_dict = normalize_pcie_errors(pcie_raw)
    pcie_errs = pcie_errors_dict.get("total_errors") if pcie_errors_dict else (
        int(pcie_raw) if isinstance(pcie_raw, (int, float)) else None
    )
    waf_val = _first_present(
        drive_json.get("WriteAmplificationFactor"),
        metrics.get("WriteAmplificationFactor"),
    )
    bad_nand = _first_present(
        drive_json.get("BadUserNANDBlocks"),
        drive_json.get("BadNANDBlockCount"),
        drive_json.get("RetiredBlockCount"),
        metrics.get("BadNANDBlockCount"),
        dell_oem.get("BadNANDBlockCount"),
        dell_oem.get("RetiredBlockCount"),
    )
    uncorr_reads = _first_present(
        drive_json.get("UncorrectableReadErrors"),
        metrics.get("UncorrectableReadErrors"),
        hpe_oem.get("UncorrectableReadErrors"),
        oem_metrics.get("uncorrectable_read_errors"),
    )
    e2e_crc = _first_present(
        drive_json.get("EndToEndCorrectionCounts"),
        drive_json.get("EndToEndErrors"),
        metrics.get("EndToEndErrors"),
    )
    avail_spare = _first_present(
        drive_json.get("AvailableSparePercent"),
        drive_json.get("PercentFreeBlocks"),
        metrics.get("AvailableSparePercent"),
        dell_oem.get("AvailableSparePercent"),
        oem_metrics.get("available_spare_pct"),
    )
    avail_spare_raw = avail_spare
    if not isinstance(avail_spare, (int, float)) or isinstance(avail_spare, bool) or not 0 <= avail_spare <= 100:
        avail_spare = None
    plp_starts = _first_present(
        drive_json.get("PLPStartCount"),
        metrics.get("PLPStartCount"),
    )
    sec_status = str(
        drive_json.get("SecurityStatus") or drive_json.get("EncryptionStatus")
        or oem_metrics.get("security_status")
        or dell_oem.get("SecurityStatus") or dell_oem.get("SecurityState") or dell_oem.get("EncryptionStatus")
        or hpe_oem.get("EncrypStatus") or hpe_oem.get("EncryptionStatus")
        or "N/A"
    ).strip()
    usage_role = str(
        drive_json.get("UsageAttribute")
        or dell_oem.get("UsageAttribute")
        or hpe_oem.get("CarrierStatus")
        or ("Boot Drive" if is_boot else "Data Drive")
    ).strip()
    pending_fw = str(
        drive_json.get("PendingFirmwareVersion")
        or dell_oem.get("ComponentStagingState")
        or hpe_oem.get("PendingFirmwareVersion")
        or "N/A"
    ).strip()

    crypto_erase_capable = bool(
        oem_metrics.get("crypto_erase_capable")
        or drive_json.get("CryptographicEraseCapable") == "Capable"
        or "crypto" in str(drive_json.get("SystemEraseCapability", "")).lower()
    )
    erase_capability = str(
        oem_metrics.get("erase_capability")
        or drive_json.get("SystemEraseCapability")
        or drive_json.get("CryptographicEraseCapable")
        or "N/A"
    ).strip()
    error_description = str(
        oem_metrics.get("error_description")
        or drive_json.get("ErrorDescription")
        or ""
    ).strip()
    if error_description.lower() in ("none", "null", "n/a"):
        error_description = ""

    return {'temperature_c': temp_c, 'power_on_hours': poh, 'failure_predicted': failure_predicted, 'unsafe_shutdowns': unsafe_shutdowns, 'media_errors': media_errors, 'thermal_throttled': thermal_throttled, 'plp_capacitor_health': plp_cap, 'tbw_written': tbw_val, 'tbr_read': tbr_val, 'critical_warnings': critical_warnings, 'power_cycles': power_cycles, 'controller_busy_time': controller_busy_time, 'controller_duty_cycle_pct': controller_duty_cycle_pct, 'host_read_commands': host_read_commands, 'host_write_commands': host_write_commands, 'available_spare_threshold': avail_spare_thresh, 'error_log_entries': error_log_entries, 'max_temperature_c': max_temp_c, 'pcie_bus_errors': pcie_errs, 'pcie_errors': pcie_errors_dict, 'write_amplification': waf_val, 'bad_nand_blocks': bad_nand, 'uncorrectable_read_errors': uncorr_reads, 'end_to_end_crc_errors': e2e_crc, 'available_spare_pct': avail_spare, 'available_spare_pct_raw': avail_spare_raw, 'plp_start_count': plp_starts, 'security_status': sec_status, 'usage_role': usage_role, 'pending_firmware': pending_fw, 'crypto_erase_capable': crypto_erase_capable, 'erase_capability': erase_capability, 'error_description': error_description}
