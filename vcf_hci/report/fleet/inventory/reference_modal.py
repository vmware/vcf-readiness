"""
SE Column Reference Guide modal HTML generator for Detailed Inventory panel.
"""
from __future__ import annotations

__all__ = [
    "_build_inventory_reference_modal_html",
]


def _build_inventory_reference_modal_html() -> str:
    """Build self-contained in-page modal dialog containing the Detailed Inventory Column Reference."""
    return """
<div id="invRefModal" class="inv-modal-backdrop" onclick="if(event.target===this)closeInvRefModal()">
  <div class="inv-modal-card" role="dialog" aria-modal="true" aria-labelledby="invRefModalTitle">
    <div class="inv-modal-header">
      <h3 id="invRefModalTitle">📖 Detailed Inventory Column Reference</h3>
      <button type="button" class="inv-modal-close" onclick="closeInvRefModal()" aria-label="Close modal">✕</button>
    </div>
    <div class="inv-modal-body">
      <h4>1. Hosts Tab (SE Decision Matrix)</h4>
      <p>Summarizes physical compute, storage qualification, network readiness, memory interleaving, and platform security for each host.</p>
      <table class="inv-ref-table">
        <thead><tr><th>Column</th><th>Description &amp; Logic</th><th>VCF 9.1 Readiness Criteria</th></tr></thead>
        <tbody>
          <tr><td><b>Host</b></td><td>Host system hostname and BMC IP address. Clicking any row navigates directly to that host's comprehensive single-host assessment report.</td><td>Identifies unique physical node.</td></tr>
          <tr><td><b>Model</b></td><td>Server hardware manufacturer (Dell, HPE, Supermicro, Cisco, Lenovo, Intel) and normalized chassis model name.</td><td>Hardware platform must be certified on VMware Compatibility Guide for vSphere 9.x.</td></tr>
          <tr><td><b>CPU</b></td><td>Processor model name, socket count, and VCF 9.1 architectural tier.<br>• <b>Supported (Green):</b> Intel Cascade Lake/Ice Lake/Sapphire Rapids/Emerald Rapids/Granite Rapids, AMD EPYC 7002/7003/8004/9004.<br>• <b>Supported (Override Required) (Yellow):</b> Intel Skylake-SP (supported for VCF 9.x per Broadcom KB 428874; installation or upgrade requires CPU support override).<br>• <b>Unsupported (Red):</b> Intel Haswell/Broadwell (v3/v4) or older architectures.</td><td>Supported CPU architecture required for VCF 9.1 cluster deployment.</td></tr>
          <tr><td><b>Host OS</b></td><td>Installed operating system or VMware ESXi hypervisor release version and vendor build number.<br>• <b>Supported (Standard):</b> Active supported release.<br>• <b>EOL (Red):</b> End of General Support reached (e.g. ESXi 7.0 reached EOL in April 2025; upgrade to vSphere 8.x/9.x required).<br>• <b>— Not Reported:</b> OS agent (Dell iSM or HPE AMS) not running.</td><td>Identifies operating system lifecycle and migration requirements for VCF 9.1 repurposing.</td></tr>
          <tr><td><b>ESA Disks</b></td><td>Direct-attached NVMe storage capacity bucket breakdown and self-contained storage qualification status (independent of network speed).<br>• <b>✓ Storage Qualified (Green):</b> &ge;2 direct-attached NVMe SSDs without RAID or VMD blockers (Software RAID controllers require BIOS bypass to AHCI/Non-RAID).<br>• <b>✗ Behind RAID (Red):</b> NVMe drives attached to HW RAID or Tri-Mode controller (direct PCIe pass-through required).<br>• <b>✗ VMD Enabled (Red):</b> Intel VMD enabled in BIOS (must be disabled for native NVMe pass-through).<br>• <b>▲ OSA (SAS/SATA) (Amber):</b> SAS/SATA drives detected without direct NVMe SSDs.<br>• <b>— Insufficient (Muted):</b> &lt;2 direct NVMe SSDs.</td><td>&ge;2 direct NVMe SSDs required for vSAN ESA storage tier.</td></tr>
          <tr><td><b>ESA Tier</b></td><td>Dedicated vSAN ESA ReadyNode profile qualification evaluating holistic hardware criteria (NVMe drive count &amp; capacity, RAM, CPU cores, and NIC speeds).<br>• <b>✓ ESA-L (Large) (Green):</b> &ge;4 Direct NVMe SSDs, &ge;512 GB RAM, &ge;48 CPU cores, &ge;25 GbE NIC. Meets high-performance cluster criteria.<br>• <b>✓ ESA-M (Medium) (Green):</b> &ge;2 Direct NVMe SSDs, &ge;256 GB RAM, &ge;32 CPU cores, &ge;25 GbE NIC. Meets standard enterprise cluster criteria.<br>• <b>✓ ESA-S (Small) (Green):</b> &ge;2 Direct NVMe SSDs, &ge;128 GB RAM, &ge;16 CPU cores, &ge;25 GbE NIC. Meets entry datacenter cluster criteria.<br>• <b>✓ ESA-XS (Edge) (Green):</b> &ge;2 Direct NVMe SSDs, &ge;64 GB RAM, &ge;16 CPU cores, &ge;10/25 GbE NIC. Suitable for ROBO / Edge deployments.<br>• <b>▲ Needs 25G NIC (Amber):</b> Meets ESA storage and compute criteria, but NIC is &lt;25 GbE (upgrade required).<br>• <b>✗ Blocked (Red):</b> Ineligible due to HW RAID, Tri-Mode, or Intel VMD.<br>• <b>— Ineligible (Muted):</b> Insufficient drives.</td><td>Holistic profile qualification matching VMware vSAN ESA ReadyNode specifications.</td></tr>
          <tr><td><b>NICs</b></td><td>Network adapter summary with selective down-port highlighting and 25 GbE baseline compliance. Active &ge;25 GbE links are highlighted in green (<code>2×25G↑</code>), while down ports are selectively highlighted in red (<code>2×25G↓</code>) without turning the entire cell red. Hover tooltips detail aggregate port count, active links, and ESA &ge;2x 25 GbE network readiness.</td><td>Minimum 25 GbE network interfaces required for vSAN ESA clusters.</td></tr>
          <tr><td><b>FC HBA</b></td><td>Optional column displayed when Fibre Channel Host Bus Adapters are detected in the fleet. Displays detected HBA model and port count.</td><td>Informational for external SAN / VMFS storage integration.</td></tr>
          <tr><td><b>RAM</b></td><td>Total installed system RAM in GB, populated DIMM slot count, and memory channel interleaving efficiency rating.</td><td>Memory must meet workload sizing and channel interleaving requirements.</td></tr>
          <tr><td><b>TPM</b></td><td>Trusted Platform Module presence and activation status.<br>• <b>✓ (Green):</b> TPM 2.0 enabled and active.<br>• <b>✗ (Red):</b> TPM absent, disabled, or legacy TPM 1.2.</td><td>TPM 2.0 required for ESXi 9.1 secure boot, host attestation, and vSphere Key Provider.</td></tr>
          <tr><td><b>BMC Sec</b></td><td>Out-of-band management security posture baseline compliance.<br>• <b>✓ Met (Green):</b> All evaluated security controls passed.<br>• <b>▲ Partial (Amber):</b> Security controls partially assessed (honesty rule: unknowns do not pass).<br>• <b>✗ Action Req (Red):</b> High-priority hardening failures detected (e.g. Telnet, default password, IPMI-over-LAN).</td><td>BMC security posture evaluation against VCF Security Configuration Guide (SCG) baseline.</td></tr>
          <tr><td><b>VMD</b></td><td>Intel Volume Management Device status.<br>• <b>✓ Off (Green):</b> VMD disabled (native pass-through enabled).<br>• <b>✗ On (Red):</b> VMD enabled (blocks native vSAN ESA NVMe driver).</td><td>Must be Disabled for direct-attached NVMe pass-through in vSAN ESA.</td></tr>
          <tr><td><b>GPU</b></td><td>Count and models of detected PCIe GPU accelerators.</td><td>Identifies hardware accelerators for VCF Private AI Foundation workloads.</td></tr>
        </tbody>
      </table>

      <h4>2. Drives Tab</h4>
      <p>Details every physical storage drive detected across all storage controllers.</p>
      <table class="inv-ref-table">
        <thead><tr><th>Column</th><th>Description &amp; Logic</th><th>VCF 9.1 / vSAN Significance</th></tr></thead>
        <tbody>
          <tr><td><b>Host</b></td><td>Host server hostname and BMC IP address.</td><td>Links drive to physical node.</td></tr>
          <tr><td><b>Controller</b></td><td>Storage controller model (e.g. Dell HBA355i, HPE Smart HBA, PERC H740P, Direct NVMe PCIe). Highlighted in red if controller is Dell PERC 7xx (HW RAID).</td><td>vSAN ESA requires direct PCIe / HBA passthrough; HW RAID controllers are ineligible.</td></tr>
          <tr><td><b>Model</b></td><td>Drive manufacturer part number and model with direct Broadcom Compatibility Guide (BCG) deep link.</td><td>Clicking opens certified device listing on Broadcom VCG.</td></tr>
          <tr><td><b>Media</b></td><td>Storage media technology: <code>NVMe SSD</code>, <code>SAS SSD</code>, <code>SATA SSD</code>, <code>HDD</code>.</td><td>vSAN ESA requires all-NVMe media; vSAN OSA supports SAS/SATA SSDs.</td></tr>
          <tr><td><b>Cap GB</b></td><td>Raw drive capacity in gigabytes (e.g. 1920 GB, 3840 GB, 7680 GB, 15360 GB).</td><td>Used for storage capacity sizing calculations.</td></tr>
          <tr><td><b>Protocol</b></td><td>Bus transport protocol: <code>NVMe</code>, <code>SAS</code>, <code>SATA</code>.</td><td>NVMe required for ESA.</td></tr>
          <tr><td><b>Category</b></td><td>Classification: <code>vSAN ESA/OSA NVMe</code>, <code>vSAN OSA Compatible (HBA)</code>, <code>Unsupported NVMe RAID</code>, <code>Unsupported NVMe Tri-Mode</code>.</td><td>Directly impacts vSAN storage qualification.</td></tr>
          <tr><td><b>Health</b></td><td>Hardware diagnostic health and S.M.A.R.T. operational state (<code>OK</code>, <code>Warning</code>, <code>Critical</code>, <code>Degraded</code>).</td><td>Failing or degraded drives must be replaced before deployment.</td></tr>
          <tr><td><b>Life%</b></td><td>Remaining silicon flash endurance percentage (wear gauge). Reported directly from BMC OEM storage telemetry and NVMe log pages.</td><td>Drives with &lt;20% remaining life trigger critical replacement warnings.</td></tr>
          <tr><td><b>Firmware</b></td><td>Installed drive firmware version compared against certified Broadcom HCL baselines.<br>• <b>✓ (Green):</b> Certified and current.<br>• <b>▲ (Amber):</b> Certified update available or outdated.</td><td>Drive firmware must match VMware certified HCL releases to prevent I/O lockups.</td></tr>
        </tbody>
      </table>

      <h4>3. NICs Tab</h4>
      <p>Details every physical network interface adapter port across the fleet.</p>
      <table class="inv-ref-table">
        <thead><tr><th>Column</th><th>Description &amp; Logic</th><th>VCF 9.1 / vSAN Significance</th></tr></thead>
        <tbody>
          <tr><td><b>Host</b></td><td>Host server hostname and BMC IP address.</td><td>Links port to physical node.</td></tr>
          <tr><td><b>Adapter</b></td><td>Network controller adapter model (e.g. Intel E810-XXVDA2, Broadcom BCM57414, Mellanox ConnectX-6 Dx) with BCG deep link.</td><td>Clicking opens certified controller entry on Broadcom VCG.</td></tr>
          <tr><td><b>Port</b></td><td>Physical network interface port identifier (e.g. <code>Port 1</code>, <code>NIC.Embedded.1-1-1</code>, <code>Slot 2 Port 1</code>).</td><td>Identifies physical uplink wiring.</td></tr>
          <tr><td><b>Speed</b></td><td>Current negotiated link speed or maximum rated bandwidth (e.g. <code>25 Gbps</code>, <code>100 Gbps</code>, <code>10 Gbps</code>).</td><td>&ge;25 Gbps required for vSAN ESA traffic; &ge;10 Gbps for management/vMotion.</td></tr>
          <tr><td><b>Link</b></td><td>Physical connection state (<code>✓ Up</code> in green or <code>✗ Down</code> in red).</td><td>All intended cluster uplinks must be connected and negotiated Up.</td></tr>
          <tr><td><b>MAC</b></td><td>Permanent hardware MAC address of the network interface port.<br>• <i>Note:</i> In obfuscated reports and exports, MAC addresses are deterministic locally-administered hashes with an IEEE <code>02:</code> prefix to protect customer datacenter topologies while preserving cross-port correlation.</td><td>Used for vSphere Distributed Switch (VDS) uplink mapping.</td></tr>
          <tr><td><b>Firmware</b></td><td>Installed network controller firmware version compared against Broadcom certified baselines.</td><td>Firmware and driver combination must be aligned with vSphere 9.1 certified versions.</td></tr>
        </tbody>
      </table>

      <h4>4. BIOS Settings Tab</h4>
      <p>Displays key platform settings affecting CPU execution performance, memory reliability, storage passthrough, and security.</p>
      <table class="inv-ref-table">
        <thead><tr><th>Column</th><th>Description &amp; Logic</th><th>VCF 9.1 Readiness Criteria</th></tr></thead>
        <tbody>
          <tr><td><b>Host</b></td><td>Host server hostname and BMC IP address.</td><td>Links BIOS configuration to physical node.</td></tr>
          <tr><td><b>Model</b></td><td>Server hardware manufacturer and chassis model.</td><td>Identifies OEM configuration template.</td></tr>
          <tr><td><b>BIOS Version</b></td><td>Installed system BIOS/UEFI firmware release version.</td><td>Must meet OEM minimum firmware release matrix for ESXi 9.1.</td></tr>
          <tr><td><b>Release Date</b></td><td>OEM release date of the installed BIOS build.</td><td>Identifies aging firmware builds requiring lifecycle updates.</td></tr>
          <tr><td><b>CPU Power Profile</b></td><td>Processor power management policy.<br>• <b>✓ Performance (Green):</b> Maximum Performance / Custom OS Control.<br>• <b>▲ Power Saving / Balanced (Amber/Red):</b> Energy Efficient or Dynamic saving modes.</td><td>ESXi and vSAN ESA require <b>Maximum Performance</b> profile in BIOS to prevent latency spikes and CPU throttling under heavy I/O.</td></tr>
          <tr><td><b>Memory RAS</b></td><td>Reliability, Availability, and Serviceability memory mode (<code>Optimized</code>, <code>Advanced ECC</code>, <code>Mirroring</code>, <code>Spare</code>).</td><td><code>Optimized</code> / <code>Advanced ECC</code> provides maximum capacity and channel throughput.</td></tr>
          <tr><td><b>Intel VMD</b></td><td>Intel Volume Management Device status.<br>• <b>✓ Disabled (Pass-thru) (Green):</b> Pass-through ready.<br>• <b>✗ Enabled (VMD) (Red):</b> VMD enabled.</td><td>Must be <b>Disabled</b> so ESXi directly controls NVMe PCIe lanes and telemetry.</td></tr>
          <tr><td><b>Boot Mode</b></td><td>Firmware boot architecture.<br>• <b>✓ UEFI (Green):</b> Modern UEFI firmware boot.<br>• <b>✗ Legacy BIOS (Red):</b> Legacy BIOS boot mode.</td><td><b>UEFI</b> boot mode is strictly required for VCF 9.1; Legacy BIOS is unsupported.</td></tr>
          <tr><td><b>Spectre / CVE Tier</b></td><td>Processor microcode security mitigation baseline covering Spectre, Meltdown, L1TF, MDS, and SRBDS.<br>• <b>✓ Tier 4 (Green):</b> Current certified microcode.<br>• <b>✗ Tier &lt;4 (Red):</b> Outdated microcode requiring BIOS update.</td><td>Tier 4 microcode ensures protection against speculative execution side-channels.</td></tr>
        </tbody>
      </table>

      <h4>5. Health Alarms Tab</h4>
      <p>Consolidates active faults, degraded components, and telemetry breaches from BMC subsystems.</p>
      <table class="inv-ref-table">
        <thead><tr><th>Column</th><th>Description &amp; Logic</th><th>Action Required</th></tr></thead>
        <tbody>
          <tr><td><b>Host</b></td><td>Host server hostname and BMC IP address.</td><td>Identifies faulted node.</td></tr>
          <tr><td><b>Severity</b></td><td>Alarm urgency level (<code>✗ Critical</code>, <code>▲ Warning</code>, <code>ℹ Info</code>, or <code>✓ Healthy</code>).</td><td>Critical alarms block commissioning until hardware remediation.</td></tr>
          <tr><td><b>Subsystem</b></td><td>Reporting hardware domain: <code>SEL Event Log</code>, <code>Drive SMART</code>, <code>Drive Wear</code>, <code>Drive Thermal</code>, <code>Power Supply</code>, <code>Thermal</code>, <code>Memory</code>, <code>Scan Status</code>.</td><td>Identifies responsible hardware subsystem.</td></tr>
          <tr><td><b>Health Alarm / Telemetry</b></td><td>Detailed fault message, sensor threshold violation, or event description (e.g. <code>Predictive Failure on Slot 3</code>, <code>Power supply non-redundant</code>, <code>Uncorrectable multi-bit ECC error count: 1</code>). Clickable to jump directly to the relevant host diagnostic panel.</td><td>Provides diagnostic details for field technician dispatch.</td></tr>
          <tr><td><b>Component / Target</b></td><td>Specific physical component identifier, drive bay slot, DIMM slot, sensor name, or clickable vendor event message code (e.g. Dell EEMS codes link directly to remedial instructions; hardware targets jump to host subsystem view).</td><td>Pinpoints physical hardware part needing service or replacement.</td></tr>
          <tr><td><b>Timestamp / Status</b></td><td>Event timestamp or active condition status (<code>Active Alarm</code>, <code>Active State</code>, <code>Normal</code>).</td><td>Distinguishes transient historical events from active continuous faults.</td></tr>
        </tbody>
      </table>

      <h4>6. Security Tab</h4>
      <p>Provides a comprehensive audit of out-of-band management controller hardening, host cryptographic security, and baseline compliance.</p>
      <table class="inv-ref-table">
        <thead><tr><th>Column</th><th>Description &amp; Logic</th><th>VCF 9.1 Hardening Guideline</th></tr></thead>
        <tbody>
          <tr><td><b>Host</b></td><td>Host server hostname and BMC IP address.</td><td>Links security audit to physical node.</td></tr>
          <tr><td><b>Model</b></td><td>Server hardware manufacturer and chassis model.</td><td>Identifies vendor security framework.</td></tr>
          <tr><td><b>TPM 2.0</b></td><td>Trusted Platform Module 2.0 presence and activation.<br>• <b>✓ (Green):</b> TPM 2.0 enabled and active.<br>• <b>✗ (Red):</b> TPM disabled, absent, or legacy TPM 1.2.</td><td><b>Required for VCF 9.1:</b> Provides cryptographic identity, secure boot verification, and vSphere Key Provider integration.</td></tr>
          <tr><td><b>Secure Boot</b></td><td>UEFI Secure Boot signature validation status.<br>• <b>✓ (Green):</b> Enabled and active.<br>• <b>✗ (Red):</b> Disabled.</td><td><b>Recommended:</b> Ensures only cryptographically signed ESXi hypervisor binaries, kernel drivers, and VIBs are executed at boot.</td></tr>
          <tr><td><b>BMC Model &amp; FW</b></td><td>Out-of-band management controller model (iDRAC, iLO, XCC, IMC) and firmware release version with certified baseline check.</td><td>Firmware updates protect against out-of-band management vulnerabilities (e.g. CVE-2023-38545).</td></tr>
          <tr><td><b>BMC License</b></td><td>Out-of-band management controller license tier (e.g. iDRAC Enterprise/Datacenter, HPE iLO Advanced, Perpetual).<br>• <b>✓ Active / Enterprise (Green):</b> Enterprise or Perpetual license active.<br>• <b>✗ Expired / Required (Red):</b> Management license expired or required features blocked.<br>• <b>— (Muted):</b> Standard or default license.</td><td>Enterprise license tier required for full out-of-band remote telemetry and virtual media deployment.</td></tr>
          <tr><td><b>CVE Coverage Tier</b></td><td>BIOS processor microcode security tier.<br>• <b>✓ Tier 4 (Green):</b> Full speculative execution microcode coverage.<br>• <b>✗ Tier &lt;4 (Red):</b> Missing recent hardware microcode patches.</td><td>Update system BIOS to current release to protect VM-to-VM and VM-to-Hypervisor boundaries.</td></tr>
          <tr><td><b>HT</b></td><td>Intel Hyper-Threading / AMD SMT processor logical core status (<code>Enabled</code> or <code>Disabled</code>).</td><td>Displayed as informational plain text. Standard VCF deployments operate with Hyperthreading <b>Enabled</b> for maximum compute density.</td></tr>
          <tr><td><b>NTP / Time Drift</b></td><td>BMC Network Time Protocol synchronization and clock skew detection.<br>• <b>✓ In Sync (Green):</b> NTP active and BMC clock is synchronized within 300s (5 min) threshold.<br>• <b>▲ No Servers (Amber):</b> NTP protocol enabled but no NTP servers configured.<br>• <b>✗ Drift (Red):</b> Clock skew &gt;300s detected against assessment workstation.<br>• <b>✗ Disabled (Red):</b> NTP disabled on BMC.</td><td><b>Critical for VCF Operations:</b> Consistent time across all BMCs and ESXi hosts is mandatory to prevent TLS certificate validation failures, SSO token expiration errors, and log correlation skew.</td></tr>
          <tr><td><b>DNS</b></td><td>BMC Domain Name System server configuration.<br>• <b>✓ Configured (Green):</b> DNS name servers configured on BMC or forward/reverse DNS resolves.<br>• <b>▲ No Servers (Amber):</b> DNS enabled without configured servers.<br>• <b>✗ Not Configured (Red):</b> No DNS servers configured.</td><td>BMCs should have reachable DNS servers configured for forward and reverse hostname resolution.</td></tr>
          <tr><td><b>BMC Hardening</b></td><td>Comprehensive out-of-band management security posture rollup and prioritized issue badges:<br>• <b>Posture Rollup:</b> <code>✓ Baseline Met</code> (Green), <code>▲ Partial (XU)</code> (Amber), or <code>✗ Action Req (XF)</code> (Red).<br>• <b>Critical Issues (Red):</b> <code>✗ Telnet</code> (unencrypted remote shell), <code>✗ Default Pwd</code> (unrotated root password), <code>✗ TLS &lt; 1.2</code> (legacy cryptographic protocol).<br>• <b>High-Priority Concerns (Amber):</b> <code>▲ HTTP</code> (plaintext web management), <code>▲ IPMI LAN On</code> (unencrypted IPMI-over-LAN), <code>▲ No Lockout</code> (brute-force vulnerability), <code>▲ Host Pass-Through</code> (boundary escape risk), <code>▲ Weak Ciphers</code> (ciphers &lt;256-bit or weak algorithms), <code>▲ No Syslog</code> (missing remote audit logging), <code>▲ USB Mgmt</code> (unrestricted USB provisioning).<br>• <b>Baseline Tokens:</b> <code>TLS 1.2+</code>, <code>✓ Pwd Changed</code>, <code>✓ IPMI Disabled</code>, <code>✓ Hardened</code>.</td><td>Follow VCF Security Configuration Guide (SCG) and OEM hardening guides (Dell iDRAC, HPE iLO) to lock down management interfaces.</td></tr>
        </tbody>
      </table>

      <h4>7. Excel &amp; Obfuscated Export Reference</h4>
      <p>The Detailed Inventory toolbar includes one-click export actions:</p>
      <ul>
        <li><b>Export Excel (<code>inventory.xlsx</code>):</b> Multi-sheet spreadsheet containing SE Decision Matrix, CPUs, Memory, Storage, Networking, GPUs, Firmware Inventory, Fibre Channel, BIOS Settings, Health Alarms, Security, and Security Audit.</li>
        <li><b>Export Obfuscated + Key (<code>inventory_obfuscated.zip</code>):</b> Cryptographically sanitized version of the Excel spreadsheet and JSON payloads with a private obfuscation key mapping tokens to original customer values.</li>
        <li><b>Export Excel (Obfuscated) (<code>inventory_obfuscated.xlsx</code>):</b> In pre-obfuscated fleet reports, downloads the sanitized spreadsheet directly without requiring key generation.</li>
      </ul>
    </div>
    <div class="inv-modal-footer">
      <button type="button" class="inv-btn" onclick="closeInvRefModal()">Close</button>
    </div>
  </div>
</div>
"""
