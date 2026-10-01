# VMware Cloud Foundation 9.1.1 Security Configuration & Hardening Guide: BMC Hardening Guidance Extension

**Document Status:** Proposed SCG 9.1.1 Technical Addendum  
**Scope:** Physical Server Baseboard Management Controllers (BMCs) — Dell iDRAC9, HPE iLO 5/6, Lenovo XCC/XCC2/XCC3, and Cisco Standalone CIMC  
**Audit Standard:** DMTF Redfish Normative Schemas (DSP0266, DSP2059)  
**Regulatory Baseline:** NIST SP 800-53 Rev. 5, NIST SP 800-193, Secure Controls Framework (SCF 2026.1.1), PCI DSS v4.0.1  
**VMware Reference Architecture:** VMware Cloud Foundation 9.1 / 9.1.1, VMware Compatibility Guide (VCG)  

---

## 1. Executive Summary & Policy Framework

### 1.1 Purpose and VCF 9.1.1 Scope
The VMware Cloud Foundation (VCF) Security Configuration & Hardening Guide (SCG) defines baseline security requirements for virtualized and private cloud infrastructure. In VCF 9.1 and 9.1.1, server hardware virtualization relies fundamentally on the integrity of the underlying bare-metal compute nodes. 

Physical server Baseboard Management Controllers (BMCs)—such as Dell Integrated Dell Remote Access Controller (iDRAC), Hewlett Packard Enterprise Integrated Lights-Out (HPE iLO), Lenovo XClarity Controller (XCC), and Cisco Integrated Management Controller (CIMC)—operate as autonomous out-of-band computers inside the server chassis. They run independent microkernels (commonly embedded Linux), possess dedicated networking capabilities, and hold unrestricted hardware-level bus access (PCIe, I2C/SMBus, LPC, SPI) directly to system CPUs, persistent system firmware, physical memory, and storage controllers.

This addendum extends the VCF SCG with **OEM-neutral, machine-auditable guidance** for physical BMC hardening.

```
+-------------------------------------------------------------------------+
|                  VCF 9.1.1 Tier-0 Architecture Layers                   |
+-------------------------------------------------------------------------+
|  Layer 3: Workload & Management Plane (vCenter, SDDC Mgr, NSX, VMs)     |
+-------------------------------------------------------------------------+
|  Layer 2: Virtualization Hypervisor (ESXi 9.1 Kernel, VMkernel Drivers) |
+-------------------------------------------------------------------------+
|  Layer 1: Platform & Device Firmware (UEFI BIOS, Host TPM 2.0, OptionROM)|
+-------------------------------------------------------------------------+
|  Layer 0: Out-of-Band Hardware Controller (BMC / iDRAC / iLO / XCC)     |
|   * Holds unrestricted direct-bus access to CPU registers and memory   |
|   * Independent power domain, active even when the ESXi host is powered off |
|   * Controls server boot order, firmware flashing, and virtual media    |
+-------------------------------------------------------------------------+
```

---

### 1.2 Standards Framing: Should Guidance Be Limited Strictly to NIST?

When defining an OEM-neutral hardening standard for enterprise cloud infrastructure, the question arises: **Should guidance be strictly limited to NIST guidance (e.g., NIST SP 800-53 Rev. 5 and NIST SP 800-193)?**

#### Analysis
1. **The Strength of NIST Guidance:**
   - **Normative Authority:** NIST Special Publications (SP 800-53r5, SP 800-193, SP 800-131Ar2, and SP 800-147B) represent the global benchmark for security controls across government, financial, and enterprise environments.
   - **Vendor Neutrality:** NIST controls intentionally avoid vendor-specific terms (such as Dell RACADM commands, HPE RIBCL, or Cisco CIMC CLI syntax).
   - **Catalog Alignment:** Upstream SCG structures already incorporate NIST SP 800-53r5 identifiers alongside the Secure Controls Framework (SCF).

2. **The Operational Limitation of NIST Guidance Alone:**
   - NIST documents define **what** security objective must be met (e.g., *SC-08: Protect information in transit from unauthorized interception* or *CM-07: Disable unnecessary functions, ports, protocols, and services*), but they do **not** prescribe **how** an automated system or security engineer can inspect or verify compliance across multi-vendor fleets.
   - NIST guidance has no semantic awareness of virtualization hypervisors, vSphere host attestation, vSAN storage architectures, or DMTF REST schema implementations.

3. **Recommended Tripartite Policy:**
   To establish a defensible, vendor-neutral baseline that is immediately auditable, the VCF 9.1.1 SCG establishes a three-part model:
   - **Normative Anchor (Regulatory Intent):** Mapped directly to **NIST SP 800-53 Rev. 5** control identifiers (AC, CM, IA, SC, SI families) and **NIST SP 800-193** (Platform Firmware Resiliency).
   - **Machine-Auditable Query Mechanics (Standard Redfish):** Grounded strictly in **DMTF Redfish Standard Schemas (DSP0266, DSP2059)** without proprietary OEM extensions (`DellAttributes` or `HpeSecurityService`). This ensures identical REST queries evaluate Dell, HPE, Lenovo, Supermicro, and Cisco servers.
   - **Platform Context (VMware Architecture & VCG):** Anchored to **VMware Cloud Foundation 9.1.1 architecture** and the **VMware Compatibility Guide (VCG)**, addressing hypervisor prerequisites (UEFI Secure Boot, vSAN ESA controller constraints, vSphere Trust Authority, and TPM 2.0 measured boot).

---

## 2. Threat Modeling & Why BMC Hardening is Critical to VCF

### 2.1 The BMC as Tier-0 Administrative Infrastructure
In an enterprise cloud, infrastructure components are classified into trust tiers. Tier 0 comprises identities, services, and hardware whose compromise grants unconditional control over all subordinate assets.

A Baseboard Management Controller is a quintessential **Tier-0 asset**:
- **Bypassing Hypervisor Isolation:** An adversary who achieves administrative privileges on a BMC can use remote console (KVM/IP), virtual media redirection, or DMA-capable diagnostic interfaces to manipulate ESXi host execution, bypass vSphere authentication, and extract sensitive workload memory without leaving telemetry inside ESXi syslog.
- **Persistent Out-of-Band Rootkits:** Because BMC firmware runs independently of ESXi, malicious code implanted in BMC SPI flash survives host reboots, OS reinstalls, and hypervisor image reprovisioning.
- **Disrupting High Availability & Storage Fabrics:** Through Redfish or IPMI power commands (`ResetType: ForceOff`), an attacker can cause abrupt cluster-wide host outages, disrupting vSphere High Availability (HA) and forcing split-brain or data corruption states in vSAN clusters.

### 2.2 Attack Vectors Addressed in this Baseline

```
+---------------------+      Adversary Vector 1:
|   Production VLAN   |      Plaintext Credential Sniffing
| (Workload Traffic)  | <--- (Unencrypted HTTP/80 or Telnet/23)
+---------------------+
           |
           x [PROHIBITED: Virtual NIC / Host-to-BMC Bridge]
           |
+---------------------+      Adversary Vector 2:
|   Dedicated OOB     |      IPMI-over-LAN Cipher-0 Auth Bypass
|   Management VLAN   | <--- (CVE-2013-4786 / RAKP Hash Disclosure)
+---------------------+
           |
    +--------------+
    | BMC Hardware | ------> Adversary Vector 3:
    |  (OOB SoC)   |         Malicious Option ROM / Boot Tampering
    +--------------+         (Mitigated by UEFI Secure Boot + VCG Baseline)
           |
    +--------------+
    | ESXi 9.1 Host|
    | (Hypervisor) |
    +--------------+
```

1. **Cleartext Transport Interception (HTTP / Telnet / Unencrypted SNMP):**
   - *Risk:* BMC administrators and automated orchestrators (SDDC Manager) transmit administrative credentials and session tokens across the network. Cleartext protocols expose these secrets to network sniffers.
   - *Mitigation:* Require HTTPS-only operation (or mandatory port 80 to 443 redirection) with TLS 1.2+ minimum, eliminate Telnet entirely, and mandate SNMPv3 AuthPriv.

2. **IPMI-over-LAN Vulnerabilities (Cipher 0 & Hash Disclosure):**
   - *Risk:* The IPMI 2.0 protocol specification suffers from structural cryptographic deficiencies. IPMI Cipher 0 allows complete authentication bypass, while the RAKP (Remote Authenticated Key Exchange Protocol) authentication handshake forces the BMC to return HMAC hashes of user passwords before authentication finishes, enabling offline dictionary attacks (CVE-2013-4786).
   - *Mitigation:* Permanently disable IPMI-over-LAN across all management controllers in favor of standard Redfish HTTPS APIs.

3. **Untrusted Factory Certificates & MitM Attacks:**
   - *Risk:* Factory self-signed certificates force orchestrators and administrators to disable TLS certificate verification (`ssl.CERT_NONE` or `--insecure`), exposing all management sessions to adversary-in-the-middle interception.
   - *Mitigation:* Enroll unique enterprise CA-signed X.509 certificates with Subject Alternative Names (SAN) matching controller FQDNs and IPs.

4. **Brute-Force & Credential Stuffing Attacks:**
   - *Risk:* Publicly known default BMC credentials (e.g., `root/calvin`, `admin/admin`) or unthrottled authentication endpoints allow attackers to brute-force accounts without lockout penalties.
   - *Mitigation:* Enforce account lockout thresholds (1–5 attempts), minimum password length (>= 8 characters, recommended >= 14), and unique non-default administrative credentials.

---

## 3. Relationship to VMware Cloud Foundation 9.1 & VCG Requirements

### 3.1 VMware Compatibility Guide (VCG) Hardware Requirements
The VMware Compatibility Guide (VCG) sets mandatory hardware certification criteria for systems supporting ESXi 8.0, 9.0, and 9.1:
- **Mandatory UEFI Boot Mode:** Legacy BIOS boot is deprecated and unsupported for VCF 9.x host commissioning. Certified servers must support UEFI firmware and run in native UEFI mode.
- **Mandatory TPM 2.0 Support:** Modern server certification requires a discrete Trusted Platform Module (TPM 2.0) with a TIS/FIFO interface and SHA-256 hash banks.
- **vSAN Express Storage Architecture (vSAN ESA):** VCG vSAN ESA certification requires direct-attached NVMe storage without intermediate RAID abstractions. BMC configuration must not introduce non-standard PCIe RAID encapsulation over NVMe pass-through lanes.

### 3.2 vSphere Trust Authority (vTA) & Attestation
VCF security architecture relies on cryptographic hardware attestation:
- **Measured Boot (NIST SP 800-193):** During power-on, the server Root of Trust for Measurement (RTM) measures initial boot blocks into TPM Platform Configuration Registers (PCRs).
- **UEFI Secure Boot:** Verifies the cryptographic digital signatures of the UEFI bootloader, VMware VMKernel, and all VMware Installation Bundles (VIBs).
- **Attestation Linkage:** If Secure Boot is disabled in BMC/UEFI firmware, TPM PCR 7 is not populated with the signature trust chain, causing vCenter Server and vSphere Trust Authority (vTA) remote attestation to fail. This blocks the host from receiving workload encryption keys from Key Management Interoperability Protocol (KMIP) providers.

### 3.3 Host-to-BMC Network Isolation (`Net.BMCNetworkEnable`)
- VCF hardening mandates strict separation between the data plane (workloads/VMs) and the out-of-band management plane.
- Many modern BMCs support internal USB-Ethernet or PCIe virtual NIC bridging (e.g., Dell iDRAC OS-to-iDRAC Pass-Through, HPE iLO Virtual NIC).
- SCG control `esx-9.hardware-virtual-nic` mandates setting ESXi advanced system setting `Net.BMCNetworkEnable = 0` unless specifically required by an authorized vendor CIM provider. Disabling this path ensures that a compromised virtual machine cannot jump directly onto the out-of-band BMC management network.

---

## 4. VCF 9.1.1 SCG BMC Baseline Controls Catalog

This section details the 8 core controls comprising the VCF 9.1.1 BMC hardening baseline: 3 new transport/cryptography controls, 4 refined management controls, and 1 refined hardware boot control.

```
+--------------------------------------------------------------------------------------------------------------------------------------------------+
|                                                      VCF 9.1.1 BMC Security Control Map                                                         |
+------------------------------------------+-----------------------+---------------------+-------------------+-------------------------------------+
| SCG Control Identifier                   | NIST 800-53r5 Mapping | SCF 2026.1.1 ID     | Redfish Endpoint  | Target Value                        |
+------------------------------------------+-----------------------+---------------------+-------------------+-------------------------------------+
| esx-9.hardware-management-tls            | SC-08, SC-13          | CRY-03, NET-06.4    | NetworkProtocol   | HTTPS=true, HTTP=false (or redirect)|
| esx-9.hardware-management-certificates   | IA-05(02), SC-17      | CRY-03, IAC-10.2    | CertificateService| Valid CA-issued X.509, matching SAN |
| esx-9.hardware-management-ssh-cryptography| CM-07, SC-13         | CFG-03, CRY-03      | NetworkProtocol   | SSH=false (or weak ciphers disabled)|
| esx-9.hardware-management-security       | AC-12, CM-07, SC-10   | CFG-03, IAC-10.8    | NetworkProtocol   | IPMI=false, Telnet=false, SNMPv3    |
| esx-9.hardware-management-authentication | AC-04(21), AC-07      | NET-06.4, IAC-16.2  | AccountService    | Lockout: 1-5, MinPassLength >= 8    |
| esx-9.hardware-management-time           | AU-08, SC-45(01)      | MON-07.1, SEA-20    | NetworkProtocol   | NTP=true, >=3 servers configured    |
| esx-9.hardware-management-log-forwarding | AU-06(04), SI-04      | MON-02, MON-02.2    | LogServices       | Remote Syslog active via TLS        |
| esx-9.hardware-secureboot                | SI-07(09), SI-07(10)  | END-06.5, END-06.6  | SecureBoot        | SecureBootEnable=true, Current=true |
+------------------------------------------+-----------------------+---------------------+-------------------+-------------------------------------+
```

---

### Control 1: esx-9.hardware-management-tls
- **Title:** Harden TLS on hardware management controllers.
- **NIST SP 800-53r5:** `SC-08, SC-08(01), SC-13`
- **SCF 2026.1.1:** `CRY-03, IAC-10.2, NET-06.4`
- **PCI DSS v4.0.1:** `2.2.7, 4.2.1`
- **Implementation Priority:** `P0`
- **Installation Default:** Vendor and firmware dependent.
- **Baseline Suggested Value:** HTTPS enabled; plaintext HTTP disabled or permanently redirected to HTTPS; TLS 1.2 or later enforced; weak protocol and cipher profiles disabled.
- **What is Auditable:**
  - Standard DMTF URI: `GET /redfish/v1/Managers/{id}/NetworkProtocol`
  - Property: `.HTTP.ProtocolEnabled` (must be `false` or verified redirect), `.HTTPS.ProtocolEnabled` (must be `true`).
  - Pass Criteria: Plaintext HTTP is disabled while HTTPS is enabled.
  - Fail Criteria: HTTPS disabled, or plaintext HTTP enabled without automatic redirection.
- **Functional Impact:** Older monitoring appliances or custom scripts that do not negotiate TLS 1.2+ will fail to connect. Scripts relying on port 80 must be updated to target HTTPS (port 443).

---

### Control 2: esx-9.hardware-management-certificates
- **Title:** Use trusted certificates for hardware management controller communications.
- **NIST SP 800-53r5:** `IA-05(02), SC-08, SC-17`
- **SCF 2026.1.1:** `CRY-03, IAC-10.2`
- **PCI DSS v4.0.1:** `2.2.7, 4.2.1`
- **Implementation Priority:** `P0`
- **Installation Default:** Vendor factory self-signed certificate.
- **Baseline Suggested Value:** Unique valid CA-issued HTTPS certificate with matching identity; directory server certificate validation enabled whenever LDAP or Active Directory is used.
- **What is Auditable:**
  - Standard DMTF URI: `GET /redfish/v1/CertificateService/CertificateLocations` or `GET /redfish/v1/Managers/{id}/NetworkProtocol/HTTPS/Certificates`
  - Property: `.ValidNotAfter` (timestamp in the future), `.Issuer` != `.Subject` (not self-signed), SAN matches BMC IP/FQDN.
  - Pass Criteria: Certificate is CA-signed, unexpired, and includes the BMC DNS name or IP in Subject Alternative Names.
  - Fail Criteria: Self-signed certificate, expired certificate, or host mismatch.
- **Functional Impact:** Replacing certificates can cause temporary connection loss if clients or SDDC Manager lack the issuing CA root certificate in their trust stores.

---

### Control 3: esx-9.hardware-management-ssh-cryptography
- **Title:** Restrict SSH cryptography on hardware management controllers.
- **NIST SP 800-53r5:** `CM-07, SC-08, SC-13`
- **SCF 2026.1.1:** `CFG-03, CRY-03, IAC-10.2`
- **PCI DSS v4.0.1:** `2.2.7`
- **Implementation Priority:** `P1, Upon Feature Enablement`
- **Installation Default:** Vendor and firmware dependent.
- **Baseline Suggested Value:** SSH disabled unless required; when enabled, current approved cryptographic profile with weak key exchange, host-key, cipher, and MAC algorithms disabled.
- **What is Auditable:**
  - Standard DMTF URI: `GET /redfish/v1/Managers/{id}/NetworkProtocol`
  - Property: `.SSH.ProtocolEnabled`
  - Pass Criteria: SSH is disabled (`.SSH.ProtocolEnabled == false`). If SSH is enabled, controller must enforce approved cryptographic profiles (no SHA-1, no CBC ciphers, no DSA keys).
  - Fail Criteria: SSH enabled with legacy weak ciphers or unhardened default algorithm profiles.
- **Functional Impact:** Legacy SSH clients, older terminal software, or unmaintained automation scripts negotiating deprecated ciphers will fail to establish a session.

---

### Control 4: esx-9.hardware-management-security
- **Title:** Harden integrated hardware management controllers and disable vulnerable legacy protocols.
- **NIST SP 800-53r5:** `AC-12, CM-07, IA-05(05), SC-10`
- **SCF 2026.1.1:** `CFG-03, IAC-10.8`
- **PCI DSS v4.0.1:** `2.2.4`
- **Implementation Priority:** `P0`
- **Installation Default:** Site-Specific (frequently IPMI-over-LAN and HTTP enabled by default).
- **Baseline Suggested Value:** Unused controller services and protocols disabled, IPMI over LAN disabled, Telnet disabled, SNMPv1/v2c disabled, session timeout <= 1800s, vendor hardening guidance applied.
- **What is Auditable:**
  - Standard DMTF URIs:
    - `GET /redfish/v1/Managers/{id}/NetworkProtocol`
    - `GET /redfish/v1/SessionService`
  - Properties:
    - `.IPMI.ProtocolEnabled` must be `false`.
    - `.Telnet.ProtocolEnabled` must be `false`.
    - `.SNMP.ProtocolEnabled` must be `false` (or configured for SNMPv3 AuthPriv).
    - `.SessionTimeout` must be an integer where `0 < SessionTimeout <= 1800` (seconds).
  - Pass Criteria: All obsolete/cleartext protocols disabled; session timeout enforced <= 30 minutes.
  - Fail Criteria: IPMI-over-LAN enabled, Telnet enabled, SNMPv1/v2c enabled, or session timeout unlimited (`0`) or > 1800 seconds.
- **Functional Impact:** Disabling IPMI-over-LAN prevents legacy BMC monitoring scripts (`ipmitool`) from communicating over the network. Monitoring must be migrated to standard DMTF Redfish REST calls.

---

### Control 5: esx-9.hardware-management-authentication
- **Title:** Use strong, isolated identity management and brute-force protection on hardware management controllers.
- **NIST SP 800-53r5:** `AC-04(21), AC-07, IA-05(01)`
- **SCF 2026.1.1:** `NET-06.4, IAC-16.2`
- **PCI DSS v4.0.1:** `8.2.7, 8.3.4`
- **Implementation Priority:** `P0`
- **Installation Default:** Site-Specific (lockout threshold frequently set to 0/disabled).
- **Baseline Suggested Value:** Strong authentication enabled, account lockout threshold between 1 and 5 failed attempts, min password length >= 8 (recommend >= 14), identity management isolated from managed systems.
- **What is Auditable:**
  - Standard DMTF URI: `GET /redfish/v1/AccountService`
  - Properties:
    - `.AccountLockoutThreshold` (integer between `1` and `5`).
    - `.MinPasswordLength` (integer `>= 8`, recommended `>= 14`).
    - `.ActiveDirectory.ServiceEnabled` / `.LDAP.ServiceEnabled` (boolean).
  - Pass Criteria: Lockout threshold configured between 1 and 5; minimum password length meets or exceeds 8 characters.
  - Fail Criteria: Lockout threshold is 0 (disabled), threshold exceeds 5, or minimum password length is < 8 characters.
- **Functional Impact:** Aggressive lockout thresholds can lead to denial-of-service if misconfigured monitoring systems repeatedly attempt failed logins. Ensure dedicated local break-glass accounts are maintained.

---

### Control 6: esx-9.hardware-management-time
- **Title:** Synchronize hardware management controller time with organizational reference sources.
- **NIST SP 800-53r5:** `AU-08, SC-45(01)`
- **SCF 2026.1.1:** `MON-07.1, SEA-20`
- **PCI DSS v4.0.1:** `10.6.1, 10.6.2`
- **Implementation Priority:** `P0`
- **Installation Default:** Site-Specific (often unconfigured or local clock drift).
- **Baseline Suggested Value:** Controller synchronized to organizational NTP sources, one source or three or more, NTP protocol enabled.
- **What is Auditable:**
  - Standard DMTF URI: `GET /redfish/v1/Managers/{id}/NetworkProtocol`
  - Property: `.NTP.ProtocolEnabled` (must be `true`), `.NTP.NTPServers` (list contains 1 or >= 3 valid server addresses).
  - Pass Criteria: NTP enabled with 1 or >= 3 servers configured; BMC clock in sync with UTC.
  - Fail Criteria: NTP disabled, 0 servers configured, exactly 2 servers configured (split-brain risk), or clock drift exceeds 300 seconds.
- **Functional Impact:** None during normal operation. Clocks with substantial time drift should be adjusted during maintenance windows to prevent timestamp sequence inversions in audit logs.

---

### Control 7: esx-9.hardware-management-log-forwarding
- **Title:** Forward hardware management controller logs to a central log server over secure transport.
- **NIST SP 800-53r5:** `AU-06(04), SI-04`
- **SCF 2026.1.1:** `MON-02, MON-02.2`
- **PCI DSS v4.0.1:** `10.2.1, 10.3.3`
- **Implementation Priority:** `P0`
- **Installation Default:** Site-Specific (syslog forwarding typically unconfigured out of the box).
- **Baseline Suggested Value:** Controller event logs forwarded to central log collector (VCF Log Management / Aria Operations for Logs) using TLS transport where supported.
- **What is Auditable:**
  - Standard DMTF URIs:
    - `GET /redfish/v1/Managers/{id}/NetworkProtocol`
    - `GET /redfish/v1/Managers/{id}/LogServices`
  - Properties: Syslog protocol status (`ProtocolEnabled == true`) and remote server destination configured.
  - Pass Criteria: Active syslog destination configured pointing to an enterprise log aggregator; TLS transport enabled where supported.
  - Fail Criteria: Syslog disabled or destination unconfigured.
- **Functional Impact:** Requires outbound network routing and firewall clearance from BMC management networks to the central log server port (TCP 6514 for TLS, UDP 514 for legacy fallback).

---

### Control 8: esx-9.hardware-secureboot
- **Title:** Enable UEFI Secure Boot and verify out-of-band firmware attestation.
- **NIST SP 800-53r5:** `SI-07(09), SI-07(10)`
- **NIST SP 800-193:** Platform Firmware Resiliency
- **SCF 2026.1.1:** `END-06.5, END-06.6`
- **PCI DSS v4.0.1:** `5.2.3`
- **DISA STIG ID:** `VCFE-9X-000091`
- **Implementation Priority:** `P0`
- **Installation Default:** Enabled on modern certified servers, but frequently toggleable in firmware.
- **Baseline Suggested Value:** Enabled in system firmware and active for current boot.
- **What is Auditable:**
  - In-Band Assessment: PowerCLI `(Get-VMHost -Name $ESX | Get-View).Capability.UefiSecureBoot`
  - Out-of-Band Redfish Assessment:
    - DMTF URI: `GET /redfish/v1/Systems/{id}/SecureBoot`
    - Properties: `.SecureBootEnable` (boolean), `.SecureBootCurrentBoot` (string).
  - Pass Criteria: `.SecureBootEnable == true` AND `.SecureBootCurrentBoot == "Enabled"`.
  - Fail Criteria: `.SecureBootEnable == false` OR `.SecureBootCurrentBoot == "Disabled"`.
- **Functional Impact:** ESXi will refuse to load unsigned kernel modules, unauthorized VIBs, or tampered boot components. Unsigned legacy drivers must be replaced or signed before enforcement.

---

## 5. Audit Confidence & Unknown Handling Framework

In enterprise Redfish auditing, an assessment engine must never assume an unexposed or restricted property is compliant. The VCF SCG adheres to strict deterministic result states:

```
+----------------------------------------------------------------------------------------------------+
|                                    Audit State Determination                                       |
+----------------------+-----------------------------------------------------------------------------+
| State                | Operational Definition & Handling                                           |
+----------------------+-----------------------------------------------------------------------------+
| pass                 | DMTF standard property is exposed and matches the secure baseline value.  |
| fail                 | DMTF standard property is exposed and violates the baseline value.         |
| unknown_not_exposed  | DMTF endpoint or property omitted by BMC firmware (PROPERTY_NOT_EXPOSED).  |
| unknown_write_only   | Security attribute is write-only for secrecy (e.g. bind passwords/keys).    |
| unknown_unsupported  | Legacy BMC firmware generation does not support DMTF security schemas.      |
| unknown_unlicensed   | BMC requires OEM tier upgrade (e.g. iDRAC Enterprise, iLO Advanced).        |
| unknown_ambiguous    | Conflicting evidence observed (e.g. SNMP enabled without protocol version). |
+----------------------+-----------------------------------------------------------------------------+
```

**Principle of Zero Secret Extraction:** An audit tool must never collect or persist secret values (passwords, private keys, symmetric pre-shared keys) solely to verify a control. Write-only secrets remain categorized as `unknown_write_only`.

---

## 6. Implementation Summary & Upstream Integration

Integrating this guidance into the upstream VMware Cloud Foundation repository requires:
1. Appending the 3 new rows (`esx-9.hardware-management-tls`, `esx-9.hardware-management-certificates`, `esx-9.hardware-management-ssh-cryptography`) to `vcf-security-configuration-guide-91-controls.csv`.
2. Updating the discussions, baseline suggested values, and NIST mappings for the 5 existing rows (`esx-9.hardware-management-security`, `esx-9.hardware-management-authentication`, `esx-9.hardware-management-time`, `esx-9.hardware-management-log-forwarding`, and `esx-9.hardware-secureboot`).
3. Re-generating the companion Excel spreadsheet (`vcf-security-configuration-guide-91-controls.xlsx`) and guidance documentation (`vcf-security-configuration-guide-91-guidance.pdf`).
4. Utilizing the companion technical audit reference (`vcf-911-redfish-audit-reference.md`) for automated validation via SDDC Manager and the VCF Readiness Assessment Tool.
