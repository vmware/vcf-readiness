## 9. Key Anchor: BMC Hardware Security Audit Findings {#bmc-hardware-security-audit-findings}

This section serves as the definitive architectural reference for the out-of-band management controller security audit, baseline compliance frameworks, OEM hardening guidelines, and automated remediation procedures.

Out-of-band Baseboard Management Controllers (Dell iDRAC, HPE iLO, Lenovo XCC, Cisco IMC, Supermicro BMC, Intel BMC) operate with persistent access to server motherboards, PCIe buses, physical memory, and system firmware. Securing these interfaces is a non-negotiable prerequisite for enterprise VMware Cloud Foundation (VCF) 9.1 deployments.

---

### 9.1 Platform Cryptographic Security (TPM 2.0 & Secure Boot) {#platform-cryptographic-security}

Platform security combines hardware-rooted cryptographic identity with firmware boot integrity validation:

| Platform Security Feature | Evaluation Logic & Technical Standard | VCF 9.1 Mandate & Compliance Role | External Documentation |
|---|---|---|---|
| **TPM 2.0 Cryptoprocessor** | Validates presence of physical Trusted Platform Module (TPM) 2.0 chip enabled in UEFI mode. | **Mandatory Requirement:** Required for ESXi 9.1 Secure Boot attestation, cryptographic core isolation, and vSphere Native Key Provider. | [vSphere Security Guide — TPM 2.0](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-10F7022C-DBE0-4E80-9285-EB02CEF513A1.html) |
| **UEFI Secure Boot** | Audits UEFI signature verification for bootloaders, hypervisor kernel, and VIB kernel modules. | Ensures only cryptographically signed VMware binaries execute during POST; blocks bootkits and unauthorized rootkits. | [Broadcom KB 2147606](https://kb.vmware.com/s/article/2147606) |
| **Side-Channel Mitigations**| Evaluates processor microcode against Broadcom security baselines (Tier 1–Tier 4). | **Tier 4 Required:** Protects hypervisor and guest VM boundaries against Spectre, Meltdown, L1TF, MDS, and SRBDS. | [Broadcom KB 330041](https://kb.vmware.com/s/article/330041) |
| **BMC Firmware Baseline** | Compares BMC firmware build against certified OEM security maintenance baselines. | Mitigates published remote code execution (RCE) and memory corruption vulnerabilities in BMC daemons. | [OEM Reference Guide](docs/OEM_REFERENCE.md) |

---

### 9.2 BMC Security Posture Rollup & Risk Ratings {#bmc-security-posture-rollup}

The assessment engine aggregates individual control findings into a deterministic host security posture score:

#### Posture Classifications
1. **🟢 Baseline Met (`posture: "Baseline Met"`):**
   - All evaluated security controls passed the hardening standard.
   - Zero critical or high-priority vulnerabilities detected.
2. **🟡 Partially Assessed (`posture: "Partially Assessed"`):**
   - **Honesty Rule:** Unknown controls never count as a pass. If certain OEM attributes could not be queried via Redfish, the posture is classified as partially assessed rather than claiming compliance.
3. **🔴 Action Required (`posture: "Action Required"`):**
   - High-priority security failures detected (e.g. active Telnet, default root password, unencrypted IPMI-over-LAN).
   - Remediation is strictly required prior to commissioning nodes into enterprise clusters.

#### Prioritized Issue Badges
- **Critical Issues (Red Badges):**
  - `✗ Telnet`: Legacy unencrypted remote shell active on TCP port 23.
  - `✗ Default Pwd`: Unrotated factory default administrative password detected on root account.
  - `✗ TLS < 1.2`: Insecure cryptographic protocols (SSL 3.0, TLS 1.0, TLS 1.1) permitted on BMC web interfaces.
- **High-Priority Concerns (Amber Badges):**
  - `▲ HTTP`: Unencrypted plaintext web management interface exposed on TCP port 80.
  - `▲ IPMI LAN On`: Legacy IPMI-over-LAN active; vulnerable to RMCP+ Cipher 0 authentication bypass ([Broadcom KB 2046632](https://kb.vmware.com/s/article/2046632)).
  - `▲ No Lockout`: Account lockout threshold disabled, leaving the BMC exposed to automated brute-force attacks.
  - `▲ Host Pass-Through`: Virtual USB / Host-to-BMC network pass-through enabled; creates a hypervisor-to-BMC boundary escape path ([Broadcom KB 82435](https://kb.vmware.com/s/article/82435)).
  - `▲ Weak Ciphers`: Insecure symmetric ciphers (<256-bit) or obsolete hashing algorithms permitted.
  - `▲ No Syslog`: Out-of-band audit logging not forwarded to a central SIEM/syslog collector.
  - `▲ USB Mgmt`: Unrestricted local physical USB direct management port left enabled on server bezel.

---

### 9.3 Comprehensive 84-Control Security Audit Catalog {#bmc-84-control-catalog}

The tool evaluates out-of-band management controllers against an 84-control security catalog organized into five architectural tiers:

#### Control Provenance and Architectural Lineage
Users and security auditors frequently ask where the `C01`–`C59` numbering and controls originate:
- **Origin of the C01–C59 Taxonomy (Dell iDRAC9 Normalization):** When the audit engine was established, Dell was the only server OEM with an exhaustive, setting-by-setting published hardening manual: the *Dell iDRAC9 Security Configuration Guide* (revision A01). This guide was normalized into 84 canonical controls: 59 configuration controls (`C01`–`C59`), 16 operational lifecycle recommendations (`O01`–`O16`), and 9 platform assurance capabilities (`I01`–`I09`).
- **Vendor-Neutral Governance:** The security intent of these controls is governed by authoritative non-OEM frameworks: the **CISA & NSA Joint CSI** (*Harden Baseboard Management Controllers*), **VMware Cloud Foundation Security Configuration Guide (SCG 9.1)**, and **NIST SP 800-193**. Exactly 36 of the 59 configuration controls represent universal baseline hardening standards.
- **Three-Tier Multi-OEM Portability Model:**
  - **Tier 1: 8 Universal DMTF Standards (`C09, C21, C23, C24, C29, C37, C43, C53`):** Implemented purely via standard DMTF Redfish schemas (`ManagerNetworkProtocol`, `AccountService`, `CertificateService`, `SecureBoot`) and evaluated identically across all server manufacturers (including Intel Server Systems and Supermicro).
  - **Tier 2: 40 Portable Concepts (`C01–C08, C10–C17, C20, C22, C25–C28, C33–C36, C38–C42, C44–C47, C49–C52, C54`):** Vendor-neutral hardening concepts where underlying attributes differ by OEM. Resolved through dedicated OEM adapters (Dell `DellAttributes`, HPE iLO `SecurityService`, Lenovo XCC Security Mode, Cisco CIMC).
  - **Tier 3: 11 Dell-Specific Controls (`C18, C19, C30, C31, C32, C48, C55, C56, C57, C58, C59`):** Proprietary Dell features (e.g. Dell System Lockdown, SEKM, Group Manager, Lifecycle Controller import/export, Field Service Debug). Evaluated strictly as **`not_applicable`** on HPE, Lenovo, Cisco, Supermicro, and Intel platforms.
  - **OEM Feature Gap Stubs (`G-*`):** Unique vendor capabilities not present in Dell's baseline (e.g. HPE iLO `SecurityState` and Cisco `CNSA`) are maintained as separate architectural gap stubs without altering the canonical `C01`–`C59` taxonomy.

#### Group 1: Baseline Hardening Controls (VCF SCG Alignment) (36 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **C01** | HTTP-to-HTTPS Redirection | Force web clients onto HTTPS via iDRAC redirection. | Dell OEM Redfish | High |
| **C02** | Minimum TLS Version | Require TLS 1.2+ (prefer 1.3 where available). | Dell OEM Redfish | High |
| **C03** | TLS Encryption Strength | Prefer 256-bit or higher SSL encryption bit length. | Dell OEM Redfish | High |
| **C04** | TLS Cipher-Suite Restriction | Retain only strongest compatible suites; remove weak/DHE where applicable. | Dell OEM Redfish | High |
| **C05** | Trusted iDRAC Web Certificate | Replace unique self-signed default with CA-signed cert; unique key per controller. | Dell OEM Redfish | Medium |
| **C07** | Remote Syslog over TLS | Prefer secure remote syslog (e.g. TCP/6514) with CA validation. | Dell OEM Redfish | High |
| **C09** | SSH Service Exposure | Enable SSH only when required; prefer over Telnet. | Standard Redfish | High |
| **C11** | SSH Cryptographic Policy | No DSA; strong ciphers/KEX/MACs; no SHA-1/CBC weak sets. | Dell OEM Redfish | High |
| **C12** | Dedicated Management NIC | Prefer Dedicated NIC for BMC management. | Dell OEM Redfish | High |
| **C13** | Management VLAN | Enable management VLAN on BMC NIC. | Dell OEM Redfish | High |
| **C14** | USB Management & USB SCP | Disable unused USB management and USB XML/SCP configuration. | Dell OEM Redfish | High |
| **C15** | OS-to-iDRAC Pass-Through | Disable OS-BMC pass-through unless required; prefer USB-NIC mode if needed. | Dell OEM Redfish | High |
| **C16** | IP Login Blocking | Enable source-IP blocking after failed logins (window/penalty). | Dell OEM Redfish | High |
| **C17** | IP Allow-Range Filtering | Restrict BMC access to authorized management address ranges. | Dell OEM Redfish | High |
| **C18** | Auto-Discovery | Disable auto-discovery after provisioning. | Dell OEM Redfish | High |
| **C19** | Auto Config / SCP Provisioning | Disable unused Auto Config; require HTTPS if used. | Dell OEM Redfish | Medium |
| **C20** | Disable Unused Interfaces & Services | Disable unused Local Config, Web, SEKM, SSH, remote RACADM, SNMP, ASR, USB, pass-through, etc. | Dell OEM Redfish | Medium |
| **C21** | IPMI over LAN Disablement | IPMI-over-LAN disabled by default/recommendation. | Standard Redfish | High |
| **C22** | Serial over LAN Hardening | Disable Serial-over-LAN when unused (guide default enabled). | Dell OEM Redfish | High |
| **C23** | Telnet Service Disablement | Telnet disabled (removed in FW 4.40+). | Standard Redfish | High |
| **C24** | SNMP Service Exposure & SNMPv3 | Disable SNMP unless needed; if needed SNMPv3 only. | Standard Redfish | High |
| **C26** | SNMP Credentials & Cryptography | No default communities; SNMPv3 SHA/AES with separate auth/privacy passphrases. | Dell OEM Redfish | Medium |
| **C28** | Authenticated NTP | Use authenticated NTP; do not mix auth and unauth sources. | Dell OEM Redfish | High |
| **C29** | Redfish Session Authentication | Clients should use session token auth (POST session, X-Auth-Token, DELETE) not per-request Basic. | Standard Redfish | High |
| **C37** | Least-Privilege Roles & Session Timeout | Grant only required privileges; restrict Configure Users. | Standard Redfish | High |
| **C38** | Per-User IPMI Privilege | IPMI LAN/Serial privilege No Access for every user by default. | Dell OEM Redfish | High |
| **C39** | Per-User SNMPv3 Protection | SHA/AES, separate passphrases, protocol disabled when unused. | Dell OEM Redfish | Medium |
| **C40** | Password Quality Policy | Strong password policy (score/length/classes). | Dell OEM Redfish | High |
| **C41** | Default Password & Force Change | Change unique shipped password; enable FCP where required. | Dell OEM Redfish | Medium |
| **C42** | Two-Factor Authentication | Enable supported 2FA (Simple 2FA / RSA SecurID where licensed). | Dell OEM Redfish | Medium |
| **C43** | Central Directory Authentication & Lockout | Use AD or LDAP for centralized identities when required. | Standard Redfish | High |
| **C44** | Active Directory Certificate Validation | Enable AD cert validation and upload issuing CA. | Dell OEM Redfish | High |
| **C45** | LDAP Certificate Validation | Enable LDAP cert validation and upload issuing CA. | Dell OEM Redfish | High |
| **C46** | Disable Host-Local Reconfiguration | Disable Local RACADM and/or preboot iDRAC Settings when not required. | Dell OEM Redfish | High |
| **C48** | System Lockdown | Enable System Lockdown after provisioning. | Dell OEM Redfish | High |
| **C53** | UEFI Secure Boot | Secure Boot enabled with UEFI boot. | Standard Redfish | High |

#### Group 2: Conditional Hardening Controls (Environment Dependent) (16 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **C06** | SCEP / Automated Certificate Enrollment | Enable SCEP only where automated enrollment is used; default disabled. | Dell OEM Redfish | Medium |
| **C08** | FIPS Mode | Enable FIPS where required; know that enabling resets config. | Dell OEM Redfish | High |
| **C10** | SSH Public-Key Authentication | Prefer PKI SSH auth with strong keys where used. | Dell OEM Redfish | Medium |
| **C25** | SNMP Network Isolation | Isolate SNMP with VLAN/ACL/physical separation from general networks. | External Process | High |
| **C27** | IPMI Fallback Hardening / Cipher 0 | If IPMI unavoidable: segment, IPMI 2.0, disable Cipher 0. | Vendor Tool | Low |
| **C33** | Virtual Console Client & Video Encryption | eHTML5 + video encryption enabled. | Dell OEM Redfish | High |
| **C34** | Virtual Console TLS & Web Redirection | TLS 1.2+, 256-bit, HTTPS web redirect for virtual console. | Dell OEM Redfish | High |
| **C35** | Virtual Media Encryption | Virtual media encryption enabled. | Dell OEM Redfish | Low |
| **C36** | VNC Server Hardening | Disable VNC unless needed; if enabled use 256-bit SSL + timeout; password write-only. | Dell OEM Redfish | High |
| **C47** | Security Login Banner | Custom authorized-use / monitoring banner. | Dell OEM Redfish | High |
| **C49** | BIOS Setup/System Passwords & Lock Status | Setup password + Password Status Locked where required. | Dell OEM Redfish | Medium |
| **C50** | BIOS Power-Button Control | Disable power button where local shutdown risk warrants. | Standard Redfish | Medium |
| **C51** | UEFI Variable Access | Prefer Controlled UEFI variable access. | Standard Redfish | Medium |
| **C52** | In-Band Manageability Interface | Disable host-side manageability when unused; enable during HECI/IPMI update workflows. | Standard Redfish | Medium |
| **C54** | Secure Boot Policy & Mode | Standard policy + Deployed Mode for normal operation. | Standard Redfish | Medium |
| **C55** | LCD / Control-Panel Restriction | View Only or Disabled LCD; optional disable ID-button reset. | Vendor Tool | Low |

#### Group 3: OEM Runbook & Procedural Controls (Dell-Specific) (7 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **C30** | Secure Enterprise Key Manager (SEKM) | Use SEKM where centralized keys required; TLS/cert identity match KMS. | Dell OEM Redfish | Medium |
| **C31** | Group Manager Enablement | Disable Group Manager when unused. | Dell OEM Redfish | High |
| **C32** | Group Manager Network & Passcode | Dedicated mgmt network + strong shared passcode + rotation. | Dell OEM Redfish | Medium |
| **C56** | BIOS Live Scanning | Boot-time integrity checking + licensed live scans. | Vendor Tool | Low |
| **C57** | Secure Imports & Exports | Use HTTPS for inventory/LCL/SCP/license/update transfers. | Dell OEM Redfish | Medium |
| **C58** | Outbound HTTPS & Proxy Validation | Do not ignore cert warnings; validate outbound HTTPS; distinct proxy creds. | Dell OEM Redfish | Medium |
| **C59** | Field Service Debug (FSD) | FSD disabled except authorized Dell support engagement. | External Process | High |

#### Group 4: Operational Recommendations (Lifecycle & Governance) (16 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **O01** | Isolated Management Network | Never expose BMC to Internet; dedicated mgmt network. | External Process | Varies |
| **O02** | Firmware Currency | Keep BMC/platform firmware current. | Standard Redfish | Varies |
| **O03** | Signed Update & Rollback | Use signed packages; investigate signature failures. | Standard Redfish | Varies |
| **O04** | Certificate Lifecycle | Inventory expiry; renew trust stores. | Vendor Tool | Varies |
| **O05** | FIPS Change Control | Export SCP before FIPS; verify after FW maintenance. | Dell OEM Redfish | Varies |
| **O06** | Credential & Passcode Rotation | Rotate passwords and Group Manager passcode. | Vendor Tool | Varies |
| **O07** | Account & Privilege Review | Periodic review of local slots/roles/keys. | Standard Redfish | Varies |
| **O08** | Auto Config Credential Containment | Least-privilege non-reused share creds (DHCP plaintext). | External Process | Varies |
| **O09** | Java Console Verification | User verifies publisher/cert/FQDN before launch. | External Process | Varies |
| **O10** | SEKM Lifecycle Governance | Verify PERC/KMS/certs before enable/rekey. | Vendor Tool | Varies |
| **O11** | Secure Boot Certificate Governance | Test PK/KEK/db changes only in controlled deployment. | Vendor Tool | Varies |
| **O12** | Secure Disposal & Repurposing | System Erase before ownership transition. | Dell OEM Redfish | Varies |
| **O13** | Security-Event Monitoring | Alert on security Lifecycle Log events. | Standard Redfish | Varies |
| **O14** | Vulnerability Scanning Disposition | Harden before scan; document Dell false positives. | External Process | Varies |
| **O15** | Superroot Governance | Contractual reclaim/reprovision authority. | External Process | Varies |
| **O16** | Applicability & Exception Review | Threat-model exceptions documented. | External Process | Varies |

#### Group 5: Hardware & Platform Assurance Capabilities (9 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **I01** | Silicon Root of Trust | Built-in silicon RoT. | Vendor Tool | Varies |
| **I02** | Cryptographically Verified Trusted Boot | Built-in trusted boot + Secure Boot. | Standard Redfish | Varies |
| **I03** | SELinux inside BMC | Built-in non-disableable SELinux. | External Process | Varies |
| **I04** | Signed Firmware Enforcement | Built-in signed updates. | Standard Redfish | Varies |
| **I05** | Non-Root Internal Services | Built-in least privilege. | External Process | Varies |
| **I06** | BMC Credential Vault | Chip-bound credential encryption. | External Process | Varies |
| **I07** | BIOS Recovery & Hardware RoT | Automatic integrity/recovery. | Dell OEM Redfish | Varies |
| **I08** | Built-In SNMP Safeguards | Lockout/restricted MIB behavior. | Vendor Tool | Varies |
| **I09** | Lifecycle Security Auditing | Built-in security event generation. | Standard Redfish | Varies |

---

### 9.4 OEM Security Hardening Guides & VCF Security Guidelines {#oem-security-hardening-guides}

Consult the official security configuration baselines published by VMware, national cybersecurity authorities, and hardware server manufacturers:

- 🛡️ **[VMware Cloud Foundation Security and Compliance Guidelines (GitHub)](https://github.com/vmware/vcf-security-and-compliance-guidelines):**
  The authoritative repository of security configuration guides (SCG) for VCF, ESXi, and vSAN deployments.
- 🛡️ **[CISA & NSA Joint Cybersecurity Information Sheet: Harden Baseboard Management Controllers (PDF)](https://media.defense.gov/2023/Jun/14/2003241405/-1/-1/0/CSI_HARDEN_BMCS.PDF):**
  Authoritative joint federal guidance published by CISA and NSA establishing 8 essential defensive baselines for enterprise BMC operations and hardware security.
- 🔧 **[Dell iDRAC9 Security Configuration Guide](https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v5.x-series/idrac9_security_configuration_guide/):**
  Hardening standards for Dell PowerEdge 14G, 15G, and 16G servers (System Lockdown, TLS, ports, IP filtering, SSH crypto, FIPS, BIOS security).
  - Direct PDF: [iDRAC9 Security Configuration Guide (PDF)](https://dl.dell.com/content/manual30213951-idrac9-security-configuration-guide.pdf)
- 🔧 **[HPE iLO Security Documentation Hub](https://www.hpe.com/info/iLO):**
  Official security documentation and administration resources for HPE ProLiant iLO 5 and iLO 6 controllers.
  - Redfish Security Service: [HPE iLO Redfish Security Service (Security States & TLS)](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/securityservice)
  - Security Bulletin Reference: *Implementing Security Best Practices to Protect the iLO Management Interface* (Doc ID: `a00046959en_us`)
  - Platform Security States: Gen10/Gen11 iLO 5/6 security modes (Production, High Security, FIPS, CNSA).
- 🔧 **[Lenovo ThinkSystem Server & XCC Hardening Guide](https://lenovopress.lenovo.com/lp1260-how-to-harden-the-security-of-your-thinksystem-server):**
  Hardening paper for Lenovo XClarity Controller (XCC / XCC2 / XCC3) covering TLS, IPMI/KCS disablement, physical lockdown, security modes, and OneCLI automation.
  - Direct PDF: [How to Harden the Security of your ThinkSystem Server (PDF)](https://lenovopress.lenovo.com/lp1260.pdf)
- 🔧 **[Cisco Compute Security Hardening Guide (Standalone / CIMC)](https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/compute-security-hardening-guide-standalone-wp.pdf):**
  Authoritative hardening whitepaper for Cisco UCS C-Series rack servers and standalone Cisco Integrated Management Controllers (CIMC).
  - GUI Configuration Guide: [Cisco UCS C-Series IMC GUI Configuration Guide, Release 6.0](https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/gui/config/guide/6_0/b_cisco_ucs_c-series_gui_configuration_guide_6-0.html)
- 🔧 **[Supermicro BMC Security Best Practices (PDF)](https://www.supermicro.com/products/nfo/files/IPMI/Best_Practices_BMC_Security.pdf):**
  Official best practices paper for securing Supermicro Baseboard Management Controllers, IPMI interfaces, and management networks.
  - Feature Guide PDF: [Supermicro BMC Server Management Feature Guide (PDF)](https://www.supermicro.com/products/nfo/files/IPMI/BMC_Server_Management_Feature_Guide.pdf)
  - Security Hub: [Supermicro Security Center](https://www.supermicro.com/en/support/security_center)
- 🔧 **[Intel Server Systems BMC & BIOS Security Configuration Guide](https://www.intel.com/content/www/us/en/support/articles/000055785/server-products.html):**
  Security configuration guidelines and best practices for Intel server platforms and integrated Baseboard Management Controllers.
  - Direct PDF: [Intel Server Systems BMC & BIOS Security Good Practices (PDF)](https://cdrdv2-public.intel.com/840799/BMC_BIOS_Security_GoodPractices.pdf)

#### CISA / NSA "Harden Baseboard Management Controllers" Alignment & Control Mapping

In June 2023, the Cybersecurity and Infrastructure Security Agency (CISA) and the National Security Agency (NSA) jointly published the Cybersecurity Information Sheet (CSI): **[Harden Baseboard Management Controllers (PDF)](https://media.defense.gov/2023/Jun/14/2003241405/-1/-1/0/CSI_HARDEN_BMCS.PDF)**. Unhardened BMCs represent highly privileged attack vectors that operate independently of the host operating system, maintain separate network identities, and persist even when the physical server is powered down.

The VCF HCI Readiness Tool's BMC Hardware Security Audit engine directly evaluates and automates verification of all 8 core recommendations defined in the joint CSI:

| CISA / NSA CSI Recommendation | Security Objective | VCF Readiness Tool Audit Controls | Confidence |
|---|---|---|---|
| **1. Protect BMC credentials** | Eliminate default passwords, enforce strong authentication, and thwart brute-force password guessing. | **C41** (Default Password & Force Change), **C40** (Password Quality Policy), **C43** (Central Directory Authentication & Account Lockout), **C16** (IP Login Blocking), Least-Privilege ReadOnly Audit Role. | High |
| **2. Enforce VLAN separation** | Isolate OOB management on dedicated VLANs with restricted network routing and access controls. | **C12** (Dedicated Management NIC), **C13** (Management VLAN), **C16** (IP Login Blocking), **C17** (IP Allow-Range Filtering). | High |
| **3. Harden configurations** | Minimize attack surface by disabling plaintext services, insecure protocols, and boundary-escape paths. | **C01** (HTTP-to-HTTPS Redirection), **C02** (Minimum TLS 1.2+), **C03** (TLS Encryption Strength), **C04** (TLS Cipher-Suite Restriction), **C07** (Remote Syslog TLS), **C09** (SSH Hardening), **C11** (SSH Cryptographic Policy), **C14** (USB Port Management), **C15** (OS-to-iDRAC Pass-Through), **C18/C19** (Auto-Discovery & SCP Zero-Touch), **C20** (Unused Services), **C21** (IPMI over LAN Disablement), **C22** (Serial-over-LAN), **C23** (Telnet Disablement), **C24** (SNMPv3 Only), **C28** (Authenticated NTP), **C37** (Session Timeout ≤ 1800s), **C48** (System Lockdown). | High / Medium |
| **4. Perform routine BMC update checks** | Maintain firmware patch currency to eliminate known CVEs, remote code execution (RCE), and privilege escalation flaws. | BMC Firmware Version Audit against certified baseline lines; **O01–O04** (Firmware Update Checks & CVE Microcode Baselines). | High |
| **5. Monitor BMC integrity** | Verify immutable hardware-anchored trust chains, secure boot validation, and cryptographically attested component integrity. | **I01–I05** (Hardware Silicon Root of Trust — Dell RoT, HPE Silicon Root of Trust), **I06–I09** (Secure Component Verification factory ledger), Host UEFI Secure Boot & TPM 2.0. | High |
| **6. Move sensitive workloads to hardened devices** | Restrict critical applications and sensitive data to server nodes with verified hardware and BMC security compliance. | Automated BMC Security Posture Rollup (`✓ Baseline Met`, `▲ Partial`, `✗ Action Req`), host compliance scorecards, and fleet triage views. | High |
| **7. Use firmware scanning tools periodically** | Conduct routine out-of-band auditing to detect configuration drift, unpatched vulnerabilities, or unauthorized changes. | **Automated by Tool:** Read-only Redfish compliance scanning engine auditing 84 canonical controls without OS interruption. | High |
| **8. Do not ignore BMCs** | Prevent forgotten, unconfigured, or legacy BMCs from serving as unmonitored footholds in datacenter fabrics. | Fleet-wide BMC network discovery, subnet sweeps, automated OEM identification, and multi-host inventory auditing. | High |

#### Key Broadcom Security Knowledge Base Articles
- [Broadcom KB 2147606 — Verifying Secure Boot on ESXi Hosts](https://kb.vmware.com/s/article/2147606)
- [Broadcom KB 1003734 — Time Synchronization and NTP Best Practices](https://kb.vmware.com/s/article/1003734)
- [Broadcom KB 82435 — Security Risks of Host-to-BMC Virtual USB NIC Pass-Through](https://kb.vmware.com/s/article/82435)
- [Broadcom KB 2046632 — Disabling Insecure IPMI Protocols (VMSA-2013-0007)](https://kb.vmware.com/s/article/2046632)
- [Broadcom KB 330041 — VMware ESXi Speculative Execution Mitigations](https://kb.vmware.com/s/article/330041)

---

### 9.5 Practical Security Remediation Scripts & CLI Commands {#security-remediation-scripts}

Use these verified command snippets to remediate out-of-band management findings across vendor environments.

*(Note: Network IP addresses used below adhere strictly to RFC 5737 documentation ranges `192.0.2.x` / `198.51.100.x`).*

#### 1. VMware ESXi Host Verification (In-Band)
Run these commands from an administrative ESXi SSH shell to verify Secure Boot and TPM attestation:

```bash
# Verify ESXi UEFI Secure Boot validation status
/usr/lib/vmware/secureboot/bin/secureBoot.py -c

# Check ESXi security configuration and TPM encryption status
esxcli system security get

# Verify TPM 2.0 device presence and driver registration
esxcli hardware tpm get
```

#### 2. Dell iDRAC (RACADM / Remote SSH CLI)
Remediate IPMI-over-LAN, default passwords, Telnet, NTP, and pass-through interfaces:

```bash
# Disable insecure legacy IPMI-over-LAN (RMCP+ Cipher 0 mitigation)
racadm set iDRAC.IPMILan.Enable 0

# Disable plaintext Telnet daemon
racadm set iDRAC.Telnet.Enable 0

# Enforce TLS 1.2 or TLS 1.3 as minimum cryptographic protocol
racadm set iDRAC.WebServer.TLSProtocol 2

# Disable Host-to-iDRAC virtual USB pass-through (boundary isolation)
racadm set iDRAC.USB.HostPassThrough 0

# Configure authenticated NTP synchronization
racadm set iDRAC.NTPConfigGroup.NTPEnable 1
racadm set iDRAC.NTPConfigGroup.NTP1 192.0.2.123
racadm set iDRAC.NTPConfigGroup.NTP2 192.0.2.124

# Enforce Account Lockout (5 attempts, 1800 second lockout)
racadm set iDRAC.Security.AccountLockoutThreshold 5
racadm set iDRAC.Security.AccountLockoutDuration 1800

# Enable System Lockdown mode (blocks unauthorized firmware/BIOS changes)
racadm set System.Lockdown.SystemLockdownMode 1
```

#### 3. HPE iLO (RESTful Interface Tool / ilorest CLI)
Apply hardening baselines to HPE iLO 5 and iLO 6 controllers:

```bash
# Login to HPE iLO
ilorest login 192.0.2.10 -u Administrator -p <CurrentPassword>

# Disable legacy IPMI-over-LAN
ilorest set Service.IpmiEnabled=False --commit

# Enforce High Security mode (disables TLS 1.0/1.1 and insecure ciphers)
ilorest set Security.SecurityState=HighSecurity --commit

# Configure static enterprise NTP servers
ilorest set DateTime.StaticNTP=192.0.2.123,192.0.2.124 --commit

# Enable UEFI Secure Boot in system BIOS
ilorest set Bios.SecureBoot=Enabled --commit

# Logout
ilorest logout
```

#### 4. Lenovo XClarity Controller (OneCLI)
Configure security policies across Lenovo ThinkSystem servers:

```bash
# Disable IPMI-over-LAN channel
onecli config set IPMI.EnableLANChannel Disabled --host 192.0.2.20 --user USERID --password <Password>

# Enforce TLS 1.2 minimum on web services
onecli config set Network.MinTLSVersion TLS1.2 --host 192.0.2.20 --user USERID --password <Password>

# Enable UEFI Secure Boot
onecli config set SystemConfiguration.SecureBootConfiguration.SecureBoot Enable --host 192.0.2.20 --user USERID --password <Password>

# Configure NTP servers
onecli config set NTP.NTPEnable Enabled --host 192.0.2.20 --user USERID --password <Password>
onecli config set NTP.NTP1 192.0.2.123 --host 192.0.2.20 --user USERID --password <Password>
```
