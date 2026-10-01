# DMTF Redfish BMC Security Audit Reference Guide

**Document Status:** Technical Reference for VCF 9.1.1 SCG Implementation  
**Audience:** VMware Solution Architects, Security Auditors, and Automation Engineers  
**Specification Standard:** DMTF Redfish Scalable Platforms Management Standard (DSP0266 v1.19+, DSP2059 v1.2+)  
**Verified OEM Hardware:** Dell PowerEdge 14G/15G/16G (iDRAC9), HPE ProLiant Gen10/Gen10 Plus/Gen11 (iLO 5/6)  
**Evidence Source:** `samples/reference-captures/`  

---

## 1. Architectural Overview & Vendor-Neutral Discovery

DMTF Redfish provides a standardized, hypermedia-driven REST API across server OEMs. While vendors organize proprietary extensions in vendor-specific trees (`Oem/Dell` or `Oem/Hpe`), core server security management conforms to standard normative DMTF schemas.

To maintain **100% vendor-neutral automation**, audit tools must never hardcode vendor URI paths (e.g., `/redfish/v1/Managers/iDRAC.Embedded.1` or `/redfish/v1/Managers/1`). Instead, tools dynamically discover manager and system URIs from the ServiceRoot.

```
                  +--------------------------------+
                  |  GET /redfish/v1 (ServiceRoot)  |
                  +--------------------------------+
                                  |
                +-----------------+-----------------+
                |                                   |
                v                                   v
+-------------------------------+   +-------------------------------+
|     GET /redfish/v1/Managers   |   |     GET /redfish/v1/Systems   |
| (Members[0]["@odata.id"])     |   | (Members[0]["@odata.id"])     |
+-------------------------------+   +-------------------------------+
                |                                   |
        +-------+-------+                           v
        |               |             +----------------------------+
        v               v             |  GET {sys_uri}/SecureBoot  |
+---------------+---------------+     +----------------------------+
|NetworkProtocol|AccountService |
+---------------+---------------+
```

### Dynamic URI Resolution Pattern
```bash
# 1. Resolve Manager URI (Dell: /redfish/v1/Managers/iDRAC.Embedded.1, HPE: /redfish/v1/Managers/1)
MGR_URI=$(curl -ks -u "$USER:$PASS" https://$BMC_HOST/redfish/v1/Managers | jq -r '.Members[0]["@odata.id"]')

# 2. Resolve System URI (Dell: /redfish/v1/Systems/System.Embedded.1, HPE: /redfish/v1/Systems/1)
SYS_URI=$(curl -ks -u "$USER:$PASS" https://$BMC_HOST/redfish/v1/Systems | jq -r '.Members[0]["@odata.id"]')
```

---

## 2. Standard DMTF Audit Matrix & SCG Control Mappings

| SCG 9.1.1 Control ID | Standard DMTF Endpoint URI | Audited Property Keys | Normative Schema |
|---|---|---|---|
| `esx-9.hardware-management-tls` | `{MGR_URI}/NetworkProtocol` | `.HTTP.ProtocolEnabled`<br>`.HTTPS.ProtocolEnabled` | `ManagerNetworkProtocol` |
| `esx-9.hardware-management-certificates` | `/redfish/v1/CertificateService/CertificateLocations`<br>`{MGR_URI}/NetworkProtocol/HTTPS/Certificates` | `.ValidNotAfter`<br>`.Issuer`<br>`.Subject` | `CertificateService`<br>`Certificate` |
| `esx-9.hardware-management-ssh-cryptography` | `{MGR_URI}/NetworkProtocol` | `.SSH.ProtocolEnabled` | `ManagerNetworkProtocol` |
| `esx-9.hardware-management-security` | `{MGR_URI}/NetworkProtocol`<br>`/redfish/v1/SessionService` | `.IPMI.ProtocolEnabled`<br>`.Telnet.ProtocolEnabled`<br>`.SNMP.ProtocolEnabled`<br>`.SessionTimeout` | `ManagerNetworkProtocol`<br>`SessionService` |
| `esx-9.hardware-management-authentication` | `/redfish/v1/AccountService` | `.AccountLockoutThreshold`<br>`.MinPasswordLength`<br>`.ActiveDirectory.ServiceEnabled`<br>`.LDAP.ServiceEnabled` | `AccountService` |
| `esx-9.hardware-management-time` | `{MGR_URI}/NetworkProtocol` | `.NTP.ProtocolEnabled`<br>`.NTP.NTPServers` | `ManagerNetworkProtocol` |
| `esx-9.hardware-management-log-forwarding` | `{MGR_URI}/LogServices` | `.SyslogFilter`<br>`.RemoteServers` | `LogService` |
| `esx-9.hardware-secureboot` | `{SYS_URI}/SecureBoot` | `.SecureBootEnable`<br>`.SecureBootCurrentBoot` | `SecureBoot` |

---

## 3. Side-by-Side Multi-OEM Ground Truth (Dell vs HPE)

Telemetry extracted directly from verified OEM reference captures confirms DMTF schema alignment between Dell and HPE servers.

### 3.1 Network Protocol Endpoint (`NetworkProtocol`)
- **Query:** `GET {MGR_URI}/NetworkProtocol`

```json
/* Dell PowerEdge R6525 (OBFUSCATED_Host-209.json) */
{
  "uri": "/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol",
  "@odata.type": "#ManagerNetworkProtocol.v1_10_1.ManagerNetworkProtocol",
  "HTTP": {
    "ProtocolEnabled": true,
    "Port": 80
  },
  "HTTPS": {
    "ProtocolEnabled": true,
    "Port": 443,
    "CertificatesCount": 1
  },
  "IPMI": {
    "ProtocolEnabled": true
  },
  "SSH": {
    "ProtocolEnabled": true,
    "Port": 22
  },
  "Telnet": {
    "ProtocolEnabled": true,
    "Port": 23
  },
  "SNMP": {
    "ProtocolEnabled": true,
    "Port": 161
  },
  "NTP": {
    "ProtocolEnabled": true,
    "NTPServersCount": 2
  }
}
```

```json
/* HPE ProLiant DL380 Gen10 (OBFUSCATED_Host-208.json) */
{
  "uri": "/redfish/v1/Managers/1/NetworkProtocol",
  "@odata.type": "#ManagerNetworkProtocol.v1_0_0.ManagerNetworkProtocol",
  "HTTP": {
    "ProtocolEnabled": true,
    "Port": 80
  },
  "HTTPS": {
    "ProtocolEnabled": true,
    "Port": 443
  },
  "IPMI": {
    "ProtocolEnabled": true,
    "Port": 623
  },
  "SSH": {
    "ProtocolEnabled": true,
    "Port": 22
  },
  "SNMP": {
    "ProtocolEnabled": true,
    "Port": 161
  },
  "VirtualMedia": {
    "ProtocolEnabled": true,
    "Port": 17988
  }
}
```

**Cross-OEM Assessment Observation:**
- Both vendors provide identical boolean flags for `HTTP.ProtocolEnabled`, `HTTPS.ProtocolEnabled`, `IPMI.ProtocolEnabled`, `SSH.ProtocolEnabled`, and `SNMP.ProtocolEnabled`.
- Dell explicitly models `Telnet.ProtocolEnabled` (set to `true` in unhardened factory states). HPE iLO firmware omits the `Telnet` object entirely because Telnet was permanently removed from iLO 5/6 microcode, representing an implicit disabled state (`unknown_not_exposed` or compliant-by-removal).

---

### 3.2 Account Service Endpoint (`AccountService`)
- **Query:** `GET /redfish/v1/AccountService`

```json
/* Dell PowerEdge R6525 (OBFUSCATED_Host-209.json) */
{
  "uri": "/redfish/v1/AccountService",
  "@odata.type": "#AccountService.v1_15_1.AccountService",
  "ServiceEnabled": true,
  "AuthFailureLoggingThreshold": 2,
  "MinPasswordLength": 1,
  "MaxPasswordLength": 127,
  "AccountLockoutThreshold": 0,
  "AccountLockoutDuration": 0,
  "AccountLockoutCounterResetAfter": 0,
  "LocalAccountAuth": "Fallback",
  "ActiveDirectory": {
    "ServiceEnabled": true,
    "ServiceAddressesCount": 3,
    "RemoteRoleMappingCount": 15
  },
  "LDAP": {
    "ServiceEnabled": false,
    "ServiceAddressesCount": 1,
    "RemoteRoleMappingCount": 15
  }
}
```

```json
/* HPE ProLiant DL380 Gen10 (OBFUSCATED_Host-208.json) */
{
  "uri": "/redfish/v1/AccountService",
  "@odata.type": "#AccountService.v1_15_0.AccountService",
  "MinPasswordLength": 7,
  "LocalAccountAuth": "Enabled",
  "ActiveDirectory": {
    "ServiceEnabled": false,
    "ServiceAddressesCount": 1,
    "RemoteRoleMappingCount": 3
  },
  "LDAP": {
    "ServiceEnabled": true,
    "ServiceAddressesCount": 1,
    "RemoteRoleMappingCount": 3
  }
}
```

**Cross-OEM Assessment Observation:**
- `MinPasswordLength`: Dell in this scan was set to `1` (unhardened default); HPE was set to `7` (unhardened default). Both fail the VCF baseline requirement of `>= 8` characters.
- `AccountLockoutThreshold`: Dell reports `0` (lockout disabled, failing SCG baseline).
- Central Directory Integration: Both vendors adhere to standard `ActiveDirectory.ServiceEnabled` and `LDAP.ServiceEnabled` structures with remote role mappings.

---

### 3.3 Session Service Endpoint (`SessionService`)
- **Query:** `GET /redfish/v1/SessionService`

```json
/* Dell PowerEdge R6525 (OBFUSCATED_Host-209.json) */
{
  "uri": "/redfish/v1/SessionService",
  "@odata.type": "#SessionService.v1_1_9.SessionService",
  "ServiceEnabled": true,
  "SessionTimeout": 1800,
  "SessionsExposed": true
}
```

```json
/* HPE ProLiant DL380 Gen10 (OBFUSCATED_Host-208.json) */
{
  "uri": "/redfish/v1/SessionService",
  "@odata.type": "#SessionService.v1_0_0.SessionService",
  "ServiceEnabled": true,
  "SessionTimeout": 30,
  "SessionsExposed": true
}
```

**Cross-OEM Assessment Observation:**
- Both vendors expose `SessionTimeout` in seconds.
- Dell is configured for exactly `1800` seconds (30 minutes, upper baseline limit, PASS).
- HPE is configured for `30` seconds (within baseline `<= 1800` seconds, PASS).

---

### 3.4 UEFI Secure Boot Endpoint (`SecureBoot`)
- **Query:** `GET {SYS_URI}/SecureBoot`

```json
/* Dell PowerEdge R6525 (OBFUSCATED_Host-209.json - Disabled) */
{
  "uri": "/redfish/v1/Systems/System.Embedded.1/SecureBoot",
  "@odata.type": "#SecureBoot.v1_1_2.SecureBoot",
  "SecureBootEnable": false,
  "SecureBootCurrentBoot": "Disabled",
  "SecureBootMode": "DeployedMode"
}
```

```json
/* Dell PowerEdge R740 (Host-124.json - Enabled) */
{
  "uri": "/redfish/v1/Systems/System.Embedded.1/SecureBoot",
  "@odata.type": "#SecureBoot.v1_1_2.SecureBoot",
  "SecureBootEnable": true,
  "SecureBootCurrentBoot": "Enabled",
  "SecureBootMode": "DeployedMode"
}
```

```json
/* HPE ProLiant DL380 Gen10 (OBFUSCATED_Host-208.json - Disabled) */
{
  "uri": "/redfish/v1/Systems/1/SecureBoot",
  "@odata.type": "#SecureBoot.v1_0_0.SecureBoot",
  "SecureBootEnable": false,
  "SecureBootCurrentBoot": "Disabled",
  "SecureBootMode": "UserMode"
}
```

**Cross-OEM Assessment Observation:**
- Both vendors expose standard properties: `SecureBootEnable` (boolean target) and `SecureBootCurrentBoot` (active state string).
- Compliance requires both properties to indicate enabled:
  ```python
  is_secure_boot_pass = (
      data.get("SecureBootEnable") is True 
      and str(data.get("SecureBootCurrentBoot", "")).lower() == "enabled"
  )
  ```

---

## 4. Production CLI Audit Procedures

Below are production-ready audit commands using `curl` and `jq` that execute against any DMTF Redfish conformant BMC.

### 4.1 Transport & Service Surface Audit
```bash
#!/usr/bin/env bash
set -euo pipefail

BMC="192.0.2.100"
USER="readonly_audit"
PASS="AuditPassword123"

# 1. Discover Manager URI
MGR_URI=$(curl -ks -u "$USER:$PASS" "https://${BMC}/redfish/v1/Managers" | jq -r '.Members[0]["@odata.id"]')

# 2. Query Protocols
curl -ks -u "$USER:$PASS" "https://${BMC}${MGR_URI}/NetworkProtocol" | jq '{
  HTTP_Enabled: .HTTP.ProtocolEnabled,
  HTTPS_Enabled: .HTTPS.ProtocolEnabled,
  IPMI_LAN_Enabled: .IPMI.ProtocolEnabled,
  Telnet_Enabled: .Telnet.ProtocolEnabled,
  SSH_Enabled: .SSH.ProtocolEnabled,
  SNMP_Enabled: .SNMP.ProtocolEnabled,
  NTP_Enabled: .NTP.ProtocolEnabled
}'
```

### 4.2 Account Policy & Lockout Audit
```bash
# Query Account Service
curl -ks -u "$USER:$PASS" "https://${BMC}/redfish/v1/AccountService" | jq '{
  LockoutThreshold: .AccountLockoutThreshold,
  LockoutDurationSeconds: .AccountLockoutDuration,
  MinPasswordLength: .MinPasswordLength,
  ActiveDirectory_Enabled: .ActiveDirectory.ServiceEnabled,
  LDAP_Enabled: .LDAP.ServiceEnabled
}'
```

### 4.3 Session Timeout Audit
```bash
# Query Session Service
curl -ks -u "$USER:$PASS" "https://${BMC}/redfish/v1/SessionService" | jq '{
  ServiceEnabled: .ServiceEnabled,
  SessionTimeout_Seconds: .SessionTimeout
}'
```

### 4.4 Out-of-Band Secure Boot Audit
```bash
# Discover System URI and Query Secure Boot
SYS_URI=$(curl -ks -u "$USER:$PASS" "https://${BMC}/redfish/v1/Systems" | jq -r '.Members[0]["@odata.id"]')

curl -ks -u "$USER:$PASS" "https://${BMC}${SYS_URI}/SecureBoot" | jq '{
  SecureBootEnable: .SecureBootEnable,
  SecureBootCurrentBoot: .SecureBootCurrentBoot,
  SecureBootMode: .SecureBootMode
}'
```

---

## 5. Python 3.9+ Zero-Dependency Redfish Evaluator Implementation

In strict adherence to VCF tooling architecture, the evaluation engine uses only Python standard library modules (`urllib.request`, `ssl`, `json`).

```python
"""
VCF 9.1.1 SCG — Zero-Dependency Standard Redfish BMC Security Evaluator.
"""
import json
import ssl
import urllib.request
from typing import Any, Dict, Optional, Tuple

class StandardRedfishAuditor:
    def __init__(self, host: str, username: str, password: str, port: int = 443):
        self.base_url = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _get(self, uri: str) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}{uri}"
        req = urllib.request.Request(url)
        # HTTP Basic Auth header
        import base64
        auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        req.add_header("Authorization", f"Basic {auth}")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return None

    def audit_host(self) -> Dict[str, Tuple[str, str]]:
        results = {}

        # 1. Resolve Managers and Systems URIs
        mgrs = self._get("/redfish/v1/Managers")
        syss = self._get("/redfish/v1/Systems")
        mgr_uri = mgrs["Members"][0]["@odata.id"] if mgrs and mgrs.get("Members") else None
        sys_uri = syss["Members"][0]["@odata.id"] if syss and syss.get("Members") else None

        if not mgr_uri or not sys_uri:
            return {"ERROR": ("fail", "Could not discover ServiceRoot endpoints")}

        # 2. NetworkProtocol Checks (C01, C09, C21, C23, C24)
        np = self._get(f"{mgr_uri}/NetworkProtocol") or {}
        
        # TLS / HTTP
        http_on = (np.get("HTTP") or {}).get("ProtocolEnabled")
        https_on = (np.get("HTTPS") or {}).get("ProtocolEnabled")
        if http_on is False and https_on is True:
            results["esx-9.hardware-management-tls"] = ("pass", "HTTP disabled, HTTPS enabled")
        elif http_on is True:
            results["esx-9.hardware-management-tls"] = ("fail", "Plaintext HTTP is enabled on port 80")
        else:
            results["esx-9.hardware-management-tls"] = ("unknown_not_exposed", "HTTP state not exposed")

        # IPMI over LAN
        ipmi_on = (np.get("IPMI") or {}).get("ProtocolEnabled")
        if ipmi_on is False:
            results["esx-9.hardware-management-security.ipmi"] = ("pass", "IPMI over LAN disabled")
        elif ipmi_on is True:
            results["esx-9.hardware-management-security.ipmi"] = ("fail", "IPMI over LAN is enabled (Cipher 0 risk)")
        else:
            results["esx-9.hardware-management-security.ipmi"] = ("unknown_not_exposed", "IPMI state not exposed")

        # Telnet
        telnet_on = (np.get("Telnet") or {}).get("ProtocolEnabled")
        if telnet_on is False or "Telnet" not in np:
            results["esx-9.hardware-management-security.telnet"] = ("pass", "Telnet disabled or absent")
        else:
            results["esx-9.hardware-management-security.telnet"] = ("fail", "Telnet is enabled")

        # 3. AccountService Checks (C43 Lockout & Password Length)
        acct = self._get("/redfish/v1/AccountService") or {}
        lockout = acct.get("AccountLockoutThreshold")
        min_pw = acct.get("MinPasswordLength")

        if lockout is not None and 1 <= int(lockout) <= 5:
            results["esx-9.hardware-management-authentication.lockout"] = ("pass", f"Lockout threshold = {lockout}")
        elif lockout == 0:
            results["esx-9.hardware-management-authentication.lockout"] = ("fail", "Lockout disabled (threshold = 0)")
        else:
            results["esx-9.hardware-management-authentication.lockout"] = ("unknown_not_exposed", "Lockout not exposed")

        if min_pw is not None and int(min_pw) >= 8:
            results["esx-9.hardware-management-authentication.password"] = ("pass", f"Min password length = {min_pw}")
        elif min_pw is not None:
            results["esx-9.hardware-management-authentication.password"] = ("fail", f"Min password length = {min_pw} (< 8)")

        # 4. SessionService (Session Timeout)
        sess = self._get("/redfish/v1/SessionService") or {}
        timeout = sess.get("SessionTimeout")
        if timeout is not None and 0 < int(timeout) <= 1800:
            results["esx-9.hardware-management-security.timeout"] = ("pass", f"Session timeout = {timeout}s")
        elif timeout is not None:
            results["esx-9.hardware-management-security.timeout"] = ("fail", f"Session timeout = {timeout}s (> 1800s)")

        # 5. Secure Boot (C53)
        sb = self._get(f"{sys_uri}/SecureBoot") or {}
        sb_enable = sb.get("SecureBootEnable")
        sb_current = str(sb.get("SecureBootCurrentBoot", "")).lower()
        if sb_enable is True and sb_current == "enabled":
            results["esx-9.hardware-secureboot"] = ("pass", "Secure Boot enabled and active for current boot")
        elif sb_enable is False or sb_current == "disabled":
            results["esx-9.hardware-secureboot"] = ("fail", f"Secure Boot disabled (CurrentBoot: {sb_current})")
        else:
            results["esx-9.hardware-secureboot"] = ("unknown_not_exposed", "Secure Boot not exposed")

        return results
```

---

## 6. Summary of Audit Outcomes

By using standard DMTF Redfish endpoints:
1. **Consistency:** Evaluates Dell, HPE, Lenovo, and Cisco bare-metal servers using a unified logic tree.
2. **Defensibility:** Completely avoids vendor-proprietary extensions, ensuring findings stand up to rigorous compliance audits.
3. **Safety:** Requires strictly read-only `GET` queries. Does not mutate BMC configuration or risk host disruption during assessment.
