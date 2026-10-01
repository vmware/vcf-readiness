---
name: OEM Support Request
about: Request support for a BMC controller not yet covered by the tool
title: "[OEM] Add support for <Vendor> <Model>"
labels: oem-support, enhancement
assignees: ""
---

## Server / BMC Details

- **Server make / model**: e.g. "Lenovo ThinkSystem SR650 V3"
- **BMC name / firmware**: e.g. "Lenovo XClarity Controller v8.90"
- **Redfish version** (from `/redfish/v1`):

## What Works Today

Describe what the tool currently does with this hardware (wrong data, missing sections, crashes, etc.).

## Redfish Capture (Required)

A Redfish dump is required for us to implement support without physical hardware.

```bash
python tools/redfishMockupCreate.py -r <BMC_IP> -u <USER> -p <PASS> -D samples/<vendor>
```

Attach the resulting `.zip` to this issue. **Scrub all sensitive data** (credentials, IPs, serial numbers) before posting.

At minimum, we need the responses from:
- `/redfish/v1`
- `/redfish/v1/Systems` and `/redfish/v1/Systems/{id}`
- `/redfish/v1/Systems/{id}/Storage`
- `/redfish/v1/Chassis/{id}/NetworkAdapters`
- `/redfish/v1/Managers/{id}`

## OEM-Specific Behavior (if known)

Describe any known non-standard Redfish behavior for this BMC — unusual endpoint paths, OEM JSON fields, authentication quirks, etc.

## Additional Context

VCF version, network topology, any other relevant information.
