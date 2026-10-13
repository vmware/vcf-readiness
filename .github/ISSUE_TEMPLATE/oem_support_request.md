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

## Sanitized Redfish Evidence

Provide the smallest JSON excerpts that show the missing or vendor-specific
fields. Do not attach an unreviewed full capture. Remove credentials, tokens,
IPs, hostnames, serial numbers, MAC addresses, asset tags, and customer
identifiers before posting.

Useful endpoint shapes often include:
- `/redfish/v1`
- `/redfish/v1/Systems` and `/redfish/v1/Systems/{id}`
- `/redfish/v1/Systems/{id}/Storage`
- `/redfish/v1/Chassis/{id}/NetworkAdapters`
- `/redfish/v1/Managers/{id}`

## OEM-Specific Behavior (if known)

Describe any known non-standard Redfish behavior for this BMC — unusual endpoint paths, OEM JSON fields, authentication quirks, etc.

## Additional Context

VCF version, network topology, any other relevant information.
