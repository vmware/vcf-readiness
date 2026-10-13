---
name: Bug Report
about: A crash, incorrect data, or wrong compatibility verdict
title: "[BUG] "
labels: bug
assignees: ""
---

## Describe the Bug

A clear and concise description of what went wrong.

## Environment

- **Tool version** (from `--version` or the HTML report footer):
- **Python version** (`python3 --version`):
- **OS**: macOS / Windows / Linux
- **BMC vendor / model**: e.g. "Dell PowerEdge R750 / iDRAC 9"
- **BMC firmware version** (if known):

## Command Used

```bash
python3 vcfr_collector.py --targets <IP> ...
```

(Replace credentials with `***` before posting.)

## Expected Behavior

What did you expect the tool to do or report?

## Actual Behavior

What happened instead? Paste the relevant output or error traceback here.

```
(paste output here)
```

## Diagnostic Data (Optional)

Provide the smallest sanitized JSON excerpt needed to demonstrate an incorrect
field. Do not attach an unreviewed Redfish dump or report. Remove credentials,
tokens, IPs, hostnames, serial numbers, MAC addresses, asset tags, and customer
identifiers before posting.

## Additional Context

Any other context — firewall rules, VPN, non-default BMC port, etc.
