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
python3 redfish_collector.py --targets <IP> ...
```

(Replace credentials with `***` before posting.)

## Expected Behavior

What did you expect the tool to do or report?

## Actual Behavior

What happened instead? Paste the relevant output or error traceback here.

```
(paste output here)
```

## Redfish Capture (Optional but Very Helpful)

If the bug involves incorrect data from a specific BMC, a Redfish dump helps enormously.
Run the bundled dump tool:

```bash
python tools/redfishMockupCreate.py -r <BMC_IP> -u <USER> -p <PASS> -D samples/<vendor>
```

Attach the resulting `.zip` file (scrub any sensitive data first).

## Additional Context

Any other context — firewall rules, VPN, non-default BMC port, etc.
