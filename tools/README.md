# Developer & Quality Tools (`tools/`)

> Quality assurance and data hygiene utilities for the VCF Readiness Assessment Tool.

---

## Utility Index

### `tools/check_data_hygiene.py`
- **Purpose:** Deterministic scanner enforcing Customer-Facing Data Hygiene by checking files for internal corporate hostnames, private lab IPs, and internal repository paths.
- **Usage:**
  ```bash
  python tools/check_data_hygiene.py
  ```
- **Exit Status:**
  - `0`: All files clean.
  - `1`: Violations found (printed with file, line number, pattern, and remediation advice).
