# Contributing

VCF Readiness supports Python 3.9+ and keeps runtime code in the Python standard library. Read [AGENTS.md](AGENTS.md) before changing code, security behavior, or generated files.

## Set up a development checkout

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
python -m pip install -e '.[dev]'
```

Running from source does not require installation. The editable install above is only for the declared development tools.

Verify the entry points:

```bash
python vcfr_collector.py --help
python -m vcf_hci.web --help
```

## Canonical checks

Run these before opening a pull request:

```bash
python -m pytest
python -m ruff check .
python tools/check_data_hygiene.py
python tools/bundle_docs.py --check
```

Documentation-only changes should also run:

```bash
python -m pytest tests/test_docs_contract.py
```

Tests must remain offline unless explicitly marked and documented otherwise. Never point tests at a real BMC.

## Engineering rules

- Use Python 3.9-compatible syntax. Do not use `X | Y` type unions.
- Add no runtime dependency outside the standard library.
- Preserve strict read-only collection. Do not add BMC configuration changes, actions, resets, firmware updates, or power operations.
- Make public-network access an explicit operator choice. Normal scans must remain offline except for operator-selected BMC targets.
- Do not log credentials or commit customer identifiers, internal hostnames, private addresses, raw production captures, or generated reports.
- Use defensive parsing for incomplete and vendor-specific Redfish responses.
- Sanitize values used in filenames.
- Update tests and user documentation when changing a public option, path, output, or security property.

## Documentation and generated files

The embedded help portal is generated from a fixed whitelist in `tools/bundle_docs.py`.

After changing a whitelisted document:

```bash
python tools/bundle_docs.py
python tools/bundle_docs.py --check
```

Commit `vcf_hci/web/docs_data.py` with its source changes. Do not edit it directly. A second generator run must leave the worktree unchanged.

`vcf_hci/web/assets.py` is also generated and must not be hand-edited. This checkout does not include a script that regenerates it.

Documentation claims are contracts:

- Every repository-relative path must exist.
- Every documented CLI option must appear in the corresponding `--help`.
- Do not promise binaries, release assets, scripts, fixtures, or tools that are absent from the checkout.
- Use RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`) and approved example domains.

## Changing collectors or compatibility rules

Keep generic DMTF behavior in the shared collector code and vendor deviations in `vcf_hci/collector/oem/`. Add the smallest focused test that demonstrates the response shape and expected normalized value.

Compatibility changes belong in `vcf_hci/compat/` or `vcf_hci/security/`. Cite the governing public source in the pull request and test each changed verdict path.

Do not request or commit an unsanitized Redfish capture. If hardware evidence is needed, provide the minimum scrubbed JSON shape directly in a focused test.

## Pull requests

Keep each pull request reviewable:

1. Explain the user-visible or security-visible change.
2. Identify affected entry points and outputs.
3. Include focused regression tests.
4. Report the canonical check results.
5. Call out any check that could not run and why.

Use the repository pull request template. Never include passwords, tokens, private keys, customer data, or internal infrastructure details.
