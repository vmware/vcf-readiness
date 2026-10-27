# Contributing

This public source export includes synthetic smoke tests and the stdlib-only
runtime. Use Python 3.9 or newer. Runtime code requires no pip dependencies.

For test-only tooling, install a compatible pytest version in a development
virtual environment, then run `python -m pytest tests/ -q` and
`python tools/check_data_hygiene.py`. The public CI definition uses reviewed
pytest and Ruff pins independently of the private development workflow.

Do not add runtime dependencies or include customer captures, credentials,
internal hostnames or other identifying data in contributions. Keep collection
read-only, use defensive JSON parsing, and preserve Python 3.9 compatibility.
Report the affected behavior, test results and any skipped platform checks in a
pull request. Development-only release and fixture tooling is maintained in the
source development repository and is deliberately excluded from this export.
