# Pull Request

## Summary

<!-- 1-3 bullet points describing the change -->

- 

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New OEM support (adds a new vendor collector)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] Documentation / tests only

## Testing

- [ ] `python -m pytest` passes locally
- [ ] `python -m ruff check .` passes locally
- [ ] `python tools/check_data_hygiene.py` passes locally
- [ ] `python tools/bundle_docs.py --check` passes locally (when docs are affected)
- [ ] New tests added for new code (or explain why tests are not needed)
- [ ] Hardware-dependent behavior uses sanitized, minimal test data (or explain validation)

## OEM Support Checklist (if adding a new vendor)

- [ ] New file in `vcf_hci/collector/oem/<vendor>.py`
- [ ] `VENDOR_MATCH` tuple set correctly
- [ ] Only non-default hooks overridden
- [ ] Registered in `vcf_hci/collector/oem/__init__.py` `_REGISTRY`
- [ ] Focused test added
- [ ] No unsanitized Redfish capture, credential, or customer identifier committed
- [ ] OEM behavior documented where users or maintainers need it

## Compat Engine Checklist (if changing rules)

- [ ] Unit test added for each new verdict path
- [ ] VCF 9.x KB/release notes link provided in PR description

## Zero-Dependency Check

- [ ] No new imports outside Python 3.9+ stdlib in `vcf_hci/` package code

## Related Issues

Closes #
