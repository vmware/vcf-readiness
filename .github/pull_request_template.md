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

- [ ] `python -m pytest tests/ -v` passes locally
- [ ] New tests added for new code (or explain why tests are not needed)
- [ ] Tested against real hardware (or describe mock/fixture approach)

## OEM Support Checklist (if adding a new vendor)

- [ ] New file in `vcf_hci/collector/oem/<vendor>.py`
- [ ] `VENDOR_MATCH` tuple set correctly
- [ ] Only non-default hooks overridden
- [ ] Registered in `vcf_hci/collector/oem/__init__.py` `_REGISTRY`
- [ ] Test class added to `tests/test_collector_oem.py` or new test file
- [ ] Redfish capture added to `samples/<vendor>/` (scrubbed of credentials)
- [ ] OEM quirks documented in `ARCHITECTURE.md` section 9

## Compat Engine Checklist (if changing rules)

- [ ] Unit test added for each new verdict path
- [ ] VCF 9.x KB/release notes link provided in PR description

## Zero-Dependency Check

- [ ] No new imports outside Python 3.9+ stdlib in `vcf_hci/` package code

## Related Issues

Closes #
