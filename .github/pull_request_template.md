## Summary

Describe the user-visible problem and the general solution.

## Evidence model

- Positive structural/semantic evidence:
- Mutation/corruption coverage:
- Negative/bait coverage:
- Resource bounds affected:

## Tests

- [ ] Relevant focused tests pass.
- [ ] `python3 tests/run_public_regression.py --binary <build>/auto-refirst --tier all` passes.
- [ ] `git diff --check` passes.

## Fixture / provenance

- [ ] No new opaque fixture was added, or its generator/source, version, license/rights basis, rebuild command, and SHA-256 are documented.
- [ ] No private sample, credential, personal data, or non-redistributable challenge attachment is included.

## Safety

- [ ] Static analysis still does not execute target code.
- [ ] Execution still requires explicit `--run`.
- [ ] Install/writeback still requires explicit `--apply` and validation.
- [ ] Filesystem and resource bounds are unchanged or strengthened.
