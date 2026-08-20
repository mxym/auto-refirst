# Release Checklist

This checklist defines the public release verification flow for auto-refirst.

## Source and provenance

- Verify the release commit is the intended public commit.
- Verify no private development material, internal audit records, or non-redistributable fixtures are included.
- Verify new fixtures have documented source, redistribution basis, generator or acquisition path, and SHA-256.

## Build reproducibility

- Build Linux release artifacts from a clean checkout.
- Build Windows release artifacts from a clean checkout.
- Record compiler, CMake, dependency, and commit information in release metadata.
- Verify generated artifacts match the published SHA-256 manifest.

## Regression verification

- Run public regression tests across supported static analysis formats.
- Run malformed-input sanitizer coverage.
- Verify directory orchestration and resource limits.
- Verify runtime authorization boundaries:
  - analysis remains static by default;
  - execution requires explicit authorization;
  - installation or writeback requires explicit apply authorization.

## Documentation

- Update capability and limitation documentation when behavior changes.
- Update changelog entries for user-visible changes.
- Review examples and commands against the current CLI behavior.

## Release publication

- Publish source and binary assets together with hashes.
- Verify downloaded release assets using the published checksum file.
- Keep public history limited to reviewable release changes.
