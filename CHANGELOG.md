# Changelog

## [0.1.0-alpha.1] - 2026-08-20

Initial public alpha.

### Highlights

- Evidence-driven static preprocessing across native executables, bytecode, managed runtimes, containers, and game/runtime ecosystems.
- Recursive artifact materialization with provenance, deduplication, path safety, and hard resource budgets.
- Directory-scale ranking and relationship guidance with bounded JSON/report output.
- Opt-in runtime tracing/materialization/reconstruction on supported host backends.
- Explicit `--apply` authorization for validated transactional installation.
- Public Linux/Windows builds, source-backed fixtures, sanitizer surface, and provenance/license bundle.

### Safety

- Deprecated `--run=unpack` is non-destructive by default. `--apply` is required for validated installation.

### Known limitations

See `docs/VALIDATION.md` and `docs/CAPABILITIES.md` for externally observed gaps and unsupported scopes.
