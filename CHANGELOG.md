# Changelog

## [Unreleased]

### Added

- Add bounded static recognition for Hermes HBC v89/v96/v98, including exact APK content-child routing; JavaScript source recovery and runtime loading are not claimed.
- Add Unreal Pak/IoStore container framing, integrity metadata and UTOC/UCAS pair relationships without claiming decrypted asset semantics or signature verification.
- Add .NET single-file bundle and Linux NativeAOT structural metadata, plus bounded Mach-O Swift metadata inventories and validated direct record closures.
- Add APK JNI exported-name and `RegisterNatives` relationship evidence with strict JNI modified UTF-8 handling.
- Add a disabled-by-default experimental Linux de4dotEx sidecar adapter source/manifest; no third-party binary is bundled and its status remains `PARTIAL`.

### Changed

- Extend source-generated public P0/P1 gates for Hermes/APK, Mach-O/Swift, .NET bundle/NativeAOT, Unreal containers and the CLI exit-code contract.
- Add a project-owned source-backed APK/JNI J0-J4 structural-relation fixture to the static-only public P0 gate.
- Keep semantic confidence fail-closed: encrypted/unsupported layouts remain `PARTIAL`, structural relations do not become native-registration or source-recovery claims, and analyzed fixtures are never executed.

### Fixed

- Preserve Unicode JNI matching on MSVC and keep J4 `RegisterNatives` matching reachable for non-ASCII class and member names.
- Make input-open failures follow the documented input-error exit contract while retaining empty files as valid inputs.

## [0.1.0-rc.1] - 2026-08-22

First release candidate for exact-commit public validation. This entry describes candidate source changes; publication remains subject to the hosted CI and release-asset gates in `docs/RELEASE_CHECKLIST.md`.

### Added

- Add independent product/build/report-schema identity, including exact clean-source commit binding and archive fallback rules.
- Extend bounded delivery and relationship support for Unity IL2CPP and Flutter APKs, Godot legacy PCK/GDScript/GDExtension variants, and Go 1.26 pclntab layouts.

### Changed

- Define the stable `0/1/2/3/4` CLI process contract while keeping findings, partial analysis, bounded refusal, and runtime observations separate from process failure.
- Require explicit `--run` for target execution and the additional `--apply` authorization for validated transactional installation.
- Add exact-source public gates for Linux GCC/Clang, GCC ASan+UBSan, native MSVC, strict warnings, P0/P1, provenance, and install staging.

### Fixed

- Correct Lua 5.3 long-string decoding when the chunk uses the `0xff` marker followed by a full `size_t` length. The previous parser truncated that extended length to one byte and could reject otherwise valid chunks.

### Maintenance

- Add a maintainer release checklist covering provenance, clean builds, public and sanitizer gates, authorization/resource invariants, hosted CI, packaging, and post-publication verification.
- Bind compiled dependency declarations to exact committed/index/worktree vendored snapshots and add fail-closed mutation coverage.

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
