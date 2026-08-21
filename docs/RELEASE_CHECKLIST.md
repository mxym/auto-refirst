# Release Checklist

This checklist is the maintainer gate for public auto-refirst prereleases and releases. It complements the public CI workflows; a local build alone is not a release gate.

## 1. Freeze the candidate

- [ ] Record the exact candidate commit and confirm the worktree is clean.
- [ ] Allow only release-blocker fixes after the freeze begins.
- [ ] Run `git diff --check` and verify the release version/changelog are intentional.
- [ ] Confirm the public tree contains no private development history, internal audit/collaboration material, credentials, private paths, or non-redistributable fixtures.

## 2. Provenance and supply chain

- [ ] Revalidate `tests/corpus/PROVENANCE.csv`: every tracked fixture has a documented source/rights basis and matching SHA-256.
- [ ] Review all newly added fixtures and generated references for source, version/revision, redistribution basis, generator/acquisition path, transformations, and hash.
- [ ] Reconcile `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSES/`, `docs/PROVENANCE.md`, and `SBOM.spdx.json` with the bytes actually shipped.
- [ ] Review dependency/revision changes explicitly; do not silently substitute vendored sources during packaging.

## 3. Clean builds

From a clean checkout of the frozen commit:

- [ ] Build Linux x86-64 Release with the supported public toolchain.
- [ ] Build Windows x64 Release with MSVC on the hosted Windows gate.
- [ ] Run the documented Zig Windows cross-build as an additional portability check when the maintainer toolchain is available.
- [ ] Record commit, compiler/toolchain, CMake version, platform, and relevant build flags in release metadata.
- [ ] Verify `auto-refirst --version` reports the intended release version on both release binaries.

## 4. Public regression gates

- [ ] `python3 tests/run_public_regression.py --binary <binary> --tier all` passes.
- [ ] `python3 tests/test_bounded_directory_output.py <binary>` passes.
- [ ] `python3 tests/test_directory_orchestration.py <binary>` passes.
- [ ] `python3 tests/test_runtime_authorization.py <binary>` passes.
- [ ] The malformed-input ASan+UBSan target and sanitizer smoke suite pass.
- [ ] Static P0/P1 tests do not execute analyzed targets.

For changes touching an ecosystem/parser, run its focused positive, mutation/corruption, and bait/negative coverage in addition to the public gate.

## 5. Safety and resource invariants

- [ ] Default analysis remains static-only.
- [ ] Target execution still requires explicit `--run` authorization.
- [ ] Installation/writeback still requires explicit `--apply` plus the implemented validation/rollback gates.
- [ ] Extraction and directory traversal preserve path, symlink/reparse, depth, count, byte, spool, and artifact bounds.
- [ ] New attacker-controlled sizes/counts/depths/time budgets fail closed or report `PARTIAL`/refusal rather than silently weakening evidence.

## 6. Extended maintainer evidence

For an RC/final candidate, not every routine patch:

- [ ] Run the retained maintainer-only regression corpus without copying private/non-redistributable bytes into the public tree or release assets.
- [ ] Re-run the current frozen external holdout/maturity checks when a change can affect ranking, evidence promotion, resource behavior, or broad parser/orchestration behavior.
- [ ] Compare resource ceilings and externally validated capability claims with `docs/VALIDATION.md`; investigate regressions before release.

## 7. Hosted CI on the frozen commit

- [ ] GitHub Linux public CI passes on the exact candidate commit.
- [ ] GitHub ASan+UBSan malformed-static CI passes on the exact candidate commit.
- [ ] GitHub Windows-2022/MSVC CI passes on the exact candidate commit.
- [ ] A skipped, cancelled, billing-blocked, or never-started job is not recorded as PASS.

## 8. Documentation and public contract

- [ ] `README.md` and `README_EN.md` agree on version, safety, supported targets, capabilities, and limitations.
- [ ] `docs/CAPABILITIES.md`, `docs/VALIDATION.md`, `docs/CLI.md`, and `docs/BUILD.md` match implemented behavior.
- [ ] `CHANGELOG.md` records user-visible fixes, compatibility changes, and known release limitations.
- [ ] New claims are backed by reproducible evidence and do not generalize beyond the tested mechanism/version/layout boundary.

## 9. Package and publish

- [ ] Build final release assets from the frozen commit; do not reuse intermediate development binaries.
- [ ] Include Linux and Windows binaries, `SHA256SUMS`, build metadata, license/notices, and the release SBOM.
- [ ] Generate checksums only after assets are immutable.
- [ ] Verify the uploaded assets by downloading them from the published release and running the published checksum manifest against those downloaded bytes.
- [ ] Confirm the release tag resolves to the intended public commit and that prerelease/stable status is intentional.

## 10. Post-publication check

- [ ] Reconfirm the public default branch is clean and contains only intended public history.
- [ ] Reconfirm release downloads, documentation links, security-reporting path, and issue templates are usable.
- [ ] Keep private research/history and maintainer-only fixtures outside the public repository.
