# Release Checklist

This checklist is the maintainer gate for public auto-refirst prereleases and releases. It complements the public CI workflows; a local build alone is not a release gate.

## 1. Freeze the candidate

- [ ] Record the exact candidate commit and confirm the worktree is clean.
- [ ] Allow only release-blocker fixes after the freeze begins.
- [ ] Run `git diff --check` and verify the release version/changelog are intentional.
- [ ] Confirm the public tree contains no private development history, internal audit/collaboration material, credentials, private paths, or non-redistributable fixtures.

## 2. Provenance and supply chain

- [ ] Revalidate `tests/corpus/PROVENANCE.csv`: every tracked fixture has a documented source/rights basis and matching SHA-256.
- [ ] `python3 tests/check_third_party_provenance.py` passes and reconciles compiled/reference rows with CMake, vendored roots, license files, notices, the SBOM, and the committed/worktree digests in `docs/VENDORED_SNAPSHOT_MANIFEST.json`.
- [ ] Review all newly added fixtures and generated references for source, version/revision, redistribution basis, generator/acquisition path, transformations, and hash.
- [ ] Reconcile `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSES/`, `docs/PROVENANCE.md`, and `SBOM.spdx.json` with the bytes actually shipped.
- [ ] Review dependency/revision changes explicitly; do not silently substitute vendored sources during packaging.

## 3. Clean builds

From a clean checkout of the frozen commit:

- [ ] Build Linux x86-64 Release with the supported public toolchain.
- [ ] Build Windows x64 Release with MSVC on the hosted Windows gate.
- [ ] Configure release builds with `AUTO_REFIRST_WARNINGS_AS_ERRORS=ON`; warning-free compilation is required for project-owned targets.
- [ ] Run the documented Zig Windows cross-build as an additional portability check when the maintainer toolchain is available.
- [ ] Record commit, compiler/toolchain, CMake version, platform, and relevant build flags in release metadata.
- [ ] Verify `auto-refirst --version` reports the intended release version on both release binaries.
- [ ] `cmake --build <build-dir> --target auto_refirst_public_install_stage_check` passes for each native release build.

## 4. Public regression gates

- [ ] `python3 tests/check_workflow_contract.py --self-test --require-clean-worktree` passes and confirms the required jobs, exact-source binding, install staging, sanitizer, and static-only P0/P1 steps remain wired into the public workflows.
- [ ] `python3 tests/run_public_regression.py --binary <binary> --tier all --require-clean-source` passes and binds the binary to the exact clean candidate commit.
- [ ] `python3 tests/test_build_metadata_source_root.py` passes for archive/source-root isolation and full-length fallback identities.
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
- [ ] If merging, rebasing, or squashing a release PR changes the commit, repeat every exact-commit gate on the resulting public commit; results for the former PR head do not transfer.

## 8. Documentation and public contract

- [ ] `README.md` and `README_EN.md` agree on version, safety, supported targets, capabilities, and limitations.
- [ ] `docs/CAPABILITIES.md`, `docs/VALIDATION.md`, `docs/CLI.md`, and `docs/BUILD.md` match implemented behavior.
- [ ] `CHANGELOG.md` records user-visible fixes, compatibility changes, and known release limitations.
- [ ] New claims are backed by reproducible evidence and do not generalize beyond the tested mechanism/version/layout boundary.

## 9. Package and publish

- [ ] Build final release assets from the frozen commit; do not reuse intermediate development binaries.
- [ ] Run `python3 tests/test_release_source_archive.py`, then create the custom source archive from the frozen public commit with `tests/create_release_source_archive.py` as documented in `docs/RELEASE_ASSETS.md`. Give it a stable release filename and exclude `.git`, ignored build output, private paths/material, and maintainer-only fixtures; do not substitute direct `git archive` output or GitHub's automatically generated archive for this reviewed asset.
- [ ] Include Linux and Windows binaries/packages, the custom source archive, `BUILD_INFO.txt`, `SHA256SUMS`, license/notices, the release SBOM, and any other declared immutable release asset.
- [ ] Record in `BUILD_INFO.txt` at minimum: release tag/version, exact public source commit, report schema, clean-source state, platform artifact names and SHA-256 values, compiler/toolchain and CMake versions, relevant build flags including warnings-as-errors, exact hosted run IDs and head SHA/results, and the `SEMANTICALLY_REPRODUCIBLE` contract without a bit-reproducibility claim. Do not record a gate as PASS before its exact hosted run completes successfully.
- [ ] After every other uploaded asset is immutable, generate `SHA256SUMS` so it covers every uploaded immutable asset except the manifest itself.
- [ ] Follow `docs/RELEASE_ASSETS.md` and run `tests/check_release_assets.py` once per platform against the complete staged asset directory. Both platform binaries' exact `--version` metadata must pass through native execution or an explicit runner.
- [ ] Unpack the custom source archive in a fresh directory and re-run public/private-path and inventory hygiene checks. Without adding a `.git` directory, configure/build it with the exact full source commit supplied through `AUTO_REFIRST_SOURCE_COMMIT`, then verify the archive binary's `--version` identity.
- [ ] Verify the release tag's peeled commit (`refs/tags/<tag>^{}`), not only its name or `targetCommitish`, equals the frozen public commit and that prerelease/stable status is intentional.
- [ ] Download every published asset into a fresh directory and verify `SHA256SUMS` against those downloaded bytes.
- [ ] Re-run `tests/check_release_assets.py` once per platform against that fresh download with local/remote tag checking enabled; staged-directory results do not substitute for download-back verification.
- [ ] From the downloaded assets, re-run both platform binaries' `--version` checks (natively or through the documented compatibility runner), unpack each binary package and check its expected executable/legal-file inventory, and unpack the source archive to repeat the source hygiene and archive build/fallback checks.

## 10. Post-publication check

- [ ] Reconfirm the public default branch is clean and contains only intended public history.
- [ ] Reconfirm release downloads, documentation links, security-reporting path, and issue templates are usable.
- [ ] Keep private research/history and maintainer-only fixtures outside the public repository.
