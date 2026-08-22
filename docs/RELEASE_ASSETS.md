# Release Asset Verification

`tests/check_release_assets.py` is a fail-closed verifier. It does not create,
upload, modify, or publish an asset, tag, or release.

Run it after all staged assets are immutable, and repeat it against a fresh
download of every uploaded asset. The asset directory must contain only the
uploaded immutable files plus `SHA256SUMS`. The manifest covers every other
file in that directory and does not cover itself.

The verifier binds the asset set to one clean public Git commit. It checks:

- the current `HEAD`, clean worktree, and public source-hygiene gate;
- exact `BUILD_INFO.txt` fields, hosted run IDs/head SHAs/results, and the
  `SEMANTICALLY_REPRODUCIBLE` contract without a bit-reproducibility claim;
- product version and report schema against the frozen source declarations;
- every asset hash and the complete top-level asset inventory;
- the custom source archive against every tracked Git blob and executable
  mode at `HEAD`, with no links, duplicate, absolute, parent-traversal,
  untracked, missing, or misplaced members;
- root legal/notices/SBOM assets against their exact committed blobs;
- optionally, the local tag peel and its remote tag object/peeled commit; and
- one downloaded platform binary's exact `--version` metadata, using either
  native execution or one explicit runner executable.

Because the archive is byte-for-byte and mode-for-mode equal to the tracked
tree, passing the source-hygiene gate on that exact clean `HEAD` also binds the
archive to the same private-path and tracked-inventory policy.

## Custom source archive generation

Generate the reviewed archive outside the clean source worktree. Use the
full frozen commit and a single safe top-level directory:

```sh
python3 tests/create_release_source_archive.py \
  --source-root . \
  --expected-commit <full-frozen-commit> \
  --archive-root auto-refirst-<product-version> \
  --output /outside/source/tree/auto-refirst-<product-version>-source.tar.gz
```

Do not upload the direct output of `git archive`. Its member permission bits
can depend on the host Git configuration. The generator reads committed Git
blobs and modes, requires an exact clean `HEAD` and index, and emits canonical
USTAR without PAX headers. Directories use mode `0755`; regular files use
`0644` or `0755` according to the Git executable bit. Member order, owner
fields, and timestamps are fixed; the gzip header has no filename/comment and
uses the exact commit timestamp as its source-date epoch. Paths outside the
portable ASCII/USTAR boundary, links/gitlinks, unsafe names, dirty state, index
drift, and an existing or in-worktree output fail closed.

When the generator contract changes, run its isolated deterministic and
mutation suite:

```sh
python3 tests/test_release_source_archive.py
```

## BUILD_INFO.txt contract

The file is BOM-free, LF-only UTF-8. It uses the following exact field order,
one non-empty `key=value` pair per line:

```text
release_tag=v<product_version>
product_version=<SemVer product version>
public_source_commit=<full frozen Git object ID>
report_schema_version=<major.minor>
source_tree_state=CLEAN
reproducibility_contract=SEMANTICALLY_REPRODUCIBLE
bit_reproducible=false
source_archive=<safe .tar.gz filename>
source_archive_root=<single safe top-level directory>
source_archive_sha256=<lowercase SHA-256>
linux_artifact=<safe filename>
linux_sha256=<lowercase SHA-256>
linux_build_platform=Linux/x86_64
linux_toolchain=<compiler and version>
linux_cmake_version=<CMake version>
linux_build_flags=<semicolon-separated flags including AUTO_REFIRST_WARNINGS_AS_ERRORS=ON>
linux_hosted_run_id=<positive decimal GitHub Actions run ID>
linux_hosted_head_sha=<full frozen Git object ID>
linux_hosted_result=PASS
windows_artifact=<safe filename>
windows_sha256=<lowercase SHA-256>
windows_build_platform=Windows/AMD64
windows_toolchain=<compiler and version>
windows_cmake_version=<CMake version>
windows_build_flags=<semicolon-separated flags including AUTO_REFIRST_WARNINGS_AS_ERRORS=ON>
windows_hosted_run_id=<positive decimal GitHub Actions run ID>
windows_hosted_head_sha=<full frozen Git object ID>
windows_hosted_result=PASS
sanitizer_hosted_run_id=<positive decimal GitHub Actions run ID>
sanitizer_hosted_head_sha=<full frozen Git object ID>
sanitizer_hosted_result=PASS
```

Do not record `PASS` until the hosted run completed successfully at the exact
frozen commit. Generate `SHA256SUMS` only after `BUILD_INFO.txt` and every
other uploaded file are final; its rows are lowercase, filename-sorted lines
of `<sha256><two spaces><safe basename>`.

## Verification commands

Run once per platform so both downloaded binaries are executed. Use
`--native-binary` on the matching native host:

```sh
python3 tests/check_release_assets.py \
  --source-root . \
  --asset-dir /path/to/fresh-assets \
  --expected-commit <full-frozen-commit> \
  --platform linux \
  --native-binary \
  --check-tag \
  --remote origin
```

For a compatibility runner, pass its executable as a separate, explicit
argument instead of asking the verifier to infer the execution environment:

```sh
python3 tests/check_release_assets.py \
  --source-root . \
  --asset-dir /path/to/fresh-assets \
  --expected-commit <full-frozen-commit> \
  --platform windows \
  --binary-runner /path/to/wine64 \
  --check-tag \
  --remote origin
```

Omit `--check-tag` only before a tag exists. If tag checking is enabled, any
missing, stale, malformed, or local/remote mismatch is fatal. The final
pre-publication and download-back gates must enable it.

Run the isolated negative suite when this contract changes:

```sh
python3 tests/test_release_assets.py
```
