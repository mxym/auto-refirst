# Contributing to auto-refirst

Contributions are accepted under Apache-2.0 unless explicitly agreed otherwise in writing. By submitting a contribution, you represent that you have the right to license it on those terms.

## Engineering requirements

Changes to detection, parsing, extraction, runtime analysis, or guidance should include:

- structural or semantic positive evidence;
- malformed/mutation cases that exercise failure boundaries;
- negative or bait cases that prevent marker/name/string-only promotion;
- explicit attacker-controlled resource bounds for size, count, depth, recursion, or runtime;
- stable JSON/text reporting for the same underlying evidence model.

Product logic must not depend on challenge names, known sample hashes, local fixture paths, flag strings, or other sample identities. Evidence gates should generalize across independently sourced inputs.

## Fixtures and third-party material

Prefer source-generated fixtures. A committed binary fixture must record its source or generator, toolchain version, license/redistribution basis, rebuild command, and SHA-256 in `tests/corpus/PROVENANCE.csv`.

Do not submit credentials, personal data, private customer files, copyrighted challenge attachments without redistribution rights, or third-party source with removed notices.

## Safety contracts

- Static analysis is the default and does not execute the target.
- Target execution requires explicit `--run` authorization.
- Replacement/install requires explicit `--apply` authorization and the implemented validation gates.
- Recursive materialization remains bounded, path-safe, symlink/reparse-safe, and deduplicated.

## Before opening a pull request

Run the relevant focused tests plus the public gate:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
python3 tests/run_public_regression.py --binary build/auto-refirst --tier all
git diff --check
```

Security vulnerabilities should follow `SECURITY.md` instead of a public issue.
