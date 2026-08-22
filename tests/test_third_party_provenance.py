#!/usr/bin/env python3
"""Isolated mutation negatives for the public third-party provenance gate."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
from collections.abc import Callable


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = pathlib.Path(__file__).with_name("check_third_party_provenance.py")


def git(root: pathlib.Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")
        raise AssertionError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def write_text(path: pathlib.Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def commit_all(root: pathlib.Path, message: str) -> None:
    git(root, "add", "-A")
    commit_index(root, message)


def commit_index(root: pathlib.Path, message: str) -> None:
    git(
        root,
        "-c", "user.name=Public Provenance Test",
        "-c", "user.email=provenance@example.invalid",
        "commit", "-qm", message,
    )


def clone(source: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    completed = subprocess.run(
        ["git", "clone", "--no-local", "-q", str(source), str(destination)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")
        raise AssertionError(f"fixture clone failed: {detail}")
    return destination


def invoke(root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )


def replace_once(root: pathlib.Path, relative: str, before: str, after: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if text.count(before) != 1:
        raise AssertionError(f"fixture mutation expected one match in {relative}: {before!r}")
    write_text(path, text.replace(before, after, 1))


def update_json(root: pathlib.Path, relative: str, mutate: Callable[[dict[str, object]], None]) -> None:
    path = root / relative
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    write_text(path, json.dumps(document, indent=2, ensure_ascii=False) + "\n")


def mutate_legacy_noassertion(root: pathlib.Path) -> None:
    replace_once(
        root,
        "docs/THIRD_PARTY_PROVENANCE.csv",
        '"NOASSERTION","","","src/reference/pyinstaller_loader_refs.inc',
        '"NOASSERTION_REFERENCE_ONLY","","","src/reference/pyinstaller_loader_refs.inc',
    )
    commit_all(root, "mutation: legacy NOASSERTION sentinel")


def mutate_compiled_noassertion(root: pathlib.Path) -> None:
    replace_once(
        root,
        "docs/THIRD_PARTY_PROVENANCE.csv",
        '"BSD-2-Clause","LICENSES/libPeConv-BSD-2-Clause.txt',
        '"NOASSERTION","LICENSES/libPeConv-BSD-2-Clause.txt',
    )
    commit_all(root, "mutation: compiled NOASSERTION")


def mutate_missing_reference_notice(root: pathlib.Path) -> None:
    path = root / "THIRD_PARTY_NOTICES.md"
    lines = path.read_text(encoding="utf-8").splitlines()
    filtered = [line for line in lines if not line.startswith("- Godot —")]
    if len(filtered) + 1 != len(lines):
        raise AssertionError("Godot reference notice mutation did not remove exactly one line")
    write_text(path, "\n".join(filtered) + "\n")
    commit_all(root, "mutation: missing reference notice")


def manifest_component(document: dict[str, object], component_id: str) -> dict[str, object]:
    components = document["components"]
    assert isinstance(components, list)
    component = next(item for item in components if isinstance(item, dict) and item.get("component_id") == component_id)
    return component


def mutate_manifest_identity(root: pathlib.Path) -> None:
    update_json(
        root,
        "docs/VENDORED_SNAPSHOT_MANIFEST.json",
        lambda document: manifest_component(document, "zydis").update(declared_upstream_tag="4.1.2"),
    )
    commit_all(root, "mutation: manifest identity")


def mutate_manifest_digest(root: pathlib.Path) -> None:
    update_json(
        root,
        "docs/VENDORED_SNAPSHOT_MANIFEST.json",
        lambda document: manifest_component(document, "tiny-aes-c").update(tree_sha256="f" * 64),
    )
    commit_all(root, "mutation: manifest digest")


def mutate_duplicate_root_manifest_file_set(root: pathlib.Path) -> None:
    def reduce_file_set(document: dict[str, object]) -> None:
        component = manifest_component(document, "zycore-c")
        tracked_files = component["tracked_files"]
        assert isinstance(tracked_files, list) and len(tracked_files) == 3
        component["tracked_files"] = tracked_files[:2]

    update_json(root, "docs/VENDORED_SNAPSHOT_MANIFEST.json", reduce_file_set)
    commit_all(root, "mutation: duplicate root manifest file set")


def mutate_manifest_scope(root: pathlib.Path) -> None:
    def overstate(document: dict[str, object]) -> None:
        document["scope"] = "Independently authenticates every upstream source revision."

    update_json(root, "docs/VENDORED_SNAPSHOT_MANIFEST.json", overstate)
    commit_all(root, "mutation: manifest scope overclaim")


def mutate_sbom_identity(root: pathlib.Path) -> None:
    def change(document: dict[str, object]) -> None:
        packages = document["packages"]
        assert isinstance(packages, list)
        package = next(item for item in packages if isinstance(item, dict) and item.get("name") == "libPeConv")
        package["versionInfo"] = "1" * 40

    update_json(root, "SBOM.spdx.json", change)
    commit_all(root, "mutation: SBOM identity")


def mutate_cmake_anchor(root: pathlib.Path) -> None:
    replace_once(
        root,
        "CMakeLists.txt",
        "third_party/tiny_aes/aes.c",
        "third_party/tiny_aes/aes-missing.c",
    )
    commit_all(root, "mutation: CMake anchor")


def mutate_committed_vendor(root: pathlib.Path) -> None:
    path = root / "third_party/tiny_aes/aes.c"
    with path.open("ab") as handle:
        handle.write(b"\n/* committed provenance mutation */\n")
    commit_all(root, "mutation: committed vendor bytes")


def mutate_added_vendor(root: pathlib.Path) -> None:
    write_text(root / "third_party/tiny_aes/EXTRA.txt", "undeclared vendored file\n")
    commit_all(root, "mutation: added vendor file")


def mutate_missing_vendor(root: pathlib.Path) -> None:
    git(root, "rm", "-q", "--", "third_party/tiny_aes/aes.h")
    commit_index(root, "mutation: missing vendor file")


def mutate_vendor_symlink(root: pathlib.Path) -> None:
    oid = git(root, "hash-object", "-w", "--stdin", input_bytes=b"../outside").decode("ascii").strip()
    git(
        root,
        "update-index", "--add", "--cacheinfo",
        f"120000,{oid},third_party/tiny_aes/escape-link",
    )
    commit_index(root, "mutation: vendored symlink")


def mutate_vendor_gitlink(root: pathlib.Path) -> None:
    head = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    git(
        root,
        "update-index", "--add", "--cacheinfo",
        f"160000,{head},third_party/tiny_aes/escape-submodule",
    )
    commit_index(root, "mutation: vendored gitlink")


def mutate_worktree_vendor(root: pathlib.Path) -> None:
    path = root / "third_party/tiny_aes/aes.c"
    with path.open("ab") as handle:
        handle.write(b"\n/* worktree-only provenance mutation */\n")


def mutate_staged_only_vendor(root: pathlib.Path) -> None:
    path = root / "third_party/tiny_aes/aes.c"
    original = path.read_bytes()
    path.write_bytes(original + b"\n/* staged-only provenance mutation */\n")
    git(root, "add", "--", "third_party/tiny_aes/aes.c")
    path.write_bytes(original)


def main() -> int:
    cases: tuple[tuple[str, Callable[[pathlib.Path], None], str], ...] = (
        ("legacy-noassertion-sentinel", mutate_legacy_noassertion, "unsupported NOASSERTION license expression"),
        ("compiled-noassertion", mutate_compiled_noassertion, "NOASSERTION is restricted to reference-only rows"),
        ("missing-reference-notice", mutate_missing_reference_notice, "missing from THIRD_PARTY_NOTICES.md"),
        ("manifest-identity", mutate_manifest_identity, "identity disagrees with snapshot manifest"),
        ("manifest-digest", mutate_manifest_digest, "committed tree digest mismatch"),
        (
            "duplicate-root-manifest-file-set",
            mutate_duplicate_root_manifest_file_set,
            "shared vendored root tracked_files disagree",
        ),
        ("manifest-scope-overclaim", mutate_manifest_scope, "scope changed or overstates authentication"),
        ("sbom-identity", mutate_sbom_identity, "identity disagrees with SBOM"),
        ("cmake-anchor", mutate_cmake_anchor, "not anchored by CMake marker"),
        ("committed-vendor-drift", mutate_committed_vendor, "committed tree digest mismatch"),
        ("added-vendor-file", mutate_added_vendor, "manifest/HEAD file set mismatch"),
        ("missing-vendor-file", mutate_missing_vendor, "source_anchors is missing, linked, or non-regular"),
        ("vendored-symlink", mutate_vendor_symlink, "vendored HEAD entry must be a regular blob"),
        ("vendored-gitlink", mutate_vendor_gitlink, "vendored HEAD entry must be a regular blob"),
        ("worktree-vendor-drift", mutate_worktree_vendor, "worktree content does not reproduce stage-0 blob"),
        ("staged-only-vendor-drift", mutate_staged_only_vendor, "HEAD/index snapshot mismatch"),
    )
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="auto-refirst-provenance-") as raw:
        parent = pathlib.Path(raw)
        baseline = clone(ROOT, parent / "baseline")
        accepted = invoke(baseline)
        if accepted.returncode != 0:
            failures.append(f"clean baseline rejected:\n{accepted.stdout}{accepted.stderr}")
        else:
            print("[PASS MUTATION] clean committed/index/worktree baseline accepted")

        for name, mutate, expected in cases:
            fixture = clone(baseline, parent / name)
            mutate(fixture)
            completed = invoke(fixture)
            output = completed.stdout + completed.stderr
            if completed.returncode == 0 or expected not in output:
                failures.append(
                    f"{name} was not rejected as expected: rc={completed.returncode} expected={expected!r}\n{output}"
                )
            else:
                print(f"[PASS MUTATION] {name} rejected")

    if failures:
        print(f"[FAIL MUTATION] third-party provenance self-test: failures={len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"[PASS MUTATION] third-party provenance self-test: negatives={len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
