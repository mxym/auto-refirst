#!/usr/bin/env python3
"""Fail-closed consistency and vendored-snapshot checks for public provenance."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
from collections.abc import Iterable


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY_PATH = pathlib.PurePosixPath("docs/THIRD_PARTY_PROVENANCE.csv")
MANIFEST_PATH = pathlib.PurePosixPath("docs/VENDORED_SNAPSHOT_MANIFEST.json")
NOTICE_PATH = pathlib.PurePosixPath("THIRD_PARTY_NOTICES.md")
SBOM_PATH = pathlib.PurePosixPath("SBOM.spdx.json")
CMAKE_PATH = pathlib.PurePosixPath("CMakeLists.txt")
CONTROL_PATHS = (INVENTORY_PATH, MANIFEST_PATH, NOTICE_PATH, SBOM_PATH, CMAKE_PATH)
FIELDS = [
    "component_id", "display_name", "relationship", "upstream",
    "upstream_identity", "license_expression", "license_files",
    "vendored_roots", "source_anchors", "shipped_material",
    "local_changes", "notes",
]
COMPILED = {
    "libpeconv": ("libPeConv", "third_party/libpeconv"),
    "miniz": ("miniz", "third_party/miniz/miniz.c"),
    "tiny-aes-c": ("tiny-AES-c", "third_party/tiny_aes/aes.c"),
    "zstd": ("Zstandard single-file decoder", "src/core/zstd_wrap.c"),
    "rustc-demangle": ("rustc-demangle native-c", "third_party/rustc_demangle/demangle.c"),
    "zydis": ("Zydis", "third_party/zydis/Zydis.c"),
    "zycore-c": ("Zycore-C", "third_party/zydis/Zydis.c"),
}
REFERENCES = {
    "cpython-reference", "upx-reference", "pyinstaller-reference",
    "unity-format-reference", "godot-format-reference",
    "go-toolchain-reference", "dart-toolchain-reference",
}
NOASSERTION_REFERENCES = {
    "pyinstaller-reference", "unity-format-reference", "godot-format-reference",
}
MANIFEST_KEYS = {
    "schema_version", "scope", "canonical_tree_digest", "worktree_binding", "components",
}
MANIFEST_COMPONENT_KEYS = {
    "component_id", "declared_upstream_revision", "declared_upstream_tag",
    "license_files", "local_transforms", "vendored_root", "tracked_files", "tree_sha256",
}
MANIFEST_SCOPE = (
    "Binds declared upstream revisions to the exact vendored snapshot bytes tracked in this "
    "repository; it does not independently authenticate upstream origin."
)
MANIFEST_DIGEST = (
    "SHA-256 over concatenated records sorted by repository-relative path; each record is "
    "UTF-8(path) + NUL + lowercase SHA-256(committed Git blob bytes) + LF."
)
MANIFEST_WORKTREE = (
    "Each worktree file is rehashed by Git as raw bytes and, when needed, with repository "
    "attributes; one form must reproduce its stage-0 index blob, and the filesystem inventory "
    "must exactly match tracked_files."
)
FORBIDDEN = re.compile(
    r"(?i)(?:(?<![a-z0-9+.-])[a-z]:[\\/]|\\\\|/(?:data|srv|home|users|tmp)(?:[\\/]|$)|"
    + re.escape("re" + "-ybs") + r"|mcp-workspace|tier[-_ ]?r|holdout)"
)
HEX_OBJECT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
HEX_REVISION = re.compile(r"[0-9a-f]{40}")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] third-party provenance: {message}")


def run_git(root: pathlib.Path, arguments: list[str], *, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def repository_root(candidate: pathlib.Path) -> pathlib.Path:
    try:
        root = candidate.resolve(strict=True)
    except OSError as exc:
        fail(f"source root is unavailable: {exc}")
    if not root.is_dir():
        fail("source root is not a directory")
    raw = run_git(root, ["rev-parse", "--show-toplevel"])
    try:
        git_root = pathlib.Path(raw.decode("utf-8", errors="strict").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"Git top-level is invalid: {exc}")
    if git_root != root:
        fail(f"source root must be the exact Git top-level: expected={root} actual={git_root}")
    return root


def is_link_or_reparse(path: pathlib.Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def decode_git_path(raw: bytes) -> str:
    try:
        relative = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"Git path is not UTF-8: {exc}")
    path = pathlib.PurePosixPath(relative)
    if not relative or "\\" in relative or path.is_absolute() or ".." in path.parts:
        fail(f"unsafe Git path: {relative!r}")
    if path.as_posix() != relative:
        fail(f"non-canonical Git path: {relative!r}")
    return relative


def parse_index_entries(root: pathlib.Path, relative_root: str) -> dict[str, str]:
    raw = run_git(root, ["ls-files", "--stage", "-z", "--", relative_root])
    entries: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, raw_oid, stage = metadata.decode("ascii", errors="strict").split(" ")
        except (UnicodeDecodeError, ValueError) as exc:
            fail(f"invalid Git index record below {relative_root}: {exc}")
        path = decode_git_path(raw_path)
        if mode not in ("100644", "100755") or stage != "0" or not HEX_OBJECT.fullmatch(raw_oid):
            fail(f"vendored index entry must be a regular stage-0 blob: {path}")
        if path in entries:
            fail(f"duplicate Git index entry: {path}")
        entries[path] = raw_oid
    return entries


def parse_head_entries(root: pathlib.Path, relative_root: str) -> dict[str, str]:
    raw = run_git(root, ["ls-tree", "-r", "-z", "--full-tree", "HEAD", "--", relative_root])
    entries: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_oid = metadata.decode("ascii", errors="strict").split(" ")
        except (UnicodeDecodeError, ValueError) as exc:
            fail(f"invalid Git HEAD record below {relative_root}: {exc}")
        path = decode_git_path(raw_path)
        if mode not in ("100644", "100755") or object_type != "blob" or not HEX_OBJECT.fullmatch(raw_oid):
            fail(f"vendored HEAD entry must be a regular blob: {path}")
        if path in entries:
            fail(f"duplicate Git HEAD entry: {path}")
        entries[path] = raw_oid
    return entries


def batch_blob_contents(root: pathlib.Path, object_ids: Iterable[str]) -> dict[str, bytes]:
    unique = list(dict.fromkeys(object_ids))
    if not unique:
        return {}
    raw = run_git(root, ["cat-file", "--batch"], input_bytes=("\n".join(unique) + "\n").encode("ascii"))
    offset = 0
    blobs: dict[str, bytes] = {}
    for expected in unique:
        line_end = raw.find(b"\n", offset)
        if line_end < 0:
            fail("git cat-file --batch omitted an object header")
        try:
            actual, object_type, raw_size = raw[offset:line_end].decode("ascii", errors="strict").split(" ")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as exc:
            fail(f"git cat-file --batch returned an invalid header: {exc}")
        if actual != expected or object_type != "blob" or size < 0:
            fail(f"git cat-file --batch returned the wrong object for {expected}")
        begin = line_end + 1
        end = begin + size
        if end >= len(raw) or raw[end:end + 1] != b"\n":
            fail(f"git cat-file --batch returned a truncated blob for {expected}")
        blobs[expected] = raw[begin:end]
        offset = end + 1
    if offset != len(raw):
        fail("git cat-file --batch returned trailing bytes")
    return blobs


def worktree_oid(root: pathlib.Path, relative: str, *, filtered: bool) -> str:
    mode = f"--path={relative}" if filtered else "--no-filters"
    raw = run_git(root, ["hash-object", mode, "--", relative])
    try:
        oid = raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        fail(f"worktree object id is invalid for {relative}: {exc}")
    if not HEX_OBJECT.fullmatch(oid):
        fail(f"worktree object id is invalid for {relative}: {oid!r}")
    return oid


def worktree_reproduces_index(root: pathlib.Path, relative: str, expected_oid: str) -> bool:
    if worktree_oid(root, relative, filtered=False) == expected_oid:
        return True
    return worktree_oid(root, relative, filtered=True) == expected_oid


def verify_control_file(root: pathlib.Path, relative: pathlib.PurePosixPath) -> None:
    name = relative.as_posix()
    head = parse_head_entries(root, name)
    index = parse_index_entries(root, name)
    if set(head) != {name} or set(index) != {name}:
        fail(f"control file must be a single regular tracked blob: {name}")
    if head[name] != index[name]:
        fail(f"control file HEAD/index mismatch: {name}")
    path = root.joinpath(*relative.parts)
    if is_link_or_reparse(path) or not path.is_file():
        fail(f"control file is missing, linked, or non-regular: {name}")
    if not worktree_reproduces_index(root, name, index[name]):
        fail(f"control file worktree differs from committed blob: {name}")


def split_paths(value: str, field: str, component: str) -> list[str]:
    result = [item.strip() for item in value.split("|") if item.strip()]
    for item in result:
        if "\\" in item:
            fail(f"{component} {field} must use repository-relative POSIX paths: {item}")
        path = pathlib.PurePosixPath(item)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != item:
            fail(f"{component} {field} escapes the public source root: {item}")
    return result


def existing_paths(
    root: pathlib.Path, row: dict[str, str], field: str, *, directories: bool = False,
) -> list[str]:
    paths = split_paths(row[field], field, row["component_id"])
    for item in paths:
        target = root.joinpath(*pathlib.PurePosixPath(item).parts)
        expected_type = target.is_dir() if directories else target.is_file()
        if not expected_type or is_link_or_reparse(target):
            fail(f"{row['component_id']} {field} is missing, linked, or non-regular: {item}")
    return paths


def load_text(root: pathlib.Path, relative: pathlib.PurePosixPath) -> str:
    path = root.joinpath(*relative.parts)
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"cannot read UTF-8 control file {relative.as_posix()}: {exc}")
    match = FORBIDDEN.search(text)
    if match:
        fail(f"private or absolute path marker is forbidden in {relative.as_posix()}: {match.group(0)!r}")
    return text


def load_inventory(root: pathlib.Path) -> list[dict[str, str]]:
    text = load_text(root, INVENTORY_PATH)
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames != FIELDS:
        fail(f"unexpected inventory columns: {reader.fieldnames!r}")
    rows = list(reader)
    if not rows:
        fail("inventory has no rows")
    ids = [row["component_id"] for row in rows]
    required = ("component_id", "display_name", "relationship", "upstream", "upstream_identity", "license_expression", "shipped_material")
    if any(not row[field] for row in rows for field in required):
        fail("required inventory field is empty")
    if len(ids) != len(set(ids)):
        fail("duplicate component_id")
    return rows


def load_manifest(root: pathlib.Path) -> dict[str, object]:
    text = load_text(root, MANIFEST_PATH)
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"snapshot manifest is invalid JSON: {exc}")
    if not isinstance(document, dict) or set(document) != MANIFEST_KEYS:
        fail(f"snapshot manifest top-level keys are not exact: {sorted(document) if isinstance(document, dict) else type(document).__name__}")
    if document["schema_version"] != "1.0":
        fail("snapshot manifest schema_version must be 1.0")
    if document["scope"] != MANIFEST_SCOPE:
        fail("snapshot manifest scope changed or overstates authentication")
    if document["canonical_tree_digest"] != MANIFEST_DIGEST:
        fail("snapshot manifest digest contract changed")
    if document["worktree_binding"] != MANIFEST_WORKTREE:
        fail("snapshot manifest worktree contract changed")
    components = document["components"]
    if not isinstance(components, list) or not components:
        fail("snapshot manifest components must be a non-empty list")
    return document


def filesystem_inventory(root: pathlib.Path, relative_root: str) -> list[str]:
    directory = root.joinpath(*pathlib.PurePosixPath(relative_root).parts)
    if not directory.is_dir() or is_link_or_reparse(directory):
        fail(f"vendored root is missing, linked, or non-directory: {relative_root}")
    files: list[str] = []
    for current, directories, names in os.walk(directory, followlinks=False):
        current_path = pathlib.Path(current)
        for name in directories:
            child = current_path / name
            if is_link_or_reparse(child):
                fail(f"vendored worktree contains linked/reparse directory: {child.relative_to(root).as_posix()}")
        for name in names:
            child = current_path / name
            relative = child.relative_to(root).as_posix()
            if is_link_or_reparse(child) or not child.is_file():
                fail(f"vendored worktree contains linked or non-regular file: {relative}")
            files.append(relative)
    return sorted(files)


def tree_digest(paths: list[str], entries: dict[str, str], blobs: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        content_sha = hashlib.sha256(blobs[entries[path]]).hexdigest()
        digest.update(path.encode("utf-8") + b"\0" + content_sha.encode("ascii") + b"\n")
    return digest.hexdigest()


def verify_snapshot_root(root: pathlib.Path, relative_root: str, declared_files: list[str]) -> str:
    head = parse_head_entries(root, relative_root)
    index = parse_index_entries(root, relative_root)
    head_files = sorted(head)
    index_files = sorted(index)
    worktree_files = filesystem_inventory(root, relative_root)
    if declared_files != head_files:
        fail(f"{relative_root} manifest/HEAD file set mismatch")
    if index_files != head_files or any(index[path] != head[path] for path in head_files):
        fail(f"{relative_root} HEAD/index snapshot mismatch")
    if worktree_files != head_files:
        fail(f"{relative_root} manifest/worktree file set mismatch")
    for path in head_files:
        if not worktree_reproduces_index(root, path, index[path]):
            fail(f"{relative_root} worktree content does not reproduce stage-0 blob: {path}")
    blobs = batch_blob_contents(root, head.values())
    return tree_digest(head_files, head, blobs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="exact Git top-level to audit")
    args = parser.parse_args()
    root = repository_root(args.root)
    for relative in CONTROL_PATHS:
        verify_control_file(root, relative)

    rows = load_inventory(root)
    by_id = {row["component_id"]: row for row in rows}
    compiled_ids = {key for key, row in by_id.items() if row["relationship"].startswith("COMPILED_")}
    reference_ids = set(by_id) - compiled_ids
    if compiled_ids != set(COMPILED):
        fail(f"compiled row mismatch: expected={sorted(COMPILED)} actual={sorted(compiled_ids)}")
    if reference_ids != REFERENCES:
        fail(f"reference row mismatch: expected={sorted(REFERENCES)} actual={sorted(reference_ids)}")

    manifest = load_manifest(root)
    raw_components = manifest["components"]
    assert isinstance(raw_components, list)
    if any(not isinstance(component, dict) for component in raw_components):
        fail("snapshot manifest component must be an object")
    components = raw_components
    component_ids = [component.get("component_id") for component in components]
    if component_ids != list(COMPILED):
        fail(f"snapshot manifest component order/set mismatch: {component_ids!r}")
    if any(set(component) != MANIFEST_COMPONENT_KEYS for component in components):
        fail("snapshot manifest component keys are not exact")
    manifest_by_id = {str(component["component_id"]): component for component in components}

    cmake = load_text(root, CMAKE_PATH)
    notices = load_text(root, NOTICE_PATH)
    try:
        sbom = json.loads(load_text(root, SBOM_PATH))
    except json.JSONDecodeError as exc:
        fail(f"SBOM is invalid JSON: {exc}")
    sbom_packages = {
        package["name"]: package
        for package in sbom.get("packages", [])
        if package.get("name") != "auto-refirst"
    }

    used_license_files: set[str] = set()
    used_vendored_roots: set[str] = set()
    noassertion_ids: set[str] = set()
    snapshot_cache: dict[tuple[str, tuple[str, ...]], str] = {}
    snapshot_declarations: dict[str, tuple[str, ...]] = {}
    for row in rows:
        component = row["component_id"]
        licenses = existing_paths(root, row, "license_files")
        anchors = existing_paths(root, row, "source_anchors")
        roots = existing_paths(root, row, "vendored_roots", directories=True)
        used_license_files.update(path for path in licenses if path.startswith("LICENSES/"))
        used_vendored_roots.update(roots)
        if not anchors:
            fail(f"{component} has no public source anchor")

        expression = row["license_expression"]
        is_compiled = component in compiled_ids
        is_reference_only = row["relationship"].endswith("_REFERENCE_ONLY")
        if "NOASSERTION" in expression and expression != "NOASSERTION":
            fail(f"{component} uses unsupported NOASSERTION license expression: {expression}")
        if expression == "NOASSERTION":
            noassertion_ids.add(component)
            if is_compiled or component not in REFERENCES or not is_reference_only:
                fail(f"{component} NOASSERTION is restricted to reference-only rows")
            if licenses:
                fail(f"{component} reference-only NOASSERTION must not claim license files")
            if "REFERENCE_ONLY:" not in row["notes"] or "Final release legal review remains authoritative." not in row["notes"]:
                fail(f"{component} reference-only NOASSERTION notes are incomplete")
        else:
            if is_reference_only:
                fail(f"{component} REFERENCE_ONLY relationship must use exact NOASSERTION")
            if not licenses:
                fail(f"{component} omits license files without exact reference-only NOASSERTION")
        if is_compiled and not licenses:
            fail(f"compiled component {component} has no license file")

    if noassertion_ids != NOASSERTION_REFERENCES:
        fail(f"NOASSERTION reference set mismatch: expected={sorted(NOASSERTION_REFERENCES)} actual={sorted(noassertion_ids)}")

    for component, (package_name, cmake_marker) in COMPILED.items():
        row = by_id[component]
        snapshot = manifest_by_id[component]
        if cmake_marker not in cmake:
            fail(f"compiled component {component} is not anchored by CMake marker {cmake_marker}")
        expected_notice = f"| {row['display_name']} | `{row['upstream_identity']}` | {row['license_expression']} |"
        if expected_notice not in notices:
            fail(f"compiled component {component} identity/license is missing from THIRD_PARTY_NOTICES.md")
        if package_name not in sbom_packages:
            fail(f"compiled component {component} is missing from SBOM.spdx.json")
        package = sbom_packages[package_name]
        if row["upstream_identity"] != package.get("versionInfo"):
            fail(f"{component} identity disagrees with SBOM")
        if row["license_expression"] != package.get("licenseDeclared"):
            fail(f"{component} declared license disagrees with SBOM")
        if row["upstream"] != package.get("downloadLocation"):
            fail(f"{component} upstream location disagrees with SBOM")

        revision = snapshot["declared_upstream_revision"]
        tag = snapshot["declared_upstream_tag"]
        if not isinstance(revision, str) or not HEX_REVISION.fullmatch(revision):
            fail(f"{component} snapshot revision must be a full lowercase Git SHA-1")
        if not isinstance(tag, str) or "@" in tag or any(character in tag for character in "\r\n"):
            fail(f"{component} snapshot tag is invalid")
        snapshot_identity = f"{tag}@{revision}" if tag else revision
        if snapshot_identity != row["upstream_identity"]:
            fail(f"{component} identity disagrees with snapshot manifest")
        if snapshot["license_files"] != split_paths(row["license_files"], "license_files", component):
            fail(f"{component} license files disagree with snapshot manifest")
        if snapshot["local_transforms"] != row["local_changes"]:
            fail(f"{component} local transforms disagree with snapshot manifest")
        manifest_root = snapshot["vendored_root"]
        roots = split_paths(row["vendored_roots"], "vendored_roots", component)
        if not isinstance(manifest_root, str) or roots != [manifest_root]:
            fail(f"{component} vendored root disagrees with snapshot manifest")
        declared_files = snapshot["tracked_files"]
        if (
            not isinstance(declared_files, list)
            or not declared_files
            or any(not isinstance(path, str) for path in declared_files)
            or declared_files != sorted(set(declared_files))
        ):
            fail(f"{component} tracked_files must be a sorted, unique, non-empty string list")
        vendored_root = str(snapshot["vendored_root"])
        prefix = vendored_root + "/"
        if any(not path.startswith(prefix) or decode_git_path(path.encode("utf-8")) != path for path in declared_files):
            fail(f"{component} tracked file escapes vendored root")
        declared_file_tuple = tuple(declared_files)
        previous_declaration = snapshot_declarations.get(vendored_root)
        if previous_declaration is not None and previous_declaration != declared_file_tuple:
            fail(f"{component} shared vendored root tracked_files disagree with another component")
        snapshot_declarations[vendored_root] = declared_file_tuple
        recorded_digest = snapshot["tree_sha256"]
        if not isinstance(recorded_digest, str) or not HEX_SHA256.fullmatch(recorded_digest):
            fail(f"{component} tree_sha256 must be a lowercase SHA-256")
        cache_key = (vendored_root, declared_file_tuple)
        if cache_key not in snapshot_cache:
            snapshot_cache[cache_key] = verify_snapshot_root(root, vendored_root, declared_files)
        actual_digest = snapshot_cache[cache_key]
        if actual_digest != recorded_digest:
            fail(f"{component} committed tree digest mismatch: expected={recorded_digest} actual={actual_digest}")

    expected_sbom = {package for package, _ in COMPILED.values()}
    if set(sbom_packages) != expected_sbom:
        fail(f"SBOM compiled package set mismatch: expected={sorted(expected_sbom)} actual={sorted(sbom_packages)}")

    for component in sorted(REFERENCES):
        row = by_id[component]
        marker = f"- {row['display_name']} —"
        line = next((item for item in notices.splitlines() if item.startswith(marker)), "")
        if not line:
            fail(f"reference component {component} is missing from THIRD_PARTY_NOTICES.md")
        if component in NOASSERTION_REFERENCES:
            required = (
                "**REFERENCE_ONLY / NOASSERTION**",
                "No license conclusion is asserted",
                "payload is distributed",
                "Final release legal review remains authoritative.",
            )
            if any(phrase not in line for phrase in required):
                fail(f"reference component {component} has incomplete NOASSERTION notice")

    actual_license_files = {
        path.relative_to(root).as_posix()
        for path in (root / "LICENSES").iterdir()
        if path.is_file() and not is_link_or_reparse(path)
    }
    if used_license_files != actual_license_files:
        fail(f"LICENSES inventory mismatch: missing={sorted(actual_license_files - used_license_files)} extra={sorted(used_license_files - actual_license_files)}")

    actual_vendored_roots = {
        path.relative_to(root).as_posix()
        for path in (root / "third_party").iterdir()
        if path.is_dir() and not is_link_or_reparse(path)
    }
    if used_vendored_roots != actual_vendored_roots:
        fail(f"third_party root mismatch: missing={sorted(actual_vendored_roots - used_vendored_roots)} extra={sorted(used_vendored_roots - actual_vendored_roots)}")

    zstd_wrapper = (root / "src/core/zstd_wrap.c").read_text(encoding="utf-8")
    if "../../third_party/zstd/zstddeclib.c" not in zstd_wrapper:
        fail("zstd vendored decoder is no longer included by src/core/zstd_wrap.c")
    zydis_header = (root / "third_party/zydis/Zydis.h").read_text(encoding="utf-8", errors="replace")
    if "Zycore-C" not in zydis_header:
        fail("Zycore-C is no longer present in the Zydis amalgamation")

    unique_snapshot_files = len({path for component in components for path in component["tracked_files"]})
    print(
        f"[PASS] third-party provenance: {len(compiled_ids)} compiled + {len(reference_ids)} reference rows; "
        f"snapshot_roots={len(snapshot_declarations)} snapshot_files={unique_snapshot_files}; "
        "declared revisions bound to committed/index/worktree vendored bytes; "
        "no independent upstream authentication claimed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
