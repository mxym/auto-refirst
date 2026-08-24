#!/usr/bin/env python3
"""Fail-closed verifier for staged or downloaded public release assets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
from collections.abc import Iterable


CHECKER_ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_INFO_NAME = "BUILD_INFO.txt"
SUMS_NAME = "SHA256SUMS"
LEGAL_ASSETS = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "SBOM.spdx.json")
BUILD_INFO_FIELDS = (
    "release_tag",
    "product_version",
    "public_source_commit",
    "report_schema_version",
    "source_tree_state",
    "reproducibility_contract",
    "bit_reproducible",
    "source_archive",
    "source_archive_root",
    "source_archive_sha256",
    "linux_artifact",
    "linux_sha256",
    "linux_build_platform",
    "linux_toolchain",
    "linux_cmake_version",
    "linux_build_flags",
    "linux_hosted_run_id",
    "linux_hosted_head_sha",
    "linux_hosted_result",
    "windows_artifact",
    "windows_sha256",
    "windows_build_platform",
    "windows_toolchain",
    "windows_cmake_version",
    "windows_build_flags",
    "windows_hosted_run_id",
    "windows_hosted_head_sha",
    "windows_hosted_result",
    "sanitizer_hosted_run_id",
    "sanitizer_hosted_head_sha",
    "sanitizer_hosted_result",
)
EXPECTED_PLATFORMS = {"linux": "Linux/x86_64", "windows": "Windows/AMD64"}
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
FULL_GIT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SHA256 = re.compile(r"[0-9a-f]{64}")
SCHEMA_VERSION = re.compile(r"[0-9]+\.[0-9]+")
PRODUCT_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
MAX_ASSETS = 64
MAX_SINGLE_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 4 * 1024 * 1024 * 1024
MAX_CONTROL_BYTES = 64 * 1024
MAX_RELEASE_METADATA_BYTES = 2 * 1024 * 1024
GITHUB_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9][A-Za-z0-9._-]{0,99}"
)
FIXTURE_PROVENANCE_PATH = "tests/corpus/PROVENANCE.csv"
FIXTURE_PROVENANCE_FIELDS = (
    "path",
    "kind",
    "source_type",
    "source_path_or_repo",
    "license",
    "license_file",
    "toolchain_version",
    "rebuild_command",
    "target_platform_arch",
    "reproducibility",
    "redistribution_rights",
    "redistributable",
    "public_ci_allowed",
    "sha256",
    "public_action",
    "notes",
)
MAX_PUBLIC_FIXTURES = 512


class DuplicateJsonKey(ValueError):
    """Raised when untrusted JSON repeats an object key."""


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] release assets: {message}")


def run_git(
    root: pathlib.Path,
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: int = 60,
) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
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
        actual = pathlib.Path(raw.decode("utf-8", errors="strict").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"Git top-level is invalid: {exc}")
    if actual != root:
        fail(f"source root must be the exact Git top-level: expected={root} actual={actual}")
    return root


def is_link_or_reparse(path: pathlib.Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def safe_asset_name(name: str, label: str) -> str:
    if not SAFE_NAME.fullmatch(name) or name in (".", ".."):
        fail(f"{label} is not a safe basename: {name!r}")
    return name


def read_small_utf8(path: pathlib.Path, label: str) -> str:
    if is_link_or_reparse(path) or not path.is_file():
        fail(f"{label} is missing, linked, or non-regular")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        fail(f"cannot read {label}: {exc}")
    if len(raw) > MAX_CONTROL_BYTES:
        fail(f"{label} exceeds {MAX_CONTROL_BYTES} bytes")
    if raw.startswith(b"\xef\xbb\xbf") or b"\0" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        fail(f"{label} must be BOM-free, NUL-free, LF-only UTF-8 ending in LF")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not UTF-8: {exc}")


def read_release_metadata(path: pathlib.Path) -> dict[str, object]:
    label = "GitHub release metadata"
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        fail(f"{label} is unavailable: {exc}")
    if is_link_or_reparse(resolved) or not resolved.is_file():
        fail(f"{label} must be a regular non-linked file")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        fail(f"cannot read {label}: {exc}")
    if len(raw) > MAX_RELEASE_METADATA_BYTES:
        fail(f"{label} exceeds {MAX_RELEASE_METADATA_BYTES} bytes")
    if raw.startswith(b"\xef\xbb\xbf") or b"\0" in raw:
        fail(f"{label} must be BOM-free and NUL-free UTF-8 JSON")

    def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateJsonKey(key)
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    except (DuplicateJsonKey, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        fail(f"{label} is not strict JSON: {exc}")
    if not isinstance(document, dict):
        fail(f"{label} top level must be an object")
    return document


def hash_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        fail(f"cannot hash {path.name}: {exc}")
    return digest.hexdigest()


def asset_inventory(asset_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    try:
        directory = asset_dir.resolve(strict=True)
    except OSError as exc:
        fail(f"asset directory is unavailable: {exc}")
    if not directory.is_dir() or is_link_or_reparse(directory):
        fail("asset directory must be a real directory, not a link/reparse point")
    files: dict[str, pathlib.Path] = {}
    total = 0
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        fail(f"cannot enumerate asset directory: {exc}")
    if len(entries) > MAX_ASSETS:
        fail(f"asset directory exceeds {MAX_ASSETS} top-level entries")
    for path in entries:
        name = safe_asset_name(path.name, "asset filename")
        if is_link_or_reparse(path) or not path.is_file():
            fail(f"asset entry must be a regular non-linked file: {name}")
        size = path.stat().st_size
        if size > MAX_SINGLE_ASSET_BYTES:
            fail(f"asset exceeds {MAX_SINGLE_ASSET_BYTES} bytes: {name}")
        total += size
        if total > MAX_TOTAL_ASSET_BYTES:
            fail(f"asset directory exceeds {MAX_TOTAL_ASSET_BYTES} total bytes")
        files[name] = path
    return files


def parse_sums(path: pathlib.Path) -> dict[str, str]:
    text = read_small_utf8(path, SUMS_NAME)
    result: dict[str, str] = {}
    names: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,127})", line)
        if not match:
            fail(f"{SUMS_NAME}:{number} is not canonical lowercase SHA-256 format")
        digest, name = match.groups()
        safe_asset_name(name, f"{SUMS_NAME}:{number} filename")
        if name == SUMS_NAME:
            fail(f"{SUMS_NAME} must not hash itself")
        if name in result:
            fail(f"{SUMS_NAME} contains duplicate filename: {name}")
        result[name] = digest
        names.append(name)
    if not result:
        fail(f"{SUMS_NAME} has no asset rows")
    if names != sorted(names):
        fail(f"{SUMS_NAME} rows must be sorted by filename")
    return result


def parse_build_info(path: pathlib.Path) -> dict[str, str]:
    text = read_small_utf8(path, BUILD_INFO_NAME)
    result: dict[str, str] = {}
    keys: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if "=" not in line:
            fail(f"{BUILD_INFO_NAME}:{number} is not key=value")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or value != value.strip():
            fail(f"{BUILD_INFO_NAME}:{number} has invalid key or value")
        if key in result:
            fail(f"{BUILD_INFO_NAME} contains duplicate key: {key}")
        result[key] = value
        keys.append(key)
    if tuple(keys) != BUILD_INFO_FIELDS:
        fail(f"{BUILD_INFO_NAME} fields/order are not exact: expected={BUILD_INFO_FIELDS} actual={tuple(keys)}")
    return result


def decode_git_path(raw: bytes) -> str:
    try:
        relative = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"tracked Git path is not UTF-8: {exc}")
    path = pathlib.PurePosixPath(relative)
    if not relative or "\\" in relative or path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
        fail(f"tracked Git path is unsafe or non-canonical: {relative!r}")
    return relative


def git_tree(root: pathlib.Path) -> dict[str, tuple[str, str]]:
    raw = run_git(root, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"])
    result: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, oid = metadata.decode("ascii", errors="strict").split(" ")
        except (UnicodeDecodeError, ValueError) as exc:
            fail(f"invalid Git tree record: {exc}")
        path = decode_git_path(raw_path)
        if mode not in ("100644", "100755") or object_type != "blob" or not FULL_GIT_ID.fullmatch(oid):
            fail(f"release source tree contains non-regular or unsupported tracked entry: {path}")
        if path in result:
            fail(f"release source tree contains duplicate path: {path}")
        result[path] = (mode, oid)
    if not result:
        fail("release source tree is empty")
    return result


def batch_blob_contents(root: pathlib.Path, object_ids: Iterable[str]) -> dict[str, bytes]:
    unique = list(dict.fromkeys(object_ids))
    raw = run_git(root, ["cat-file", "--batch"], input_bytes=("\n".join(unique) + "\n").encode("ascii"))
    offset = 0
    result: dict[str, bytes] = {}
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
        result[expected] = raw[begin:end]
        offset = end + 1
    if offset != len(raw):
        fail("git cat-file --batch returned trailing bytes")
    return result


def verify_source_hygiene(root: pathlib.Path) -> str:
    checker = CHECKER_ROOT / "tests" / "check_public_source_hygiene.py"
    if not checker.is_file():
        fail("public source hygiene checker is unavailable")
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, str(checker), "--root", str(root), "--require-clean"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=180,
    )
    output = completed.stdout.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"public source hygiene gate failed: {output} {detail}")
    if not output.startswith("[PASS] public source hygiene:"):
        fail("public source hygiene checker did not emit its auditable PASS summary")
    return output


def verify_build_info(info: dict[str, str], expected_commit: str) -> None:
    if not PRODUCT_VERSION.fullmatch(info["product_version"]):
        fail("BUILD_INFO product_version is not a supported SemVer string")
    if info["release_tag"] != "v" + info["product_version"]:
        fail("BUILD_INFO release_tag must equal v + product_version")
    if info["public_source_commit"] != expected_commit:
        fail("BUILD_INFO public_source_commit does not equal the frozen commit")
    if not SCHEMA_VERSION.fullmatch(info["report_schema_version"]):
        fail("BUILD_INFO report_schema_version is invalid")
    if info["source_tree_state"] != "CLEAN":
        fail("BUILD_INFO source_tree_state must be CLEAN")
    if info["reproducibility_contract"] != "SEMANTICALLY_REPRODUCIBLE":
        fail("BUILD_INFO must retain the SEMANTICALLY_REPRODUCIBLE contract")
    if info["bit_reproducible"] != "false":
        fail("BUILD_INFO must not claim bit reproducibility")
    if info["linux_build_platform"] != EXPECTED_PLATFORMS["linux"]:
        fail("BUILD_INFO linux_build_platform is not Linux/x86_64")
    if info["windows_build_platform"] != EXPECTED_PLATFORMS["windows"]:
        fail("BUILD_INFO windows_build_platform is not Windows/AMD64")
    for platform in ("linux", "windows"):
        if "AUTO_REFIRST_WARNINGS_AS_ERRORS=ON" not in info[f"{platform}_build_flags"].split(";"):
            fail(f"BUILD_INFO {platform}_build_flags omits warnings-as-errors")
        for field in ("toolchain", "cmake_version"):
            if not info[f"{platform}_{field}"]:
                fail(f"BUILD_INFO {platform}_{field} is empty")
    for gate in ("linux", "windows", "sanitizer"):
        if not re.fullmatch(r"[1-9][0-9]*", info[f"{gate}_hosted_run_id"]):
            fail(f"BUILD_INFO {gate}_hosted_run_id must be a positive decimal run id")
        if info[f"{gate}_hosted_head_sha"] != expected_commit:
            fail(f"BUILD_INFO {gate}_hosted_head_sha does not equal the frozen commit")
        if info[f"{gate}_hosted_result"] != "PASS":
            fail(f"BUILD_INFO {gate}_hosted_result must be PASS")
    for field in ("source_archive_sha256", "linux_sha256", "windows_sha256"):
        if not SHA256.fullmatch(info[field]):
            fail(f"BUILD_INFO {field} is not lowercase SHA-256")
    for field in ("source_archive", "source_archive_root", "linux_artifact", "windows_artifact"):
        safe_asset_name(info[field], f"BUILD_INFO {field}")
    if not info["source_archive"].endswith(".tar.gz"):
        fail("BUILD_INFO source_archive must be a .tar.gz custom archive")
    if len({info["source_archive"], info["linux_artifact"], info["windows_artifact"]}) != 3:
        fail("BUILD_INFO source archive and platform artifact names must be distinct")


def source_contract(
    tree: dict[str, tuple[str, str]],
    blobs: dict[str, bytes],
) -> tuple[str, str]:
    required = ("CMakeLists.txt", "include/prts/report_schema.hpp")
    missing = [path for path in required if path not in tree]
    if missing:
        fail(f"release source omits product/schema contract anchors: {missing}")
    texts: dict[str, str] = {}
    for path in required:
        try:
            texts[path] = blobs[tree[path][1]].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            fail(f"release source contract anchor is not UTF-8: {path}: {exc}")
    versions = re.findall(
        r'^set\(AUTO_REFIRST_PRODUCT_VERSION "([^"\r\n]+)" CACHE STRING '
        r'"Product version reported by auto-refirst --version"\)$',
        texts["CMakeLists.txt"],
        flags=re.MULTILINE,
    )
    schemas = re.findall(
        r'^inline constexpr std::string_view kReportSchemaVersion = "([^"\r\n]+)";$',
        texts["include/prts/report_schema.hpp"],
        flags=re.MULTILINE,
    )
    if len(versions) != 1 or not PRODUCT_VERSION.fullmatch(versions[0]):
        fail("release source product-version contract anchor is missing, duplicate, or invalid")
    if len(schemas) != 1 or not SCHEMA_VERSION.fullmatch(schemas[0]):
        fail("release source report-schema contract anchor is missing, duplicate, or invalid")
    return versions[0], schemas[0]


def safe_source_path(value: str, label: str) -> str:
    path = pathlib.PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
    ):
        fail(f"{label} is not a safe repository-relative path: {value!r}")
    return value


def fixture_source_paths(value: str, label: str) -> tuple[str, ...]:
    """Return tracked local sources without changing opaque repo/text semantics."""
    parts = tuple(part.strip() for part in value.split("|"))
    if any(not part for part in parts):
        fail(f"{label} contains an empty source segment")
    if len(parts) != len(set(parts)):
        fail(f"{label} contains a duplicate source segment")

    local = tuple(part.startswith("tests/") for part in parts)
    if len(parts) > 1 and not all(local):
        if any(local):
            fail(f"{label} mixes local source paths with repository/text sources")
        fail(f"{label} repository/text source contains the local-path delimiter")
    if not any(local):
        return ()
    return tuple(safe_source_path(part, label) for part in parts)


def verify_fixture_provenance(
    tree: dict[str, tuple[str, str]],
    blobs: dict[str, bytes],
) -> int:
    if FIXTURE_PROVENANCE_PATH not in tree:
        fail(f"release source omits {FIXTURE_PROVENANCE_PATH}")
    provenance_oid = tree[FIXTURE_PROVENANCE_PATH][1]
    try:
        text = blobs[provenance_oid].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"public fixture provenance is not UTF-8: {exc}")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if tuple(reader.fieldnames or ()) != FIXTURE_PROVENANCE_FIELDS:
        fail(
            "public fixture provenance fields/order are not exact: "
            f"expected={FIXTURE_PROVENANCE_FIELDS} actual={tuple(reader.fieldnames or ())}"
        )
    rows = list(reader)
    if not rows or len(rows) > MAX_PUBLIC_FIXTURES:
        fail("public fixture provenance rows must be non-empty and bounded")

    row_paths: set[str] = set()
    source_paths: set[str] = set()
    for number, row in enumerate(rows, 2):
        if set(row) != set(FIXTURE_PROVENANCE_FIELDS):
            fail(f"public fixture provenance row {number} has malformed columns")
        if any(row[field] is None or not row[field].strip() for field in FIXTURE_PROVENANCE_FIELDS):
            fail(f"public fixture provenance row {number} has an empty field")
        fixture_path = safe_source_path(row["path"], f"public fixture row {number} path")
        if not fixture_path.startswith("tests/corpus/") or fixture_path == FIXTURE_PROVENANCE_PATH:
            fail(f"public fixture row {number} path is outside the corpus inventory")
        if fixture_path in row_paths:
            fail(f"public fixture provenance contains duplicate path: {fixture_path}")
        row_paths.add(fixture_path)
        if fixture_path not in tree:
            fail(f"public fixture provenance path is not tracked: {fixture_path}")
        declared_hash = row["sha256"]
        if not SHA256.fullmatch(declared_hash):
            fail(f"public fixture provenance SHA-256 is invalid: {fixture_path}")
        actual_hash = hashlib.sha256(blobs[tree[fixture_path][1]]).hexdigest()
        if actual_hash != declared_hash:
            fail(f"public fixture provenance SHA-256 mismatch: {fixture_path}")
        if row["redistributable"] != "true":
            fail(f"public fixture is not declared redistributable: {fixture_path}")
        if row["public_ci_allowed"] not in ("true", "false"):
            fail(f"public fixture public_ci_allowed is not canonical: {fixture_path}")
        if row["public_action"] != "KEEP":
            fail(f"public fixture action is not KEEP: {fixture_path}")
        for license_path in row["license_file"].split("|"):
            license_path = safe_source_path(
                license_path,
                f"public fixture row {number} license_file",
            )
            if license_path not in tree:
                fail(f"public fixture license file is not tracked: {license_path}")
        for source in fixture_source_paths(
            row["source_path_or_repo"],
            f"public fixture row {number} source",
        ):
            if source not in tree:
                fail(f"public fixture source path is not tracked: {source}")
            source_paths.add(source)

    corpus_files = {
        path
        for path in tree
        if path.startswith("tests/corpus/") and path != FIXTURE_PROVENANCE_PATH
    }
    required_rows = {
        path for path in corpus_files if path not in source_paths or path in row_paths
    }
    if row_paths != required_rows:
        fail(
            "public fixture provenance inventory mismatch: "
            f"missing={sorted(required_rows - row_paths)} "
            f"extra={sorted(row_paths - required_rows)}"
        )
    return len(rows)


def expected_archive_directories(prefix: str, paths: Iterable[str]) -> set[str]:
    result = {prefix}
    for relative in paths:
        parts = pathlib.PurePosixPath(relative).parts[:-1]
        current = pathlib.PurePosixPath(prefix)
        for part in parts:
            current /= part
            result.add(current.as_posix())
    return result


def canonical_tar_name(member: tarfile.TarInfo) -> str:
    raw_name = member.name.rstrip("/") if member.isdir() else member.name
    path = pathlib.PurePosixPath(raw_name)
    if (
        not raw_name
        or "\\" in raw_name
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or path.as_posix() != raw_name
    ):
        fail(f"source archive contains unsafe or non-canonical path: {member.name!r}")
    return raw_name


def verify_source_archive(
    archive: pathlib.Path,
    prefix: str,
    tree: dict[str, tuple[str, str]],
    blobs: dict[str, bytes],
) -> None:
    if is_link_or_reparse(archive) or not archive.is_file():
        fail("custom source archive is missing, linked, or non-regular")
    expected_files = {f"{prefix}/{relative}": relative for relative in tree}
    expected_directories = expected_archive_directories(prefix, tree)
    seen: set[str] = set()
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        with tarfile.open(archive, mode="r:gz") as handle:
            member_count = 0
            member_limit = len(expected_files) + len(expected_directories) + MAX_ASSETS
            for member in handle:
                member_count += 1
                if member_count > member_limit:
                    fail("source archive member count exceeds the bounded tracked inventory")
                name = canonical_tar_name(member)
                if name in seen:
                    fail(f"source archive contains duplicate member: {name}")
                seen.add(name)
                if member.isdir():
                    if member.mode & 0o7777 != 0o755:
                        fail(f"source archive directory mode is not 0755: {name}")
                    actual_directories.add(name)
                    continue
                if not member.isfile():
                    fail(f"source archive member is not a regular file/directory: {name}")
                if name not in expected_files:
                    fail(f"source archive contains untracked or misplaced file: {name}")
                relative = expected_files[name]
                git_mode, oid = tree[relative]
                expected_mode = 0o755 if git_mode == "100755" else 0o644
                if member.mode & 0o7777 != expected_mode:
                    fail(f"source archive mode disagrees with Git for {relative}")
                expected = blobs[oid]
                if member.size != len(expected):
                    fail(f"source archive size disagrees with Git blob for {relative}")
                extracted = handle.extractfile(member)
                if extracted is None or extracted.read() != expected:
                    fail(f"source archive bytes disagree with Git blob for {relative}")
                actual_files.add(name)
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot read custom source archive: {exc}")
    if actual_files != set(expected_files):
        missing = sorted(set(expected_files) - actual_files)
        extra = sorted(actual_files - set(expected_files))
        fail(f"source archive file inventory mismatch: missing={missing} extra={extra}")
    if actual_directories != expected_directories:
        missing = sorted(expected_directories - actual_directories)
        extra = sorted(actual_directories - expected_directories)
        fail(f"source archive directory inventory mismatch: missing={missing} extra={extra}")


def verify_tag(root: pathlib.Path, tag: str, expected_commit: str, remote: str | None) -> str:
    ref = f"refs/tags/{tag}"
    run_git(root, ["check-ref-format", ref])
    local_oid = run_git(root, ["rev-parse", "--verify", ref]).decode("ascii", errors="strict").strip()
    peeled = run_git(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"]).decode("ascii", errors="strict").strip()
    if peeled != expected_commit:
        fail(f"local release tag peels to {peeled}, not frozen commit {expected_commit}")
    object_type = run_git(root, ["cat-file", "-t", ref]).decode("ascii", errors="strict").strip()
    if object_type not in ("tag", "commit"):
        fail(f"local release tag has unsupported object type: {object_type}")
    if remote is None:
        return "local"
    if not remote or remote.startswith("-"):
        fail("remote name/path is unsafe")
    raw = run_git(root, ["ls-remote", "--exit-code", remote, ref, f"{ref}^{{}}"], timeout=120)
    records: dict[str, str] = {}
    for line in raw.decode("ascii", errors="strict").splitlines():
        try:
            oid, name = line.split("\t", 1)
        except ValueError:
            fail("git ls-remote returned an invalid tag record")
        if name in records or name not in (ref, f"{ref}^{{}}") or not FULL_GIT_ID.fullmatch(oid):
            fail(f"git ls-remote returned an unexpected tag record: {line!r}")
        records[name] = oid
    if records.get(ref) != local_oid:
        fail("remote release tag object does not equal the reviewed local tag object")
    if object_type == "tag":
        if records.get(f"{ref}^{{}}") != expected_commit:
            fail("remote annotated release tag does not peel to the frozen commit")
    elif set(records) != {ref}:
        fail("remote lightweight release tag returned an unexpected peeled record")
    return "local+remote"


def verify_github_release(
    document: dict[str, object],
    repository: str,
    info: dict[str, str],
    assets: dict[str, pathlib.Path],
    sums: dict[str, str],
) -> str:
    if not GITHUB_REPOSITORY.fullmatch(repository):
        fail("--github-repository must be an OWNER/REPO name")
    release_id = document.get("id")
    if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id <= 0:
        fail("GitHub release metadata id must be a positive integer")
    tag = info["release_tag"]
    api_root = f"https://api.github.com/repos/{repository}"
    web_root = f"https://github.com/{repository}"
    expected_top = {
        "url": f"{api_root}/releases/{release_id}",
        "assets_url": f"{api_root}/releases/{release_id}/assets",
        "html_url": f"{web_root}/releases/tag/{tag}",
        "tag_name": tag,
    }
    for field, expected in expected_top.items():
        if document.get(field) != expected:
            fail(f"GitHub release metadata {field} does not match {expected!r}")
    if document.get("draft") is not False:
        fail("GitHub release metadata must describe a published non-draft release")
    product_core = info["product_version"].split("+", 1)[0]
    expected_prerelease = "-" in product_core
    if document.get("prerelease") is not expected_prerelease:
        fail(
            "GitHub release prerelease state disagrees with the product version: "
            f"expected={str(expected_prerelease).lower()}"
        )
    if not isinstance(document.get("published_at"), str) or not document["published_at"]:
        fail("GitHub release metadata published_at must be non-empty")

    release_assets = document.get("assets")
    if not isinstance(release_assets, list) or len(release_assets) > MAX_ASSETS:
        fail("GitHub release metadata assets must be a bounded list")
    seen_names: set[str] = set()
    seen_ids: set[int] = set()
    for index, entry in enumerate(release_assets):
        if not isinstance(entry, dict):
            fail(f"GitHub release asset {index} must be an object")
        name = entry.get("name")
        if not isinstance(name, str):
            fail(f"GitHub release asset {index} name must be a string")
        safe_asset_name(name, f"GitHub release asset {index} name")
        if name in seen_names:
            fail(f"GitHub release metadata contains duplicate asset name: {name}")
        seen_names.add(name)
        asset_id = entry.get("id")
        if isinstance(asset_id, bool) or not isinstance(asset_id, int) or asset_id <= 0:
            fail(f"GitHub release asset {name} id must be a positive integer")
        if asset_id in seen_ids:
            fail(f"GitHub release metadata contains duplicate asset id: {asset_id}")
        seen_ids.add(asset_id)
        if entry.get("state") != "uploaded":
            fail(f"GitHub release asset is not uploaded: {name}")
        size = entry.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            fail(f"GitHub release asset size is invalid: {name}")
        if name not in assets:
            fail(f"GitHub release contains an asset absent from the download: {name}")
        if size != assets[name].stat().st_size:
            fail(f"GitHub release asset size disagrees with the download: {name}")
        expected_digest = sums.get(name)
        if expected_digest is None:
            expected_digest = hash_file(assets[name])
        if entry.get("digest") != f"sha256:{expected_digest}":
            fail(f"GitHub release asset digest disagrees with the download: {name}")
        expected_asset_url = f"{api_root}/releases/assets/{asset_id}"
        expected_download_url = f"{web_root}/releases/download/{tag}/{name}"
        if entry.get("url") != expected_asset_url:
            fail(f"GitHub release asset API URL is not canonical: {name}")
        if entry.get("browser_download_url") != expected_download_url:
            fail(f"GitHub release asset download URL is not canonical: {name}")
    if seen_names != set(assets):
        fail(
            "GitHub release/download asset inventory mismatch: "
            f"missing={sorted(set(assets) - seen_names)} "
            f"extra={sorted(seen_names - set(assets))}"
        )
    return "prerelease" if expected_prerelease else "stable"


def parse_version_output(raw: bytes, stream: str) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"downloaded binary {stream} is not UTF-8: {exc}")


def verify_binary(
    binary: pathlib.Path,
    platform: str,
    info: dict[str, str],
    native: bool,
    runner: pathlib.Path | None,
) -> None:
    if native:
        command = [str(binary), "--version"]
    else:
        assert runner is not None
        try:
            resolved_runner = runner.resolve(strict=True)
        except OSError as exc:
            fail(f"binary runner is unavailable: {exc}")
        if is_link_or_reparse(resolved_runner) or not resolved_runner.is_file():
            fail("binary runner must be an explicit regular executable file")
        command = [str(resolved_runner), str(binary), "--version"]
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"downloaded {platform} binary execution failed: {exc}")
    stdout = parse_version_output(completed.stdout, "stdout")
    stderr = parse_version_output(completed.stderr, "stderr")
    if completed.returncode != 0:
        fail(f"downloaded {platform} binary --version failed rc={completed.returncode}: {stderr[-1000:]}")
    lines = stdout.splitlines()
    if not lines or lines[0] != f"auto-refirst {info['product_version']}":
        fail(f"downloaded {platform} binary product version disagrees with BUILD_INFO")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if "=" not in line:
            fail(f"downloaded {platform} binary emitted a non-metadata version line")
        key, value = line.split("=", 1)
        if key in fields:
            fail(f"downloaded {platform} binary emitted duplicate metadata key: {key}")
        fields[key] = value
    expected = {
        "git_commit": info["public_source_commit"],
        "build_platform": info[f"{platform}_build_platform"],
        "report_schema_version": info["report_schema_version"],
    }
    if fields != expected:
        fail(f"downloaded {platform} binary metadata mismatch: expected={expected} actual={fields}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=pathlib.Path, default=CHECKER_ROOT)
    parser.add_argument("--asset-dir", type=pathlib.Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--platform", choices=sorted(EXPECTED_PLATFORMS), required=True)
    launch = parser.add_mutually_exclusive_group(required=True)
    launch.add_argument("--native-binary", action="store_true")
    launch.add_argument("--binary-runner", type=pathlib.Path)
    parser.add_argument("--check-tag", action="store_true")
    parser.add_argument("--remote", help="remote name/path to verify; requires --check-tag")
    parser.add_argument(
        "--github-release-json",
        type=pathlib.Path,
        help="fresh GitHub REST release response to bind to the downloaded asset set",
    )
    parser.add_argument(
        "--github-repository",
        help="OWNER/REPO identity; required with --github-release-json",
    )
    args = parser.parse_args()

    if not FULL_GIT_ID.fullmatch(args.expected_commit):
        fail("--expected-commit must be a full lowercase Git object id")
    if args.remote is not None and not args.check_tag:
        fail("--remote requires --check-tag")
    if (args.github_release_json is None) != (args.github_repository is None):
        fail("--github-release-json and --github-repository must be used together")
    if args.github_release_json is not None and (not args.check_tag or args.remote is None):
        fail("GitHub release verification requires --check-tag and --remote")
    root = repository_root(args.source_root)
    head = run_git(root, ["rev-parse", "HEAD"]).decode("ascii", errors="strict").strip()
    if head != args.expected_commit:
        fail(f"source HEAD {head} does not equal --expected-commit {args.expected_commit}")
    dirty = run_git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if dirty:
        entries = sum(1 for item in dirty.split(b"\0") if item)
        fail(f"source worktree is not clean ({entries} porcelain entries)")
    hygiene_summary = verify_source_hygiene(root)

    try:
        asset_dir = args.asset_dir.resolve(strict=True)
    except OSError as exc:
        fail(f"asset directory is unavailable: {exc}")
    if asset_dir == root or root in asset_dir.parents:
        fail("asset directory must be outside the source worktree")
    assets = asset_inventory(asset_dir)
    if SUMS_NAME not in assets or BUILD_INFO_NAME not in assets:
        fail(f"asset directory must contain {SUMS_NAME} and {BUILD_INFO_NAME}")
    sums = parse_sums(assets[SUMS_NAME])
    if set(assets) != set(sums) | {SUMS_NAME}:
        missing = sorted((set(assets) - {SUMS_NAME}) - set(sums))
        absent = sorted(set(sums) - set(assets))
        fail(f"asset/SHA256SUMS closure mismatch: uncovered={missing} absent={absent}")
    for name, expected in sums.items():
        actual = hash_file(assets[name])
        if actual != expected:
            fail(f"SHA256SUMS mismatch for {name}: expected={expected} actual={actual}")

    info = parse_build_info(assets[BUILD_INFO_NAME])
    verify_build_info(info, args.expected_commit)
    required_assets = {
        BUILD_INFO_NAME,
        *LEGAL_ASSETS,
        info["source_archive"],
        info["linux_artifact"],
        info["windows_artifact"],
    }
    if not required_assets.issubset(sums):
        fail(f"SHA256SUMS omits required immutable assets: {sorted(required_assets - set(sums))}")
    for name, field in (
        (info["source_archive"], "source_archive_sha256"),
        (info["linux_artifact"], "linux_sha256"),
        (info["windows_artifact"], "windows_sha256"),
    ):
        if sums[name] != info[field]:
            fail(f"BUILD_INFO {field} disagrees with SHA256SUMS for {name}")

    tree = git_tree(root)
    blobs = batch_blob_contents(root, (oid for _, oid in tree.values()))
    source_version, source_schema = source_contract(tree, blobs)
    if info["product_version"] != source_version:
        fail("BUILD_INFO product_version disagrees with the frozen source contract")
    if info["report_schema_version"] != source_schema:
        fail("BUILD_INFO report_schema_version disagrees with the frozen source contract")
    fixture_count = verify_fixture_provenance(tree, blobs)
    for name in LEGAL_ASSETS:
        if name not in tree:
            fail(f"required legal asset is not tracked at source root: {name}")
        source_bytes = blobs[tree[name][1]]
        if assets[name].read_bytes() != source_bytes:
            fail(f"release legal asset differs from frozen source blob: {name}")
    verify_source_archive(assets[info["source_archive"]], info["source_archive_root"], tree, blobs)

    tag_state = "skipped"
    if args.check_tag:
        tag_state = verify_tag(root, info["release_tag"], args.expected_commit, args.remote)

    github_release_state = "skipped"
    if args.github_release_json is not None:
        github_release_state = verify_github_release(
            read_release_metadata(args.github_release_json),
            args.github_repository,
            info,
            assets,
            sums,
        )

    selected_name = info[f"{args.platform}_artifact"]
    verify_binary(
        assets[selected_name],
        args.platform,
        info,
        args.native_binary,
        args.binary_runner,
    )
    print(hygiene_summary)
    print(
        f"[PASS] release assets: commit={args.expected_commit} assets={len(assets)} "
        f"hashed={len(sums)} archive_files={len(tree)} platform={args.platform} "
        f"fixtures={fixture_count} binary_metadata=exact tag_check={tag_state} "
        f"github_release={github_release_state} closure=exact"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
