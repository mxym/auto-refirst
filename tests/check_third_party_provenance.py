#!/usr/bin/env python3
"""Fail-closed consistency checks for the public third-party inventory."""

from __future__ import annotations

import csv
import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "THIRD_PARTY_PROVENANCE.csv"
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
FORBIDDEN = re.compile(
    r"(?i)(?:(?<![a-z0-9+.-])[a-z]:[\\/]|\\\\|/(?:data|srv|home|users|tmp)(?:[\\/]|$)|"
    r"re-ybs|mcp-workspace|tier[-_ ]?r|holdout)"
)


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] third-party provenance: {message}")


def split_paths(value: str, field: str, component: str) -> list[str]:
    result = [item.strip() for item in value.split("|") if item.strip()]
    for item in result:
        if "\\" in item:
            fail(f"{component} {field} must use repository-relative POSIX paths: {item}")
        path = pathlib.PurePosixPath(item)
        if path.is_absolute() or ".." in path.parts:
            fail(f"{component} {field} escapes the public source root: {item}")
    return result


def existing_paths(row: dict[str, str], field: str, *, directories: bool = False) -> list[str]:
    paths = split_paths(row[field], field, row["component_id"])
    for item in paths:
        target = ROOT / pathlib.PurePosixPath(item)
        ok = target.is_dir() if directories else target.is_file()
        if not ok:
            fail(f"{row['component_id']} {field} does not exist: {item}")
    return paths


def load_inventory() -> list[dict[str, str]]:
    if not INVENTORY.is_file():
        fail(f"missing inventory: {INVENTORY.relative_to(ROOT)}")
    text = INVENTORY.read_text(encoding="utf-8")
    match = FORBIDDEN.search(text)
    if match:
        fail(f"private or absolute path marker is forbidden: {match.group(0)!r}")
    with INVENTORY.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != FIELDS:
            fail(f"unexpected columns: {reader.fieldnames!r}")
        rows = list(reader)
    if not rows:
        fail("inventory has no rows")
    ids = [row["component_id"] for row in rows]
    if any(not value for row in rows for value in (row["component_id"], row["display_name"], row["relationship"], row["upstream"], row["upstream_identity"], row["license_expression"], row["shipped_material"])):
        fail("required field is empty")
    if len(ids) != len(set(ids)):
        fail("duplicate component_id")
    return rows


def main() -> int:
    rows = load_inventory()
    by_id = {row["component_id"]: row for row in rows}
    compiled_ids = {key for key, row in by_id.items() if row["relationship"].startswith("COMPILED_")}
    reference_ids = set(by_id) - compiled_ids
    if compiled_ids != set(COMPILED):
        fail(f"compiled row mismatch: expected={sorted(COMPILED)} actual={sorted(compiled_ids)}")
    if reference_ids != REFERENCES:
        fail(f"reference row mismatch: expected={sorted(REFERENCES)} actual={sorted(reference_ids)}")

    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    sbom = json.loads((ROOT / "SBOM.spdx.json").read_text(encoding="utf-8"))
    sbom_packages = {
        package["name"]: package.get("versionInfo", "")
        for package in sbom.get("packages", [])
        if package.get("name") != "auto-refirst"
    }

    used_license_files: set[str] = set()
    used_vendored_roots: set[str] = set()
    for row in rows:
        licenses = existing_paths(row, "license_files")
        anchors = existing_paths(row, "source_anchors")
        roots = existing_paths(row, "vendored_roots", directories=True)
        used_license_files.update(path for path in licenses if path.startswith("LICENSES/"))
        used_vendored_roots.update(roots)
        if not anchors:
            fail(f"{row['component_id']} has no public source anchor")
        if row["relationship"].startswith("COMPILED_") and not licenses:
            fail(f"compiled component {row['component_id']} has no license file")
        if not licenses and not row["license_expression"].startswith("NOASSERTION_REFERENCE_ONLY"):
            fail(f"{row['component_id']} omits license files without a reference-only NOASSERTION")

    for component, (package_name, cmake_marker) in COMPILED.items():
        row = by_id[component]
        if cmake_marker not in cmake:
            fail(f"compiled component {component} is not anchored by CMake marker {cmake_marker}")
        if row["display_name"] not in notices:
            fail(f"compiled component {component} is missing from THIRD_PARTY_NOTICES.md")
        if package_name not in sbom_packages:
            fail(f"compiled component {component} is missing from SBOM.spdx.json")
        if row["upstream_identity"] != sbom_packages[package_name]:
            fail(f"{component} identity disagrees with SBOM: {row['upstream_identity']!r} != {sbom_packages[package_name]!r}")

    expected_sbom = {package for package, _ in COMPILED.values()}
    if set(sbom_packages) != expected_sbom:
        fail(f"SBOM compiled package set mismatch: expected={sorted(expected_sbom)} actual={sorted(sbom_packages)}")

    actual_license_files = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "LICENSES").iterdir() if path.is_file()
    }
    if used_license_files != actual_license_files:
        fail(f"LICENSES inventory mismatch: missing={sorted(actual_license_files-used_license_files)} extra={sorted(used_license_files-actual_license_files)}")

    actual_vendored_roots = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "third_party").iterdir() if path.is_dir()
    }
    if used_vendored_roots != actual_vendored_roots:
        fail(f"third_party root mismatch: missing={sorted(actual_vendored_roots-used_vendored_roots)} extra={sorted(used_vendored_roots-actual_vendored_roots)}")

    zstd_wrapper = (ROOT / "src/core/zstd_wrap.c").read_text(encoding="utf-8")
    if "../../third_party/zstd/zstddeclib.c" not in zstd_wrapper:
        fail("zstd vendored decoder is no longer included by src/core/zstd_wrap.c")
    zydis_header = (ROOT / "third_party/zydis/Zydis.h").read_text(encoding="utf-8", errors="replace")
    if "Zycore-C" not in zydis_header:
        fail("Zycore-C is no longer present in the Zydis amalgamation")

    print(f"[PASS] third-party provenance: {len(compiled_ids)} compiled + {len(reference_ids)} reference rows; legal/CMake/SBOM/source anchors consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
