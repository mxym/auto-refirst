#!/usr/bin/env python3
"""Validate the exact public CMake install file and legal-asset contract."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import stat
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ("README.md", "README_EN.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")
LICENSES = (
    "CPython-PSF-2.0.txt",
    "Dart-BSD-3-Clause.txt",
    "Go-BSD-3-Clause.txt",
    "libPeConv-BSD-2-Clause.txt",
    "miniz-MIT.txt",
    "rustc-demangle-Apache-2.0.txt",
    "rustc-demangle-MIT.txt",
    "tiny-AES-c-Unlicense.txt",
    "UPX-COPYING-GPL-2.0.txt",
    "UPX-LICENSE.txt",
    "zstd-BSD-3-Clause.txt",
    "Zycore-MIT.txt",
    "Zydis-MIT.txt",
)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] public install staging: {message}")


def is_link_or_junction(path: pathlib.Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction and isjunction(path):
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def inventory(stage: pathlib.Path) -> tuple[set[pathlib.PurePosixPath], set[pathlib.PurePosixPath]]:
    files: set[pathlib.PurePosixPath] = set()
    directories: set[pathlib.PurePosixPath] = set()
    if is_link_or_junction(stage) or not stage.is_dir():
        fail(f"stage root is missing, symlinked, or non-directory: {stage}")
    for root, dirnames, filenames in os.walk(stage, followlinks=False):
        base = pathlib.Path(root)
        for name in dirnames:
            path = base / name
            rel = pathlib.PurePosixPath(path.relative_to(stage).as_posix())
            if is_link_or_junction(path) or not stat.S_ISDIR(path.lstat().st_mode):
                fail(f"non-directory or linked directory is outside the install contract: {rel}")
            directories.add(rel)
        for name in filenames:
            path = base / name
            rel = pathlib.PurePosixPath(path.relative_to(stage).as_posix())
            if is_link_or_junction(path) or not stat.S_ISREG(path.lstat().st_mode):
                fail(f"non-regular or linked file is outside the install contract: {rel}")
            files.add(rel)
    return files, directories


def validate(stage: pathlib.Path, build_binary: pathlib.Path, skip_run: bool) -> None:
    exe_name = "auto-refirst.exe" if build_binary.suffix.lower() == ".exe" else "auto-refirst"
    doc_root = pathlib.PurePosixPath("share/doc/auto-refirst")
    expected_files = {
        pathlib.PurePosixPath("bin") / exe_name,
        *(doc_root / name for name in DOCS),
        *(doc_root / "LICENSES" / name for name in LICENSES),
    }
    expected_directories = {
        pathlib.PurePosixPath("bin"), pathlib.PurePosixPath("share"),
        pathlib.PurePosixPath("share/doc"), doc_root, doc_root / "LICENSES",
    }
    files, directories = inventory(stage)
    if files != expected_files:
        fail(f"file set mismatch; missing={sorted(map(str, expected_files-files))} extra={sorted(map(str, files-expected_files))}")
    if directories != expected_directories:
        fail(f"directory set mismatch; missing={sorted(map(str, expected_directories-directories))} extra={sorted(map(str, directories-expected_directories))}")

    actual_source_licenses = {path.name for path in (ROOT / "LICENSES").iterdir() if path.is_file()}
    if actual_source_licenses != set(LICENSES):
        fail(f"source LICENSES drift; missing={sorted(set(LICENSES)-actual_source_licenses)} extra={sorted(actual_source_licenses-set(LICENSES))}")

    staged_binary = stage / "bin" / exe_name
    if sha256(staged_binary) != sha256(build_binary):
        fail("staged binary bytes differ from the selected build binary")
    for name in DOCS:
        if sha256(ROOT / name) != sha256(stage / "share/doc/auto-refirst" / name):
            fail(f"staged documentation differs from source: {name}")
    for name in LICENSES:
        if sha256(ROOT / "LICENSES" / name) != sha256(stage / "share/doc/auto-refirst/LICENSES" / name):
            fail(f"staged license differs from source: {name}")

    can_run = not skip_run and not (staged_binary.suffix.lower() == ".exe" and os.name != "nt")
    if can_run:
        result = subprocess.run([str(staged_binary), "--version"], capture_output=True, text=True, timeout=15)
        if result.returncode != 0 or not result.stdout.strip().startswith("auto-refirst "):
            fail(f"staged --version smoke failed: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}")
    print(f"[PASS] public install staging: {len(files)} exact files; binary/docs/licenses byte-identical" + ("; version smoke PASS" if can_run else "; execution skipped"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-binary", required=True, type=pathlib.Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--stage-root", type=pathlib.Path, help="Validate an existing install prefix.")
    mode.add_argument("--build-dir", type=pathlib.Path, help="Run cmake --install into a temporary prefix, then validate it.")
    parser.add_argument("--config", default="", help="CMake multi-config configuration, for example Release.")
    parser.add_argument("--skip-run", action="store_true", help="Do not execute the staged binary.")
    args = parser.parse_args()

    build_binary = args.build_binary.resolve()
    if not build_binary.is_file():
        fail(f"build binary missing: {build_binary}")
    if args.stage_root:
        # Keep the lexical stage path so inventory() can reject a stage-root
        # symlink or junction instead of silently following it via resolve().
        stage_root = pathlib.Path(os.path.abspath(args.stage_root))
        validate(stage_root, build_binary, args.skip_run)
        return 0

    build_dir = args.build_dir.resolve()
    if not (build_dir / "CMakeCache.txt").is_file():
        fail(f"configured CMake build directory missing: {build_dir}")
    with tempfile.TemporaryDirectory(prefix="auto-refirst-public-install-") as raw:
        command = ["cmake", "--install", str(build_dir), "--prefix", raw]
        if args.config:
            command.extend(["--config", args.config])
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            fail(f"cmake --install failed: rc={result.returncode}\n{result.stdout}\n{result.stderr}")
        validate(pathlib.Path(raw), build_binary, args.skip_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
