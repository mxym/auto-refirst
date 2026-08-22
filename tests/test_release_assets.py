#!/usr/bin/env python3
"""Isolated mutation negatives for the public release-asset verifier."""

from __future__ import annotations

import copy
import hashlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass

import check_release_assets as contract


CHECKER = pathlib.Path(__file__).with_name("check_release_assets.py")
TAG = "v1.2.3-rc.1"
VERSION = "1.2.3-rc.1"
ARCHIVE = "auto-refirst-1.2.3-rc.1-source.tar.gz"
ARCHIVE_ROOT = "auto-refirst-1.2.3-rc.1"
LINUX_BINARY = "auto-refirst-linux-x64.py"
WINDOWS_BINARY = "auto-refirst-windows-x64.py"


@dataclass
class Fixture:
    source: pathlib.Path
    assets: pathlib.Path
    remote: pathlib.Path
    head: str


def run(command: list[str], *, input_bytes: bytes | None = None, timeout: int = 120) -> bytes:
    completed = subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")
        raise AssertionError(f"command failed rc={completed.returncode}: {command!r}\n{detail}")
    return completed.stdout


def git(root: pathlib.Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return run(["git", "-C", str(root), *arguments], input_bytes=input_bytes)


def write_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def commit_all(root: pathlib.Path, message: str) -> None:
    git(root, "add", "-A")
    git(
        root,
        "-c", "user.name=Release Asset Test",
        "-c", "user.email=release-assets@example.invalid",
        "commit", "-qm", message,
    )


def load_info(fixture: Fixture) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in (fixture.assets / contract.BUILD_INFO_NAME).read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        if key in result:
            raise AssertionError(f"duplicate fixture BUILD_INFO key: {key}")
        result[key] = value
    return result


def write_info(fixture: Fixture, info: dict[str, str]) -> None:
    if set(info) != set(contract.BUILD_INFO_FIELDS):
        raise AssertionError("fixture BUILD_INFO fields drifted")
    write_text(
        fixture.assets / contract.BUILD_INFO_NAME,
        "".join(f"{key}={info[key]}\n" for key in contract.BUILD_INFO_FIELDS),
    )


def refresh_sums(fixture: Fixture) -> None:
    paths = sorted(
        [
            path for path in fixture.assets.iterdir()
            if path.is_file() and path.name != contract.SUMS_NAME
        ],
        key=lambda path: path.name,
    )
    write_text(
        fixture.assets / contract.SUMS_NAME,
        "".join(f"{sha256(path)}  {path.name}\n" for path in paths),
    )


def refresh_archive_binding(fixture: Fixture) -> None:
    info = load_info(fixture)
    info["source_archive_sha256"] = sha256(fixture.assets / ARCHIVE)
    write_info(fixture, info)
    refresh_sums(fixture)


def refresh_binary_binding(fixture: Fixture, platform: str) -> None:
    info = load_info(fixture)
    name = info[f"{platform}_artifact"]
    info[f"{platform}_sha256"] = sha256(fixture.assets / name)
    write_info(fixture, info)
    refresh_sums(fixture)


def product_script(commit: str, platform: str) -> str:
    return (
        "import sys\n"
        "if sys.argv[1:] != ['--version']:\n"
        "    raise SystemExit(2)\n"
        f"print('auto-refirst {VERSION}')\n"
        f"print('git_commit={commit}')\n"
        f"print('build_platform={platform}')\n"
        "print('report_schema_version=1.0')\n"
    )


def initialize_fixture(parent: pathlib.Path, name: str) -> Fixture:
    root = parent / name
    source = root / "source"
    assets = root / "assets"
    remote = root / "remote.git"
    source.mkdir(parents=True)
    assets.mkdir()
    git(source, "init", "-q")
    git(source, "config", "core.autocrlf", "false")
    write_text(source / "README.md", "release asset fixture\n")
    write_text(source / "LICENSE", "fixture project license\n")
    write_text(source / "NOTICE", "fixture notice\n")
    write_text(source / "THIRD_PARTY_NOTICES.md", "# Fixture third-party notices\n")
    write_text(source / "SBOM.spdx.json", '{"spdxVersion":"SPDX-2.3","name":"fixture"}\n')
    write_text(source / "docs" / "PUBLIC.md", "public fixture documentation\n")
    write_text(
        source / "CMakeLists.txt",
        'set(AUTO_REFIRST_PRODUCT_VERSION "1.2.3-rc.1" CACHE STRING '
        '"Product version reported by auto-refirst --version")\n',
    )
    write_text(
        source / "include" / "prts" / "report_schema.hpp",
        'inline constexpr std::string_view kReportSchemaVersion = "1.0";\n',
    )
    commit_all(source, "fixture: initial public source")
    write_text(source / "CHANGELOG.md", "# 1.2.3-rc.1\n")
    commit_all(source, "fixture: freeze release candidate")
    head = git(source, "rev-parse", "HEAD").decode("ascii").strip()
    git(
        source,
        "-c", "user.name=Release Asset Test",
        "-c", "user.email=release-assets@example.invalid",
        "tag", "-a", TAG, "-m", "fixture release",
    )
    run(["git", "init", "--bare", "-q", str(remote)])
    git(source, "remote", "add", "verify-remote", str(remote))
    git(source, "push", "-q", "verify-remote", "HEAD:refs/heads/main", f"refs/tags/{TAG}")

    run(
        [
            "git", "-C", str(source), "archive", "--format=tar.gz",
            f"--prefix={ARCHIVE_ROOT}/", f"--output={assets / ARCHIVE}", "HEAD",
        ]
    )
    for name in contract.LEGAL_ASSETS:
        (assets / name).write_bytes(git(source, "show", f"HEAD:{name}"))
    write_text(assets / LINUX_BINARY, product_script(head, contract.EXPECTED_PLATFORMS["linux"]))
    write_text(assets / WINDOWS_BINARY, product_script(head, contract.EXPECTED_PLATFORMS["windows"]))
    info = {
        "release_tag": TAG,
        "product_version": VERSION,
        "public_source_commit": head,
        "report_schema_version": "1.0",
        "source_tree_state": "CLEAN",
        "reproducibility_contract": "SEMANTICALLY_REPRODUCIBLE",
        "bit_reproducible": "false",
        "source_archive": ARCHIVE,
        "source_archive_root": ARCHIVE_ROOT,
        "source_archive_sha256": sha256(assets / ARCHIVE),
        "linux_artifact": LINUX_BINARY,
        "linux_sha256": sha256(assets / LINUX_BINARY),
        "linux_build_platform": contract.EXPECTED_PLATFORMS["linux"],
        "linux_toolchain": "fixture GCC 13",
        "linux_cmake_version": "3.30.1",
        "linux_build_flags": "Release;AUTO_REFIRST_WARNINGS_AS_ERRORS=ON",
        "linux_hosted_run_id": "101",
        "linux_hosted_head_sha": head,
        "linux_hosted_result": "PASS",
        "windows_artifact": WINDOWS_BINARY,
        "windows_sha256": sha256(assets / WINDOWS_BINARY),
        "windows_build_platform": contract.EXPECTED_PLATFORMS["windows"],
        "windows_toolchain": "fixture MSVC 19.40",
        "windows_cmake_version": "3.30.1",
        "windows_build_flags": "Release;AUTO_REFIRST_WARNINGS_AS_ERRORS=ON",
        "windows_hosted_run_id": "102",
        "windows_hosted_head_sha": head,
        "windows_hosted_result": "PASS",
        "sanitizer_hosted_run_id": "103",
        "sanitizer_hosted_head_sha": head,
        "sanitizer_hosted_result": "PASS",
    }
    fixture = Fixture(source=source, assets=assets, remote=remote, head=head)
    write_info(fixture, info)
    archive_entries = load_archive_entries(fixture)
    for member, _ in archive_entries:
        if member.isdir():
            member.mode = 0o755
        elif member.isfile():
            member.mode = 0o644
    write_archive_entries(fixture, archive_entries)
    refresh_sums(fixture)
    return fixture


def invoke(fixture: Fixture) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CHECKER),
            "--source-root", str(fixture.source),
            "--asset-dir", str(fixture.assets),
            "--expected-commit", fixture.head,
            "--platform", "linux",
            "--binary-runner", sys.executable,
            "--check-tag",
            "--remote", str(fixture.remote),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )


def mutate_dirty_source(fixture: Fixture) -> None:
    write_text(fixture.source / "README.md", "dirty source\n")


def mutate_local_tag(fixture: Fixture) -> None:
    git(
        fixture.source,
        "-c", "user.name=Release Asset Test",
        "-c", "user.email=release-assets@example.invalid",
        "tag", "-f", "-a", TAG, "HEAD^", "-m", "stale local tag",
    )


def mutate_remote_tag(fixture: Fixture) -> None:
    parent = git(fixture.source, "rev-parse", "HEAD^").decode("ascii").strip()
    git(fixture.remote, "update-ref", f"refs/tags/{TAG}", parent)


def mutate_uncovered_asset(fixture: Fixture) -> None:
    (fixture.assets / "EXTRA.bin").write_bytes(b"uncovered\n")


def mutate_missing_sum(fixture: Fixture) -> None:
    path = fixture.assets / contract.SUMS_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if not line.endswith("  NOTICE")]
    if len(kept) + 1 != len(lines):
        raise AssertionError("NOTICE sum row was not unique")
    write_text(path, "\n".join(kept) + "\n")


def mutate_bad_sum(fixture: Fixture) -> None:
    path = fixture.assets / contract.SUMS_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = ("0" if lines[0][0] != "0" else "1") + lines[0][1:]
    write_text(path, "\n".join(lines) + "\n")


def mutate_duplicate_sum(fixture: Fixture) -> None:
    path = fixture.assets / contract.SUMS_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    write_text(path, "\n".join([lines[0], lines[0], *lines[1:]]) + "\n")


def mutate_dangerous_sum_path(fixture: Fixture) -> None:
    path = fixture.assets / contract.SUMS_NAME
    text = path.read_text(encoding="utf-8")
    write_text(path, text + f"{'0' * 64}  ../escape\n")


def mutate_duplicate_build_key(fixture: Fixture) -> None:
    path = fixture.assets / contract.BUILD_INFO_NAME
    text = path.read_text(encoding="utf-8")
    write_text(path, text + f"release_tag={TAG}\n")
    refresh_sums(fixture)


def update_info(fixture: Fixture, key: str, value: str) -> None:
    info = load_info(fixture)
    info[key] = value
    write_info(fixture, info)
    refresh_sums(fixture)


def mutate_build_commit(fixture: Fixture) -> None:
    update_info(fixture, "public_source_commit", "1" * 40)


def mutate_bit_reproducibility(fixture: Fixture) -> None:
    update_info(fixture, "bit_reproducible", "true")


def mutate_hosted_head(fixture: Fixture) -> None:
    update_info(fixture, "linux_hosted_head_sha", "2" * 40)


def mutate_source_version_binding(fixture: Fixture) -> None:
    info = load_info(fixture)
    info["product_version"] = "1.2.4-rc.1"
    info["release_tag"] = "v1.2.4-rc.1"
    write_info(fixture, info)
    refresh_sums(fixture)


def mutate_source_schema_binding(fixture: Fixture) -> None:
    update_info(fixture, "report_schema_version", "1.1")


def load_archive_entries(fixture: Fixture) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    result: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(fixture.assets / ARCHIVE, "r:gz") as handle:
        for member in handle:
            payload = handle.extractfile(member).read() if member.isfile() else None
            result.append((copy.copy(member), payload))
    return result


def write_archive_entries(fixture: Fixture, entries: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
    target = fixture.assets / ARCHIVE
    temporary = fixture.assets / "archive-rewrite.tmp"
    with tarfile.open(temporary, "w:gz") as handle:
        for member, payload in entries:
            handle.addfile(member, io.BytesIO(payload) if payload is not None else None)
    os.replace(temporary, target)
    refresh_archive_binding(fixture)


def mutate_archive_extra(fixture: Fixture) -> None:
    entries = load_archive_entries(fixture)
    payload = b"private\n"
    member = tarfile.TarInfo(f"{ARCHIVE_ROOT}/research/secret.txt")
    member.mode = 0o644
    member.size = len(payload)
    entries.append((member, payload))
    write_archive_entries(fixture, entries)


def mutate_archive_content(fixture: Fixture) -> None:
    entries = load_archive_entries(fixture)
    for index, (member, payload) in enumerate(entries):
        if member.name == f"{ARCHIVE_ROOT}/README.md":
            payload = b"drifted archive bytes\n"
            member.size = len(payload)
            entries[index] = (member, payload)
            break
    else:
        raise AssertionError("README archive member missing")
    write_archive_entries(fixture, entries)


def mutate_archive_missing(fixture: Fixture) -> None:
    entries = [
        entry for entry in load_archive_entries(fixture)
        if entry[0].name != f"{ARCHIVE_ROOT}/README.md"
    ]
    write_archive_entries(fixture, entries)


def mutate_archive_symlink(fixture: Fixture) -> None:
    entries = load_archive_entries(fixture)
    member = tarfile.TarInfo(f"{ARCHIVE_ROOT}/escape-link")
    member.type = tarfile.SYMTYPE
    member.linkname = "../../outside"
    member.mode = 0o777
    entries.append((member, None))
    write_archive_entries(fixture, entries)


def mutate_archive_unsafe_path(fixture: Fixture) -> None:
    entries = load_archive_entries(fixture)
    payload = b"escape\n"
    member = tarfile.TarInfo("../escape.txt")
    member.mode = 0o644
    member.size = len(payload)
    entries.append((member, payload))
    write_archive_entries(fixture, entries)


def mutate_archive_absolute_path(fixture: Fixture) -> None:
    entries = load_archive_entries(fixture)
    payload = b"escape\n"
    member = tarfile.TarInfo("/absolute-escape.txt")
    member.mode = 0o644
    member.size = len(payload)
    entries.append((member, payload))
    write_archive_entries(fixture, entries)


def mutate_archive_duplicate(fixture: Fixture) -> None:
    entries = load_archive_entries(fixture)
    duplicate = next(entry for entry in entries if entry[0].name == f"{ARCHIVE_ROOT}/README.md")
    entries.append((copy.copy(duplicate[0]), duplicate[1]))
    write_archive_entries(fixture, entries)


def mutate_archive_mode(fixture: Fixture) -> None:
    entries = load_archive_entries(fixture)
    for member, _ in entries:
        if member.name == f"{ARCHIVE_ROOT}/README.md":
            member.mode = 0o600
            break
    write_archive_entries(fixture, entries)


def mutate_archive_root(fixture: Fixture) -> None:
    update_info(fixture, "source_archive_root", "wrong-root")


def mutate_binary_metadata(fixture: Fixture) -> None:
    write_text(
        fixture.assets / LINUX_BINARY,
        product_script("3" * 40, contract.EXPECTED_PLATFORMS["linux"]),
    )
    refresh_binary_binding(fixture, "linux")


def mutate_legal_asset(fixture: Fixture) -> None:
    write_text(fixture.assets / "NOTICE", "mutated release notice\n")
    refresh_sums(fixture)


def main() -> int:
    cases: tuple[tuple[str, Callable[[Fixture], None], str], ...] = (
        ("dirty-source", mutate_dirty_source, "source worktree is not clean"),
        ("stale-local-tag", mutate_local_tag, "local release tag peels"),
        ("stale-remote-tag", mutate_remote_tag, "remote release tag object"),
        ("uncovered-asset", mutate_uncovered_asset, "asset/SHA256SUMS closure mismatch"),
        ("missing-sum-row", mutate_missing_sum, "asset/SHA256SUMS closure mismatch"),
        ("bad-sum", mutate_bad_sum, "SHA256SUMS mismatch"),
        ("duplicate-sum", mutate_duplicate_sum, "duplicate filename"),
        ("dangerous-sum-path", mutate_dangerous_sum_path, "not canonical lowercase SHA-256 format"),
        ("duplicate-build-key", mutate_duplicate_build_key, "duplicate key"),
        ("build-commit", mutate_build_commit, "public_source_commit does not equal"),
        ("bit-reproducibility", mutate_bit_reproducibility, "must not claim bit reproducibility"),
        ("hosted-head", mutate_hosted_head, "hosted_head_sha does not equal"),
        (
            "source-version-binding",
            mutate_source_version_binding,
            "product_version disagrees with the frozen source contract",
        ),
        (
            "source-schema-binding",
            mutate_source_schema_binding,
            "report_schema_version disagrees with the frozen source contract",
        ),
        ("archive-extra", mutate_archive_extra, "untracked or misplaced file"),
        ("archive-content", mutate_archive_content, "bytes disagree with Git blob"),
        ("archive-missing", mutate_archive_missing, "file inventory mismatch"),
        ("archive-symlink", mutate_archive_symlink, "not a regular file/directory"),
        ("archive-unsafe-path", mutate_archive_unsafe_path, "unsafe or non-canonical path"),
        ("archive-absolute-path", mutate_archive_absolute_path, "unsafe or non-canonical path"),
        ("archive-duplicate", mutate_archive_duplicate, "duplicate member"),
        ("archive-mode", mutate_archive_mode, "mode disagrees with Git"),
        ("archive-root", mutate_archive_root, "untracked or misplaced file"),
        ("binary-metadata", mutate_binary_metadata, "binary metadata mismatch"),
        ("legal-asset", mutate_legal_asset, "release legal asset differs"),
    )
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="auto-refirst-release-assets-") as raw:
        parent = pathlib.Path(raw)
        baseline = initialize_fixture(parent, "baseline")
        accepted = invoke(baseline)
        if accepted.returncode != 0:
            failures.append(f"clean baseline rejected:\n{accepted.stdout}{accepted.stderr}")
        else:
            print("[PASS MUTATION] clean staged/download asset baseline accepted")
        for name, mutate, expected in cases:
            fixture = initialize_fixture(parent, name)
            mutate(fixture)
            completed = invoke(fixture)
            output = completed.stdout + completed.stderr
            if completed.returncode == 0 or expected not in output:
                failures.append(
                    f"{name} was not rejected as expected: rc={completed.returncode} "
                    f"expected={expected!r}\n{output}"
                )
            else:
                print(f"[PASS MUTATION] {name} rejected")
    if failures:
        print(f"[FAIL MUTATION] release asset self-test: failures={len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"[PASS MUTATION] release asset self-test: negatives={len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
