#!/usr/bin/env python3
"""Isolated mutation negatives for the public release-asset verifier."""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
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
REPOSITORY = "fixture-owner/fixture-repo"
RELEASE_ID = 4242


@dataclass
class Fixture:
    source: pathlib.Path
    assets: pathlib.Path
    remote: pathlib.Path
    release_json: pathlib.Path
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


def load_release(fixture: Fixture) -> dict[str, object]:
    document = json.loads(fixture.release_json.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise AssertionError("fixture release metadata is not an object")
    return document


def write_release(fixture: Fixture, document: dict[str, object]) -> None:
    write_text(
        fixture.release_json,
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
    )


def refresh_release(fixture: Fixture) -> None:
    api_root = f"https://api.github.com/repos/{REPOSITORY}"
    web_root = f"https://github.com/{REPOSITORY}"
    release_assets: list[dict[str, object]] = []
    paths = sorted(
        [path for path in fixture.assets.iterdir() if path.is_file()],
        key=lambda path: path.name,
    )
    for offset, path in enumerate(paths, 1):
        asset_id = 7000 + offset
        release_assets.append(
            {
                "id": asset_id,
                "name": path.name,
                "state": "uploaded",
                "size": path.stat().st_size,
                "digest": f"sha256:{sha256(path)}",
                "url": f"{api_root}/releases/assets/{asset_id}",
                "browser_download_url": (
                    f"{web_root}/releases/download/{TAG}/{path.name}"
                ),
            }
        )
    write_release(
        fixture,
        {
            "id": RELEASE_ID,
            "url": f"{api_root}/releases/{RELEASE_ID}",
            "assets_url": f"{api_root}/releases/{RELEASE_ID}/assets",
            "html_url": f"{web_root}/releases/tag/{TAG}",
            "tag_name": TAG,
            "draft": False,
            "prerelease": True,
            "published_at": "2026-08-24T00:00:00Z",
            "assets": release_assets,
        },
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
    release_json = root / "github-release.json"
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
    fixture_payload = b"project-owned fixture payload\n"
    fixture_path = source / "tests" / "corpus" / "sample.bin"
    fixture_path.parent.mkdir(parents=True)
    fixture_path.write_bytes(fixture_payload)
    fixture_row = {
        "path": "tests/corpus/sample.bin",
        "kind": "project data",
        "source_type": "PROJECT_GENERATED",
        "source_path_or_repo": "README.md",
        "license": "Apache-2.0 for project-owned fixture data",
        "license_file": "LICENSE",
        "toolchain_version": "fixture generator 1",
        "rebuild_command": "copy project-owned fixture payload",
        "target_platform_arch": "platform-neutral",
        "reproducibility": "SOURCE_REBUILD_DOCUMENTED",
        "redistribution_rights": "OWNER_RIGHTS_ATTESTED",
        "redistributable": "true",
        "public_ci_allowed": "true",
        "sha256": hashlib.sha256(fixture_payload).hexdigest(),
        "public_action": "KEEP",
        "notes": "Project-owned isolated verifier fixture.",
    }
    write_text(
        source / contract.FIXTURE_PROVENANCE_PATH,
        ",".join(contract.FIXTURE_PROVENANCE_FIELDS)
        + "\n"
        + ",".join(fixture_row[field] for field in contract.FIXTURE_PROVENANCE_FIELDS)
        + "\n",
    )
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
    fixture = Fixture(
        source=source,
        assets=assets,
        remote=remote,
        release_json=release_json,
        head=head,
    )
    write_info(fixture, info)
    archive_entries = load_archive_entries(fixture)
    for member, _ in archive_entries:
        if member.isdir():
            member.mode = 0o755
        elif member.isfile():
            member.mode = 0o644
    write_archive_entries(fixture, archive_entries)
    refresh_sums(fixture)
    refresh_release(fixture)
    return fixture


def invoke(
    fixture: Fixture,
    *,
    github_release: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(CHECKER),
        "--source-root", str(fixture.source),
        "--asset-dir", str(fixture.assets),
        "--expected-commit", fixture.head,
        "--platform", "linux",
        "--binary-runner", sys.executable,
        "--check-tag",
        "--remote", str(fixture.remote),
    ]
    if github_release:
        command.extend(
            [
                "--github-release-json", str(fixture.release_json),
                "--github-repository", REPOSITORY,
            ]
        )
    return subprocess.run(
        command,
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


def mutate_release_tag(fixture: Fixture) -> None:
    document = load_release(fixture)
    document["tag_name"] = "v9.9.9"
    write_release(fixture, document)


def mutate_release_draft(fixture: Fixture) -> None:
    document = load_release(fixture)
    document["draft"] = True
    write_release(fixture, document)


def mutate_release_prerelease(fixture: Fixture) -> None:
    document = load_release(fixture)
    document["prerelease"] = False
    write_release(fixture, document)


def mutate_release_missing_asset(fixture: Fixture) -> None:
    document = load_release(fixture)
    assets = document["assets"]
    if not isinstance(assets, list) or not assets:
        raise AssertionError("fixture release assets are unavailable")
    assets.pop()
    write_release(fixture, document)


def mutate_release_duplicate_asset(fixture: Fixture) -> None:
    document = load_release(fixture)
    assets = document["assets"]
    if not isinstance(assets, list) or not assets:
        raise AssertionError("fixture release assets are unavailable")
    assets.append(copy.deepcopy(assets[0]))
    write_release(fixture, document)


def release_asset(fixture: Fixture) -> dict[str, object]:
    document = load_release(fixture)
    assets = document["assets"]
    if not isinstance(assets, list) or not assets or not isinstance(assets[0], dict):
        raise AssertionError("fixture release asset is unavailable")
    return document


def mutate_release_digest(fixture: Fixture) -> None:
    document = release_asset(fixture)
    assets = document["assets"]
    assert isinstance(assets, list) and isinstance(assets[0], dict)
    assets[0]["digest"] = "sha256:" + "0" * 64
    write_release(fixture, document)


def mutate_release_size(fixture: Fixture) -> None:
    document = release_asset(fixture)
    assets = document["assets"]
    assert isinstance(assets, list) and isinstance(assets[0], dict)
    size = assets[0]["size"]
    assert isinstance(size, int)
    assets[0]["size"] = size + 1
    write_release(fixture, document)


def mutate_release_download_url(fixture: Fixture) -> None:
    document = release_asset(fixture)
    assets = document["assets"]
    assert isinstance(assets, list) and isinstance(assets[0], dict)
    assets[0]["browser_download_url"] = "https://example.invalid/wrong"
    write_release(fixture, document)


def mutate_release_duplicate_key(fixture: Fixture) -> None:
    text = fixture.release_json.read_text(encoding="utf-8").rstrip("\n")
    if not text.endswith("}"):
        raise AssertionError("fixture release JSON is malformed")
    write_text(fixture.release_json, text[:-1] + f',"tag_name":"{TAG}"}}\n')


def exercise_fixture_provenance_contract(
    fixture: Fixture,
    failures: list[str],
) -> int:
    tree = contract.git_tree(fixture.source)
    blobs = contract.batch_blob_contents(
        fixture.source,
        (oid for _, oid in tree.values()),
    )
    baseline_count = contract.verify_fixture_provenance(tree, blobs)
    if baseline_count != 1:
        failures.append(
            f"fixture provenance baseline count drifted: expected=1 actual={baseline_count}"
        )
    else:
        print("[PASS MUTATION] clean fixture provenance baseline accepted")

    provenance_oid = tree[contract.FIXTURE_PROVENANCE_PATH][1]
    sample_path = "tests/corpus/sample.bin"
    sample_digest = hashlib.sha256(blobs[tree[sample_path][1]]).hexdigest()

    def with_source(value: str) -> bytes:
        reader = csv.DictReader(
            io.StringIO(blobs[provenance_oid].decode("utf-8"), newline="")
        )
        rows = list(reader)
        if len(rows) != 1:
            raise AssertionError("fixture provenance source mutation needs one row")
        rows[0]["source_path_or_repo"] = value
        output = io.StringIO(newline="")
        writer = csv.DictWriter(
            output,
            fieldnames=contract.FIXTURE_PROVENANCE_FIELDS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue().encode("utf-8")

    source_tree = dict(tree)
    source_blobs = dict(blobs)
    first_source = "tests/fixture-source/first.c"
    second_source = "tests/fixture-source/second.c"
    first_oid = "d" * 40
    second_oid = "e" * 40
    source_tree[first_source] = ("100644", first_oid)
    source_tree[second_source] = ("100644", second_oid)
    source_blobs[first_oid] = b"first fixture source\n"
    source_blobs[second_oid] = b"second fixture source\n"
    source_blobs[provenance_oid] = with_source(f"{first_source}|{second_source}")
    if contract.verify_fixture_provenance(source_tree, source_blobs) != 1:
        failures.append("fixture provenance two-source baseline count drifted")
    else:
        print("[PASS MUTATION] two tracked fixture sources accepted")

    opaque_blobs = dict(blobs)
    opaque_blobs[provenance_oid] = with_source(
        "https://example.invalid/project/source-repository"
    )
    if contract.verify_fixture_provenance(tree, opaque_blobs) != 1:
        failures.append("fixture provenance single repository URL baseline drifted")
    else:
        print("[PASS MUTATION] single repository URL source accepted")

    digest_blobs = dict(blobs)
    digest_blobs[provenance_oid] = digest_blobs[provenance_oid].replace(
        sample_digest.encode("ascii"),
        b"0" * 64,
        1,
    )
    mutation_cases: list[
        tuple[str, dict[str, tuple[str, str]], dict[str, bytes], str]
    ] = [
        (
            "fixture-provenance-digest",
            tree,
            digest_blobs,
            "provenance SHA-256 mismatch",
        )
    ]
    orphan_tree = dict(tree)
    orphan_blobs = dict(blobs)
    orphan_oid = "f" * 40
    orphan_tree["tests/corpus/orphan.bin"] = ("100644", orphan_oid)
    orphan_blobs[orphan_oid] = b"unprovenanced fixture\n"
    mutation_cases.append(
        (
            "fixture-provenance-inventory",
            orphan_tree,
            orphan_blobs,
            "provenance inventory mismatch",
        )
    )
    source_mutations = (
        (
            "fixture-provenance-second-source-untracked",
            f"{first_source}|tests/fixture-source/untracked.c",
            "source path is not tracked",
        ),
        (
            "fixture-provenance-first-source-missing",
            f"tests/fixture-source/missing.c|{second_source}",
            "source path is not tracked",
        ),
        (
            "fixture-provenance-empty-source-segment",
            f"{first_source}||{second_source}",
            "empty source segment",
        ),
        (
            "fixture-provenance-duplicate-source-segment",
            f"{first_source}| {first_source}",
            "duplicate source segment",
        ),
        (
            "fixture-provenance-mixed-source-kinds",
            f"{first_source}|https://example.invalid/project/repo",
            "mixes local source paths with repository/text sources",
        ),
        (
            "fixture-provenance-url-pipe",
            "https://example.invalid/project|source",
            "repository/text source contains the local-path delimiter",
        ),
    )
    for name, value, expected in source_mutations:
        mutated_blobs = dict(source_blobs)
        mutated_blobs[provenance_oid] = with_source(value)
        mutation_cases.append((name, source_tree, mutated_blobs, expected))
    for name, mutated_tree, mutated_blobs, expected in mutation_cases:
        try:
            contract.verify_fixture_provenance(mutated_tree, mutated_blobs)
        except SystemExit as exc:
            if expected not in str(exc):
                failures.append(
                    f"{name} rejected for wrong reason: expected={expected!r} actual={exc}"
                )
            else:
                print(f"[PASS MUTATION] {name} rejected")
        else:
            failures.append(f"{name} was not rejected")
    return len(mutation_cases)


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
    release_cases: tuple[tuple[str, Callable[[Fixture], None], str], ...] = (
        ("github-release-tag", mutate_release_tag, "tag_name does not match"),
        ("github-release-draft", mutate_release_draft, "published non-draft"),
        ("github-release-prerelease", mutate_release_prerelease, "prerelease state disagrees"),
        ("github-release-missing-asset", mutate_release_missing_asset, "inventory mismatch"),
        ("github-release-duplicate-asset", mutate_release_duplicate_asset, "duplicate asset name"),
        ("github-release-digest", mutate_release_digest, "digest disagrees"),
        ("github-release-size", mutate_release_size, "size disagrees"),
        ("github-release-download-url", mutate_release_download_url, "download URL is not canonical"),
        ("github-release-duplicate-key", mutate_release_duplicate_key, "not strict JSON"),
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
        release_baseline = initialize_fixture(parent, "github-release-baseline")
        accepted_release = invoke(release_baseline, github_release=True)
        if accepted_release.returncode != 0:
            failures.append(
                "clean GitHub release baseline rejected:\n"
                f"{accepted_release.stdout}{accepted_release.stderr}"
            )
        else:
            print("[PASS MUTATION] clean GitHub release/download baseline accepted")
        provenance_negatives = exercise_fixture_provenance_contract(
            release_baseline,
            failures,
        )
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
        for name, mutate, expected in release_cases:
            fixture = initialize_fixture(parent, name)
            mutate(fixture)
            completed = invoke(fixture, github_release=True)
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
    print(
        "[PASS MUTATION] release asset self-test: "
        f"negatives={len(cases) + len(release_cases) + provenance_negatives}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
