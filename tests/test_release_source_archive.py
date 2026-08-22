#!/usr/bin/env python3
"""Isolated determinism and fail-closed tests for the source archive generator."""

from __future__ import annotations

import gzip
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from unittest import mock

import check_release_assets as contract
import create_release_source_archive as generator


SCRIPT = pathlib.Path(__file__).resolve().with_name("create_release_source_archive.py")
ARCHIVE_ROOT = "auto-refirst-test-1.0.0"
FIXED_GIT_DATE = "1700000000 +0000"


def run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if environment:
        env.update(environment)
    return subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
    )


def git(root: pathlib.Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = run(["git", "-C", str(root), *arguments], input_bytes=input_bytes)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def write_file(root: pathlib.Path, relative: str, data: bytes) -> None:
    path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def commit_all(root: pathlib.Path, message: str) -> str:
    git(root, "add", "-A")
    return commit_index(root, message)


def commit_index(root: pathlib.Path, message: str) -> str:
    env = {"GIT_AUTHOR_DATE": FIXED_GIT_DATE, "GIT_COMMITTER_DATE": FIXED_GIT_DATE}
    completed = run(["git", "-C", str(root), "commit", "-q", "-m", message], environment=env)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"git commit failed: {detail}")
    return git(root, "rev-parse", "HEAD").decode("ascii").strip()


def initialize_repository(root: pathlib.Path) -> str:
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Source Archive Test")
    git(root, "config", "user.email", "source-archive@example.invalid")
    git(root, "config", "core.autocrlf", "false")
    git(root, "config", "core.filemode", "false")
    write_file(root, "README.md", b"deterministic source archive fixture\n")
    write_file(root, "bin/tool.sh", b"#!/bin/sh\nexit 0\n")
    long_directory = "d" * 70
    long_filename = "f" * 70 + ".txt"
    write_file(root, f"nested/{long_directory}/{long_filename}", b"USTAR split boundary\n")
    git(root, "add", "-A")
    git(root, "update-index", "--chmod=+x", "bin/tool.sh")
    return commit_all(root, "fixture")


def invoke(
    root: pathlib.Path,
    output: pathlib.Path,
    *,
    expected_commit: str | None = None,
    archive_root: str = ARCHIVE_ROOT,
) -> subprocess.CompletedProcess[bytes]:
    commit = expected_commit or git(root, "rev-parse", "HEAD").decode("ascii").strip()
    return run(
        [
            sys.executable,
            str(SCRIPT),
            "--source-root",
            str(root),
            "--output",
            str(output),
            "--expected-commit",
            commit,
            "--archive-root",
            archive_root,
        ]
    )


def require_success(completed: subprocess.CompletedProcess[bytes], label: str) -> None:
    if completed.returncode != 0:
        output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
        raise RuntimeError(f"{label} failed:\n{output}")


def parse_raw_ustar(payload: bytes) -> tuple[list[str], list[bytes]]:
    names: list[str] = []
    types: list[bytes] = []
    offset = 0
    while offset + 512 <= len(payload):
        header = payload[offset:offset + 512]
        if header == b"\0" * 512:
            if any(payload[offset:]):
                raise RuntimeError("USTAR has non-zero bytes after the end marker")
            break
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            raise RuntimeError("archive member is not a canonical USTAR header")
        type_flag = header[156:157] or b"0"
        if type_flag in (b"x", b"g"):
            raise RuntimeError("archive contains a PAX header")
        raw_name = header[0:100].split(b"\0", 1)[0]
        raw_prefix = header[345:500].split(b"\0", 1)[0]
        raw_path = raw_prefix + (b"/" if raw_prefix else b"") + raw_name
        names.append(raw_path.decode("ascii", errors="strict"))
        types.append(type_flag)
        raw_size = header[124:136].rstrip(b"\0 ") or b"0"
        size = int(raw_size, 8)
        offset += 512 + ((size + 511) // 512) * 512
    else:
        raise RuntimeError("USTAR omitted the zero-block terminator")
    return names, types


def verify_canonical_archive(root: pathlib.Path, first: pathlib.Path, second: pathlib.Path) -> None:
    first_bytes = first.read_bytes()
    if first_bytes != second.read_bytes():
        raise RuntimeError("two archive generations are not byte-identical")
    commit_time = int(git(root, "show", "-s", "--format=%ct", "HEAD").decode("ascii"))
    if first_bytes[0:3] != b"\x1f\x8b\x08" or first_bytes[3] != 0:
        raise RuntimeError("gzip header has non-canonical magic/method/flags or embeds FNAME/COMMENT")
    if int.from_bytes(first_bytes[4:8], "little") != commit_time:
        raise RuntimeError("gzip MTIME does not equal the exact commit timestamp")
    if first_bytes[8] != 2 or first_bytes[9] != 255:
        raise RuntimeError("gzip XFL/OS bytes are not canonical 2/255")

    tree = contract.git_tree(root)
    blobs = contract.batch_blob_contents(root, (oid for _, oid in tree.values()))
    contract.verify_source_archive(first, ARCHIVE_ROOT, tree, blobs)
    contract.verify_source_archive(second, ARCHIVE_ROOT, tree, blobs)
    expected_directories = generator.directory_names(ARCHIVE_ROOT, tree)
    expected_names = expected_directories + [
        f"{ARCHIVE_ROOT}/{relative}" for relative in sorted(tree)
    ]
    expected_raw_names = [name + "/" for name in expected_directories] + expected_names[len(expected_directories):]
    raw_names, raw_types = parse_raw_ustar(gzip.decompress(first_bytes))
    if raw_names != expected_raw_names or any(flag not in (b"0", b"5") for flag in raw_types):
        mismatch = next(
            (
                f"index={index} expected={expected!r} actual={actual!r} type={raw_types[index]!r}"
                for index, (expected, actual) in enumerate(zip(expected_raw_names, raw_names))
                if expected != actual or raw_types[index] not in (b"0", b"5")
            ),
            f"expected_count={len(expected_raw_names)} actual_count={len(raw_names)} types={raw_types[:4]!r}",
        )
        raise RuntimeError(f"USTAR member order/type set is not canonical: {mismatch}")

    with tarfile.open(first, mode="r:gz", format=tarfile.USTAR_FORMAT) as archive:
        members = archive.getmembers()
    if [member.name.rstrip("/") if member.isdir() else member.name for member in members] != expected_names:
        raise RuntimeError("tarfile member order disagrees with the canonical inventory")
    expected_directory_set = set(expected_directories)
    for member in members:
        if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
            raise RuntimeError(f"archive owner metadata is not canonical: {member.name}")
        if member.mtime != commit_time or member.pax_headers:
            raise RuntimeError(f"archive time/PAX metadata is not canonical: {member.name}")
        canonical_name = member.name.rstrip("/") if member.isdir() else member.name
        if canonical_name in expected_directory_set:
            if not member.isdir() or member.mode != 0o755:
                raise RuntimeError(f"archive directory metadata is not canonical: {member.name}")
        else:
            relative = canonical_name[len(ARCHIVE_ROOT) + 1:]
            expected_mode = 0o755 if tree[relative][0] == "100755" else 0o644
            if not member.isfile() or member.mode != expected_mode:
                raise RuntimeError(f"archive file metadata is not canonical: {member.name}")


def clone_repository(seed: pathlib.Path, target: pathlib.Path) -> pathlib.Path:
    completed = run(["git", "clone", "-q", str(seed), str(target)])
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))
    git(target, "config", "user.name", "Source Archive Test")
    git(target, "config", "user.email", "source-archive@example.invalid")
    git(target, "config", "core.autocrlf", "false")
    git(target, "config", "core.filemode", "false")
    return target


def expect_rejected(
    name: str,
    root: pathlib.Path,
    output: pathlib.Path,
    expected: str,
    *,
    expected_commit: str | None = None,
    archive_root: str = ARCHIVE_ROOT,
) -> None:
    completed = invoke(
        root,
        output,
        expected_commit=expected_commit,
        archive_root=archive_root,
    )
    text = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    if completed.returncode == 0 or expected not in text:
        raise RuntimeError(f"{name} was not rejected as expected={expected!r}: rc={completed.returncode}\n{text}")
    print(f"[PASS MUTATION] {name} rejected")


def direct_boundary_negatives() -> None:
    oid = "0" * 40
    cases = (
        ("control-path", {"bad\nname": ("100644", oid)}, "non-printable"),
        ("unicode-path", {"snowman-\u2603.txt": ("100644", oid)}, "printable ASCII"),
        ("case-collision", {"A.txt": ("100644", oid), "a.txt": ("100644", oid)}, "case folding"),
        ("long-component", {("x" * 101): ("100644", oid)}, "canonical USTAR"),
        ("unsafe-character", {"bad:name": ("100644", oid)}, "portable archive character set"),
        ("reserved-component", {"CON.txt": ("100644", oid)}, "reserved component"),
    )
    for name, tree, expected in cases:
        try:
            generator.validate_tree_paths(tree, ARCHIVE_ROOT)
        except SystemExit as exc:
            if expected not in str(exc):
                raise RuntimeError(f"{name} rejected for unexpected reason: {exc}") from exc
        else:
            raise RuntimeError(f"{name} was accepted")
        print(f"[PASS MUTATION] {name} rejected")


def archive_root_negatives() -> None:
    cases = (
        ("root-dot", ".", "safe basename"),
        ("root-dot-dot", "..", "safe basename"),
        ("root-reserved-con", "CON", "reserved component"),
        ("root-reserved-nul", "nul.txt", "reserved component"),
        ("root-trailing-dot", "release.", "trailing character"),
        ("root-trailing-space", "release ", "safe basename"),
        ("root-separator", "release/root", "safe basename"),
        ("root-colon", "release:root", "safe basename"),
        ("root-control", "release\nroot", "safe basename"),
    )
    for name, value, expected in cases:
        try:
            generator.validate_archive_root(value)
        except SystemExit as exc:
            if expected not in str(exc):
                raise RuntimeError(f"{name} rejected for unexpected reason: {exc}") from exc
        else:
            raise RuntimeError(f"{name} was accepted")
        print(f"[PASS MUTATION] {name} rejected")


def atomic_publication_tests(root: pathlib.Path, parent: pathlib.Path) -> None:
    tree = contract.git_tree(root)
    blobs = contract.batch_blob_contents(root, (oid for _, oid in tree.values()))
    source_date_epoch = int(git(root, "show", "-s", "--format=%ct", "HEAD").decode("ascii"))
    real_publish = generator.publish_no_clobber

    visible = parent / "partial-visibility.tar.gz"
    observed = False

    def observe_publish(temporary: pathlib.Path, output: pathlib.Path) -> None:
        nonlocal observed
        if output != visible or os.path.lexists(output) or temporary.stat().st_size == 0:
            raise RuntimeError("partial final filename was visible before atomic publication")
        observed = True
        real_publish(temporary, output)

    with mock.patch.object(generator, "publish_no_clobber", side_effect=observe_publish):
        generator.create_archive(visible, ARCHIVE_ROOT, tree, blobs, source_date_epoch)
    if not observed or not visible.is_file() or list(parent.glob(f".{visible.name}.*.tmp")):
        raise RuntimeError("atomic publication did not leave exactly one complete final file")
    visible.unlink()
    print("[PASS MUTATION] partial-final-invisible until atomic publication")

    raced = parent / "concurrent.tar.gz"
    sentinel = b"concurrent owner\n"

    def competing_publish(temporary: pathlib.Path, output: pathlib.Path) -> None:
        output.write_bytes(sentinel)
        real_publish(temporary, output)

    try:
        with mock.patch.object(generator, "publish_no_clobber", side_effect=competing_publish):
            generator.create_archive(raced, ARCHIVE_ROOT, tree, blobs, source_date_epoch)
    except SystemExit as exc:
        if "appeared before atomic publication" not in str(exc):
            raise RuntimeError(f"concurrent publication rejected for unexpected reason: {exc}") from exc
    else:
        raise RuntimeError("concurrent final creation was overwritten")
    if raced.read_bytes() != sentinel or list(parent.glob(f".{raced.name}.*.tmp")):
        raise RuntimeError("concurrent owner's final file changed or generator temp leaked")
    raced.unlink()
    print("[PASS MUTATION] concurrent-final preserved and owned temp removed")

    broken = parent / "exception.tar.gz"
    try:
        with mock.patch.object(generator.gzip, "GzipFile", side_effect=RuntimeError("injected write failure")):
            generator.create_archive(broken, ARCHIVE_ROOT, tree, blobs, source_date_epoch)
    except RuntimeError as exc:
        if "injected write failure" not in str(exc):
            raise
    else:
        raise RuntimeError("injected archive failure was accepted")
    if os.path.lexists(broken) or list(parent.glob(f".{broken.name}.*.tmp")):
        raise RuntimeError("exception path exposed a final file or leaked the owned temp")
    print("[PASS MUTATION] exceptional-write cleaned owned temp without final exposure")

    replaced = parent / ".owned-temp.tmp"
    replaced.write_bytes(b"owned")
    owned_stat = replaced.lstat()
    identity = (owned_stat.st_dev, owned_stat.st_ino)
    replaced.unlink()
    replaced.write_bytes(b"replacement owner")
    if generator.unlink_owned(replaced, identity) or replaced.read_bytes() != b"replacement owner":
        raise RuntimeError("replaced temp path was mistaken for the generator-owned file")
    replaced.unlink()
    print("[PASS MUTATION] replaced-temp preserved by identity-checked cleanup")


def main() -> int:
    failures: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="auto-refirst-source-archive-") as raw:
            parent = pathlib.Path(raw)
            seed = parent / "seed"
            initialize_repository(seed)
            first = parent / "first.tar.gz"
            second = parent / "second.tar.gz"
            require_success(invoke(seed, first), "first generation")
            require_success(invoke(seed, second), "second generation")
            verify_canonical_archive(seed, first, second)
            print("[PASS] deterministic source archive baseline: generations=2 bytes=identical verifier=accepted")
            atomic_publication_tests(seed, parent)

            dirty = clone_repository(seed, parent / "dirty")
            write_file(dirty, "README.md", b"dirty\n")
            expect_rejected("dirty-worktree", dirty, parent / "dirty.tar.gz", "not clean")

            untracked = clone_repository(seed, parent / "untracked")
            write_file(untracked, "untracked.txt", b"untracked\n")
            expect_rejected("untracked-file", untracked, parent / "untracked.tar.gz", "not clean")

            staged = clone_repository(seed, parent / "staged")
            write_file(staged, "staged.txt", b"staged\n")
            git(staged, "add", "staged.txt")
            expect_rejected("index-drift", staged, parent / "staged.tar.gz", "not clean")

            wrong = clone_repository(seed, parent / "wrong-commit")
            expect_rejected(
                "wrong-commit",
                wrong,
                parent / "wrong.tar.gz",
                "does not equal --expected-commit",
                expected_commit="0" * 40,
            )

            existing = clone_repository(seed, parent / "existing")
            existing_output = parent / "existing.tar.gz"
            existing_output.write_bytes(b"do not overwrite")
            expect_rejected("existing-output", existing, existing_output, "already exists")
            if existing_output.read_bytes() != b"do not overwrite":
                raise RuntimeError("existing output was modified")

            inside = clone_repository(seed, parent / "inside")
            expect_rejected("output-inside-source", inside, inside / "source.tar.gz", "outside the source worktree")

            unsafe = clone_repository(seed, parent / "unsafe-root")
            expect_rejected(
                "unsafe-archive-root",
                unsafe,
                parent / "unsafe.tar.gz",
                "safe basename",
                archive_root="../escape",
            )

            unicode_repo = clone_repository(seed, parent / "unicode")
            write_file(unicode_repo, "unicode-\u2603.txt", b"unicode path\n")
            commit_all(unicode_repo, "unicode path")
            expect_rejected("tracked-unicode-path", unicode_repo, parent / "unicode.tar.gz", "printable ASCII")

            long_repo = clone_repository(seed, parent / "overlong")
            write_file(long_repo, "x" * 101, b"overlong component\n")
            commit_all(long_repo, "overlong path")
            expect_rejected("tracked-overlong-path", long_repo, parent / "overlong.tar.gz", "canonical USTAR")

            symlink_repo = clone_repository(seed, parent / "symlink")
            oid = git(symlink_repo, "hash-object", "-w", "--stdin", input_bytes=b"target").decode("ascii").strip()
            write_file(symlink_repo, "tracked-link", b"target")
            git(symlink_repo, "update-index", "--add", "--cacheinfo", f"120000,{oid},tracked-link")
            commit_index(symlink_repo, "tracked symlink")
            git(symlink_repo, "reset", "--hard", "-q")
            expect_rejected(
                "tracked-symlink",
                symlink_repo,
                parent / "symlink.tar.gz",
                "tracked symlink is forbidden",
            )

            gitlink_repo = clone_repository(seed, parent / "gitlink")
            target = git(gitlink_repo, "rev-parse", "HEAD").decode("ascii").strip()
            git(gitlink_repo, "update-index", "--add", "--cacheinfo", f"160000,{target},tracked-submodule")
            commit_index(gitlink_repo, "tracked gitlink")
            git(gitlink_repo, "reset", "--hard", "-q")
            expect_rejected(
                "tracked-gitlink",
                gitlink_repo,
                parent / "gitlink.tar.gz",
                "tracked gitlink/submodule is forbidden",
            )

            direct_boundary_negatives()
            archive_root_negatives()
    except Exception as exc:
        failures.append(str(exc))
    if failures:
        print(f"[FAIL] deterministic source archive self-test: failures={len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("[PASS] deterministic source archive self-test: baseline=1 atomic=4 negatives=26")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
