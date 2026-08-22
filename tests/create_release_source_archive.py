#!/usr/bin/env python3
"""Create a deterministic custom source archive from one clean Git commit."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import pathlib
import re
import tarfile

import check_release_assets as contract


MAX_USTAR_NAME_BYTES = 100
MAX_USTAR_PREFIX_BYTES = 155
PORTABLE_COMPONENT = re.compile(r"[A-Za-z0-9._+-]+")
WINDOWS_RESERVED_STEMS = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] source archive: {message}")


def exact_head(root: pathlib.Path, expected_commit: str) -> tuple[str, int]:
    if not contract.FULL_GIT_ID.fullmatch(expected_commit):
        fail("--expected-commit must be a full lowercase Git object id")
    head = contract.run_git(root, ["rev-parse", "HEAD"]).decode("ascii", errors="strict").strip()
    if head != expected_commit:
        fail(f"source HEAD {head} does not equal --expected-commit {expected_commit}")
    dirty = contract.run_git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if dirty:
        entries = sum(1 for item in dirty.split(b"\0") if item)
        fail(f"source worktree/index is not clean ({entries} porcelain entries)")
    head_tree = contract.run_git(root, ["rev-parse", "HEAD^{tree}"]).decode("ascii").strip()
    index_tree = contract.run_git(root, ["write-tree"]).decode("ascii").strip()
    if index_tree != head_tree:
        fail("source index tree does not equal HEAD tree")
    raw_time = contract.run_git(root, ["show", "-s", "--format=%ct", "HEAD"]).decode("ascii").strip()
    if not re.fullmatch(r"[0-9]+", raw_time):
        fail("source commit timestamp is not a non-negative decimal epoch")
    source_date_epoch = int(raw_time)
    if source_date_epoch > 0xFFFFFFFF:
        fail("source commit timestamp does not fit the canonical gzip MTIME field")
    return head_tree, source_date_epoch


def output_path(candidate: pathlib.Path, root: pathlib.Path) -> pathlib.Path:
    lexical = pathlib.Path(os.path.abspath(candidate))
    try:
        parent = lexical.parent.resolve(strict=True)
    except OSError as exc:
        fail(f"output parent is unavailable: {exc}")
    if lexical.parent != parent or contract.is_link_or_reparse(parent) or not parent.is_dir():
        fail("output parent must be an existing real directory without link/reparse traversal")
    output = parent / lexical.name
    contract.safe_asset_name(output.name, "source archive filename")
    if not output.name.endswith(".tar.gz"):
        fail("source archive filename must end in .tar.gz")
    if output == root or root in output.parents:
        fail("source archive output must be outside the source worktree")
    if os.path.lexists(output):
        fail("source archive output already exists")
    return output


def validate_archive_root(value: str) -> str:
    return contract.safe_asset_name(value, "source archive root")


def split_ustar_name(value: str) -> tuple[bytes, bytes]:
    try:
        raw = value.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        fail(f"archive path is not canonical printable ASCII: {value!r}")
    if len(raw) <= MAX_USTAR_NAME_BYTES:
        return b"", raw
    for offset in range(len(raw) - 1, -1, -1):
        if raw[offset:offset + 1] != b"/":
            continue
        prefix, name = raw[:offset], raw[offset + 1:]
        if prefix and name and len(prefix) <= MAX_USTAR_PREFIX_BYTES and len(name) <= MAX_USTAR_NAME_BYTES:
            return prefix, name
    fail(f"archive path cannot be represented in canonical USTAR: {value!r}")


def validate_tree_paths(tree: dict[str, tuple[str, str]], archive_root: str) -> None:
    folded: dict[str, str] = {}
    for relative in tree:
        pure = pathlib.PurePosixPath(relative)
        for part in pure.parts:
            try:
                raw_part = part.encode("ascii", errors="strict")
            except UnicodeEncodeError:
                fail(f"tracked path is not canonical printable ASCII: {relative!r}")
            if not raw_part or any(byte < 0x20 or byte > 0x7E for byte in raw_part):
                fail(f"tracked path contains non-printable bytes: {relative!r}")
            if not PORTABLE_COMPONENT.fullmatch(part):
                fail(f"tracked path is outside the portable archive character set: {relative!r}")
            if part.casefold() == ".git":
                fail(f"tracked path contains forbidden Git metadata component: {relative!r}")
            if part.endswith((" ", ".")):
                fail(f"tracked path has a cross-platform-unsafe trailing character: {relative!r}")
            if part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_STEMS:
                fail(f"tracked path uses a cross-platform-reserved component: {relative!r}")
        folded_name = relative.casefold()
        previous = folded.get(folded_name)
        if previous is not None and previous != relative:
            fail(f"tracked paths collide under cross-platform case folding: {previous!r} and {relative!r}")
        folded[folded_name] = relative
        split_ustar_name(f"{archive_root}/{relative}")


def directory_names(archive_root: str, tree: dict[str, tuple[str, str]]) -> list[str]:
    result = contract.expected_archive_directories(archive_root, tree)
    for name in result:
        split_ustar_name(name)
    return sorted(result, key=lambda name: (name.count("/"), name))


def tar_info(name: str, *, mode: int, source_date_epoch: int, is_directory: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = source_date_epoch
    info.size = 0
    info.pax_headers = {}
    # Validate USTAR encoding before any output file is created.
    info.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
    return info


def create_archive(
    output: pathlib.Path,
    archive_root: str,
    tree: dict[str, tuple[str, str]],
    blobs: dict[str, bytes],
    source_date_epoch: int,
) -> None:
    directories = directory_names(archive_root, tree)
    directory_infos = [
        tar_info(name, mode=0o755, source_date_epoch=source_date_epoch, is_directory=True)
        for name in directories
    ]
    file_infos: list[tuple[tarfile.TarInfo, bytes]] = []
    for relative in sorted(tree):
        git_mode, oid = tree[relative]
        data = blobs[oid]
        info = tar_info(
            f"{archive_root}/{relative}",
            mode=0o755 if git_mode == "100755" else 0o644,
            source_date_epoch=source_date_epoch,
            is_directory=False,
        )
        info.size = len(data)
        info.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
        file_infos.append((info, data))
    try:
        with output.open("xb") as raw:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw,
                mtime=source_date_epoch,
            ) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for info in directory_infos:
                        archive.addfile(info)
                    for info, data in file_infos:
                        archive.addfile(info, io.BytesIO(data))
    except BaseException:
        try:
            output.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=pathlib.Path, default=contract.CHECKER_ROOT)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--archive-root", required=True)
    args = parser.parse_args()

    root = contract.repository_root(args.source_root)
    output = output_path(args.output, root)
    archive_root = validate_archive_root(args.archive_root)
    head_tree, source_date_epoch = exact_head(root, args.expected_commit)
    hygiene_summary = contract.verify_source_hygiene(root)
    tree = contract.git_tree(root)
    current_tree = contract.run_git(root, ["rev-parse", "HEAD^{tree}"]).decode("ascii").strip()
    if current_tree != head_tree:
        fail("source HEAD tree changed while preparing the archive")
    validate_tree_paths(tree, archive_root)
    blobs = contract.batch_blob_contents(root, (oid for _, oid in tree.values()))
    create_archive(output, archive_root, tree, blobs, source_date_epoch)
    post_tree, post_source_date_epoch = exact_head(root, args.expected_commit)
    if post_tree != head_tree or post_source_date_epoch != source_date_epoch:
        output.unlink(missing_ok=True)
        fail("source commit changed while creating the archive")
    digest = contract.hash_file(output)
    print(hygiene_summary)
    print(
        f"[PASS] source archive: commit={args.expected_commit} files={len(tree)} "
        f"directories={len(directory_names(archive_root, tree))} source_date_epoch={source_date_epoch} "
        f"format=USTAR gzip_header=canonical sha256={digest} output={output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
