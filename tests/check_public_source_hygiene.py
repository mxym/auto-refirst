#!/usr/bin/env python3
"""Fail-closed public-source and tracked-history hygiene gate.

The gate audits exactly the paths reported by ``git ls-files --stage``.  It
does not crawl untracked files as publication inputs; ``--require-clean`` is
the release-mode control that rejects any tracked, staged, or untracked
working-tree residue.

Only explicitly classified text paths are opened for content scanning.  A
classified text file that is too large or contains NUL is rejected instead of
being silently treated as binary.  Content rules are ASCII and the scan uses a
one-byte-preserving view, so legacy vendored punctuation cannot hide or corrupt
an otherwise ASCII path token.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable


ROOT = pathlib.Path(__file__).resolve().parents[1]
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_TEXT_BYTES = 128 * 1024 * 1024

TEXT_EXTENSIONS = frozenset(
    {
        ".bat",
        ".c",
        ".cc",
        ".cfg",
        ".cmake",
        ".cmd",
        ".conf",
        ".cpp",
        ".csv",
        ".css",
        ".cxx",
        ".def",
        ".diff",
        ".gradle",
        ".h",
        ".hh",
        ".hpp",
        ".html",
        ".hxx",
        ".in",
        ".inc",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".kt",
        ".lua",
        ".md",
        ".mjs",
        ".patch",
        ".properties",
        ".ps1",
        ".py",
        ".rs",
        ".sh",
        ".spdx",
        ".toml",
        ".ts",
        ".tsv",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
TEXT_BASENAMES = frozenset(
    {
        ".clang-format",
        ".gitattributes",
        ".gitignore",
        "cmakelists.txt",
        "dockerfile",
        "license",
        "makefile",
        "meson.build",
        "notice",
        "unlicense",
        "zig-cc-win64",
        "zig-cxx-win64",
    }
)


def _pieces(*parts: str) -> str:
    """Keep denylisted literals out of this gate's own tracked text."""

    return "".join(parts)


@dataclasses.dataclass(frozen=True)
class ContentRule:
    name: str
    pattern: re.Pattern[str]


CONTENT_RULES = (
    ContentRule("absolute data path", re.compile(r"(?<![A-Za-z0-9_./-])/(?:data)/")),
    ContentRule("absolute service path", re.compile(r"(?<![A-Za-z0-9_./-])/(?:srv)/")),
    ContentRule("private worktree name", re.compile(re.escape(_pieces("re", "-ybs")), re.IGNORECASE)),
    ContentRule(
        "private repository name",
        re.compile(re.escape(_pieces("auto-refirst-private", "-archive")), re.IGNORECASE),
    ),
    ContentRule(
        "private holdout path",
        re.compile(re.escape(_pieces("auto-refirst-", "holdout")), re.IGNORECASE),
    ),
    ContentRule(
        "private Tier-R fixture path",
        re.compile(r"auto[-_]refirst[-_]tier[-_]r[-_]fixtures", re.IGNORECASE),
    ),
    ContentRule(
        "private Tier-R environment binding",
        re.compile(re.escape(_pieces("AUTO_REFIRST_", "TIER_R_FIXTURES"))),
    ),
    ContentRule(
        "private extended-fixture environment binding",
        re.compile(re.escape(_pieces("AUTO_REFIRST_", "EXTENDED_FIXTURES"))),
    ),
    ContentRule("internal Direction label", re.compile(r"\bDirection\s+[A-Z]{1,3}\b")),
    ContentRule("internal Direction token", re.compile(r"\bDIRECTION_[A-Z]{1,3}(?:\b|_)")),
)


@dataclasses.dataclass
class AuditCounts:
    tracked_entries: int = 0
    regular_entries: int = 0
    text_files_scanned: int = 0
    text_bytes_scanned: int = 0
    text_files_with_high_bytes: int = 0
    binary_files_skipped: int = 0
    index_symlinks: int = 0
    index_gitlinks: int = 0


@dataclasses.dataclass
class AuditResult:
    root: pathlib.Path
    require_clean: bool
    counts: AuditCounts = dataclasses.field(default_factory=AuditCounts)
    violations: list[str] = dataclasses.field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations


class GateError(RuntimeError):
    pass


def run_git(root: pathlib.Path, args: Iterable[str], *, input_bytes: bytes | None = None) -> bytes:
    command = ["git", "-C", str(root), *args]
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"cannot execute git command {' '.join(command)}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git command failed rc={completed.returncode}: {' '.join(command)}: {detail}")
    return completed.stdout


def repository_root(requested: pathlib.Path) -> pathlib.Path:
    requested = requested.resolve(strict=True)
    raw = run_git(requested, ["rev-parse", "--show-toplevel"])
    try:
        reported = pathlib.Path(raw.decode("utf-8", "strict").strip()).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as exc:
        raise GateError(f"cannot resolve Git top-level as strict UTF-8: {exc}") from exc
    if reported != requested:
        raise GateError(f"--root must be the Git top-level: requested={requested} git={reported}")
    return reported


def parse_index(root: pathlib.Path) -> list[tuple[str, str, str]]:
    raw = run_git(root, ["ls-files", "--stage", "-z"])
    if not raw:
        raise GateError("git ls-files returned no tracked entries")
    entries: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, oid, stage_number = metadata.decode("ascii", "strict").split(" ")
            path = raw_path.decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError) as exc:
            raise GateError("git ls-files emitted an invalid or non-UTF-8 index record") from exc
        if stage_number != "0":
            raise GateError(f"unmerged index stage {stage_number} for {path}")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            raise GateError(f"invalid object id for tracked path {path}")
        validate_relative_git_path(path)
        if path in seen:
            raise GateError(f"duplicate tracked path from git ls-files: {path}")
        seen.add(path)
        entries.append((mode, oid, path))
    if not entries:
        raise GateError("git ls-files returned no parseable tracked entries")
    return entries


def validate_relative_git_path(path: str) -> None:
    pure = pathlib.PurePosixPath(path)
    if not path or path.startswith("/") or "\\" in path or any(part in ("", ".", "..") for part in pure.parts):
        raise GateError(f"unsafe tracked path syntax: {path!r}")
    if "\x00" in path or "\r" in path or "\n" in path:
        raise GateError(f"control character in tracked path: {path!r}")


def forbidden_path_reason(path: str) -> str | None:
    lowered = path.casefold()
    if lowered == ".gitmodules":
        return "tracked .gitmodules is forbidden; public publication has no submodule contract"
    if lowered == "research" or lowered.startswith("research/"):
        return "research tree is private-only"
    if lowered == "docs/collab" or lowered.startswith("docs/collab/"):
        return "collaboration history is private-only"
    for component in pathlib.PurePosixPath(lowered).parts:
        compact = re.sub(r"[^a-z0-9]", "", component)
        tokens = [token for token in re.split(r"[^a-z0-9]+", component) if token]
        if "holdout" in compact:
            return "holdout path component is private-only"
        if "audit" in compact:
            return "audit path component is private-only"
        if "localrc" in compact:
            return "local-RC evidence path component is private-only"
        if "sourceembeddedpayload" in compact:
            return "source-embedded payload path component is private-only"
        if any(tokens[i : i + 2] == ["tier", "r"] for i in range(max(0, len(tokens) - 1))):
            return "Tier-R path component is private-only"
        if "private" in compact and "fixture" in compact:
            return "private fixture path component is forbidden"
    return None


def is_text_path(path: str) -> bool:
    pure = pathlib.PurePosixPath(path)
    name = pure.name.casefold()
    return (
        pure.suffix.casefold() in TEXT_EXTENSIONS
        or name in TEXT_BASENAMES
        or name.startswith("license-")
        or name.startswith("license.")
        or name.startswith("notice-")
        or name.startswith("notice.")
    )


def is_link_or_junction(path: pathlib.Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def safe_regular_worktree_file(root: pathlib.Path, relative: str) -> tuple[pathlib.Path | None, str | None]:
    current = root
    parts = pathlib.PurePosixPath(relative).parts
    for part in parts[:-1]:
        current /= part
        try:
            current_status = current.lstat()
        except OSError as exc:
            return None, f"cannot lstat tracked parent: {exc}"
        if is_link_or_junction(current):
            return None, "tracked path traverses a symlink or junction parent"
        if not stat.S_ISDIR(current_status.st_mode):
            return None, "tracked path parent is not a directory"
    candidate = root.joinpath(*parts)
    try:
        candidate_status = candidate.lstat()
    except OSError as exc:
        return None, f"tracked worktree file is unavailable: {exc}"
    if is_link_or_junction(candidate):
        return None, "tracked worktree file is a symlink or junction"
    if not stat.S_ISREG(candidate_status.st_mode):
        return None, "tracked worktree entry is not a regular file"
    try:
        resolved = candidate.resolve(strict=True)
        if os.path.commonpath((str(root), str(resolved))) != str(root):
            return None, "tracked worktree file resolves outside the repository"
    except (OSError, ValueError) as exc:
        return None, f"cannot resolve tracked worktree file safely: {exc}"
    return candidate, None


def batch_blob_sizes(root: pathlib.Path, object_ids: Iterable[str]) -> dict[str, int]:
    unique = list(dict.fromkeys(object_ids))
    if not unique:
        return {}
    raw = run_git(
        root,
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input_bytes=("\n".join(unique) + "\n").encode("ascii"),
    )
    lines = raw.splitlines()
    if len(lines) != len(unique):
        raise GateError("git cat-file --batch-check returned an unexpected record count")
    sizes: dict[str, int] = {}
    for expected, line in zip(unique, lines):
        try:
            actual, object_type, raw_size = line.decode("ascii", "strict").split(" ")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as exc:
            raise GateError("git cat-file --batch-check returned an invalid record") from exc
        if actual != expected or object_type != "blob" or size < 0:
            raise GateError(
                f"tracked regular entry is not a valid blob: expected={expected} actual={actual} "
                f"type={object_type} size={size}"
            )
        sizes[expected] = size
    return sizes


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
            raise GateError("git cat-file --batch omitted an object header")
        try:
            actual, object_type, raw_size = raw[offset:line_end].decode("ascii", "strict").split(" ")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as exc:
            raise GateError("git cat-file --batch returned an invalid object header") from exc
        if actual != expected or object_type != "blob" or size < 0:
            raise GateError(f"git cat-file --batch returned the wrong object for {expected}")
        data_begin = line_end + 1
        data_end = data_begin + size
        if data_end >= len(raw) or raw[data_end : data_end + 1] != b"\n":
            raise GateError(f"git cat-file --batch returned a truncated blob for {expected}")
        blobs[expected] = raw[data_begin:data_end]
        offset = data_end + 1
    if offset != len(raw):
        raise GateError("git cat-file --batch returned trailing unparsed bytes")
    return blobs


def scan_text(raw: bytes, relative: str, result: AuditResult) -> None:
    if b"\0" in raw:
        result.violations.append(f"{relative}: classified text file contains NUL and is ambiguous/binary")
        return
    # latin-1 is deliberately used as a one-byte-preserving view.  All deny
    # tokens are ASCII; this keeps matching deterministic while accepting
    # legacy punctuation in a small amount of vendored source.
    text = raw.decode("latin-1")
    result.counts.text_files_scanned += 1
    result.counts.text_bytes_scanned += len(raw)
    if any(byte >= 0x80 for byte in raw):
        result.counts.text_files_with_high_bytes += 1
    for rule in CONTENT_RULES:
        match = rule.pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            result.violations.append(f"{relative}:{line}: forbidden text token ({rule.name})")


def audit(root_arg: pathlib.Path, require_clean: bool) -> AuditResult:
    root = repository_root(root_arg)
    result = AuditResult(root=root, require_clean=require_clean)
    if require_clean:
        dirty = run_git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        if dirty:
            entries = sum(1 for item in dirty.split(b"\0") if item)
            result.violations.append(f"working tree is not clean ({entries} porcelain entries)")

    text_candidates: list[tuple[str, str]] = []
    for mode, oid, relative in parse_index(root):
        result.counts.tracked_entries += 1
        reason = forbidden_path_reason(relative)
        if reason:
            result.violations.append(f"{relative}: forbidden tracked path ({reason})")
        if mode == "120000":
            result.counts.index_symlinks += 1
            result.violations.append(f"{relative}: tracked symlink is forbidden")
            continue
        if mode == "160000":
            result.counts.index_gitlinks += 1
            result.violations.append(f"{relative}: tracked gitlink/submodule is forbidden")
            continue
        if mode not in ("100644", "100755"):
            result.violations.append(f"{relative}: unsupported Git index mode {mode}")
            continue
        result.counts.regular_entries += 1
        worktree_path, unsafe_reason = safe_regular_worktree_file(root, relative)
        if unsafe_reason:
            result.violations.append(f"{relative}: {unsafe_reason}")
            continue
        assert worktree_path is not None
        if is_text_path(relative):
            text_candidates.append((relative, oid))
        else:
            result.counts.binary_files_skipped += 1
    sizes = batch_blob_sizes(root, (oid for _, oid in text_candidates))
    aggregate = sum(sizes[oid] for _, oid in text_candidates)
    if aggregate > MAX_TOTAL_TEXT_BYTES:
        result.violations.append(
            f"classified text aggregate exceeds hard scan limit {MAX_TOTAL_TEXT_BYTES} bytes (actual={aggregate})"
        )
        return result
    scannable: list[tuple[str, str]] = []
    for relative, oid in text_candidates:
        size = sizes[oid]
        if size > MAX_TEXT_BYTES:
            result.violations.append(
                f"{relative}: classified text file exceeds hard scan limit {MAX_TEXT_BYTES} bytes (actual={size})"
            )
        else:
            scannable.append((relative, oid))
    blobs = batch_blob_contents(root, (oid for _, oid in scannable))
    for relative, oid in scannable:
        raw = blobs[oid]
        if len(raw) != sizes[oid]:
            raise GateError(f"blob size changed during scan for {relative}")
        scan_text(raw, relative, result)
    return result


def print_result(result: AuditResult) -> None:
    counts = result.counts
    state = "PASS" if result.passed else "FAIL"
    print(
        f"[{state}] public source hygiene: tracked={counts.tracked_entries} "
        f"regular={counts.regular_entries} text_scanned={counts.text_files_scanned} "
        f"text_bytes={counts.text_bytes_scanned} binary_skipped={counts.binary_files_skipped} "
        f"text_with_high_bytes={counts.text_files_with_high_bytes} "
        f"index_symlinks={counts.index_symlinks} index_gitlinks={counts.index_gitlinks} "
        f"path_policy_groups=8 content_rules={len(CONTENT_RULES)} text_limit={MAX_TEXT_BYTES} "
        f"aggregate_text_limit={MAX_TOTAL_TEXT_BYTES} "
        f"clean_check={'required' if result.require_clean else 'not-requested'} "
        f"violations={len(result.violations)}"
    )
    for violation in result.violations:
        print(f"  - {violation}")


def write_repo_file(root: pathlib.Path, relative: str, data: bytes) -> None:
    path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def initialize_test_repo(parent: pathlib.Path, name: str) -> pathlib.Path:
    root = parent / name
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["git", "-C", str(root), "config", "core.autocrlf", "false"], check=True)
    write_repo_file(root, "README.md", b"public fixture\n")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=Public Hygiene Test",
            "-c",
            "user.email=hygiene@example.invalid",
            "commit",
            "-qm",
            "baseline",
        ],
        check=True,
    )
    return root


def invoke_checker(script: pathlib.Path, root: pathlib.Path, require_clean: bool = False) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(script), "--root", str(root)]
    if require_clean:
        command.append("--require-clean")
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)


def add_path(root: pathlib.Path, relative: str, data: bytes = b"private\n") -> None:
    write_repo_file(root, relative, data)
    subprocess.run(["git", "-C", str(root), "add", "--", relative], check=True)


def stage_forbidden_then_restore_worktree(root: pathlib.Path) -> None:
    add_path(root, "notes.md", (_pieces("/", "data", "/staged-only\n")).encode("utf-8"))
    write_repo_file(root, "notes.md", b"clean worktree view\n")


def self_test(script: pathlib.Path) -> int:
    negative_cases: list[tuple[str, Callable[[pathlib.Path], None], bool, str]] = []
    forbidden_paths = (
        "research/secret.txt",
        "docs/collab/handoff.md",
        "tests/holdout/sample.bin",
        "tests/tier-r/sample.bin",
        "docs/audit/RC.json",
        "local-RC/evidence.json",
        "tests/source_embedded_payload/blob.bin",
        "tests/private-fixtures/blob.bin",
    )
    for index, relative in enumerate(forbidden_paths):
        negative_cases.append(
            (
                f"forbidden-path-{index + 1}",
                lambda root, value=relative: add_path(root, value),
                False,
                "forbidden tracked path",
            )
        )

    forbidden_texts = (
        _pieces("/", "data", "/private/result"),
        _pieces("/", "srv", "/private/result"),
        _pieces("re", "-ybs", "/research"),
        _pieces("auto-refirst-private", "-archive"),
        _pieces("auto-refirst-", "holdout-v2"),
        _pieces("auto-refirst-", "tier-r-fixtures-bc"),
        _pieces("AUTO_REFIRST_", "TIER_R_FIXTURES"),
        _pieces("Direc", "tion AZ"),
    )
    for index, value in enumerate(forbidden_texts):
        negative_cases.append(
            (
                f"forbidden-text-{index + 1}",
                lambda root, text=value: add_path(root, "notes.md", (text + "\n").encode("utf-8")),
                False,
                "forbidden text token",
            )
        )

    negative_cases.extend(
        (
            (
                "oversized-text",
                lambda root: add_path(root, "notes.md", b"x" * (MAX_TEXT_BYTES + 1)),
                False,
                "exceeds hard scan limit",
            ),
            (
                "nul-in-text",
                lambda root: add_path(root, "notes.md", b"text\0binary\n"),
                False,
                "contains NUL",
            ),
            (
                "tracked-missing",
                lambda root: (root / "README.md").unlink(),
                False,
                "tracked worktree file is unavailable",
            ),
            (
                "dirty-worktree",
                lambda root: (root / "README.md").write_text("dirty\n", encoding="utf-8"),
                True,
                "working tree is not clean",
            ),
            (
                "staged-content-differs-from-worktree",
                stage_forbidden_then_restore_worktree,
                False,
                "forbidden text token",
            ),
        )
    )

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="auto-refirst-hygiene-") as raw:
        parent = pathlib.Path(raw)
        baseline = initialize_test_repo(parent, "baseline")
        baseline_result = invoke_checker(script, baseline, require_clean=True)
        if baseline_result.returncode != 0:
            failures.append(f"baseline unexpectedly failed: {baseline_result.stdout}{baseline_result.stderr}")
        else:
            print("[PASS MUTATION] clean baseline accepted")

        binary_boundary = initialize_test_repo(parent, "binary-boundary")
        add_path(binary_boundary, "tests/corpus/opaque.bin", (_pieces("/", "data", "/binary-token")).encode())
        binary_result = invoke_checker(script, binary_boundary)
        if binary_result.returncode != 0:
            failures.append(f"explicit binary boundary unexpectedly failed: {binary_result.stdout}{binary_result.stderr}")
        else:
            print("[PASS MUTATION] explicit binary extension skipped from text scan")

        for name, mutate, require_clean, expected in negative_cases:
            repo = initialize_test_repo(parent, name)
            mutate(repo)
            completed = invoke_checker(script, repo, require_clean=require_clean)
            if (
                completed.returncode == 0
                or "[FAIL] public source hygiene" not in completed.stdout
                or expected not in completed.stdout
            ):
                failures.append(f"{name} was not rejected: rc={completed.returncode}\n{completed.stdout}{completed.stderr}")
            else:
                print(f"[PASS MUTATION] {name} rejected")

        symlink_repo = initialize_test_repo(parent, "index-symlink")
        link_oid = run_git(symlink_repo, ["hash-object", "-w", "--stdin"], input_bytes=b"../outside")
        subprocess.run(
            [
                "git",
                "-C",
                str(symlink_repo),
                "update-index",
                "--add",
                "--cacheinfo",
                f"120000,{link_oid.decode().strip()},escape-link",
            ],
            check=True,
        )
        symlink_result = invoke_checker(script, symlink_repo)
        if symlink_result.returncode == 0 or "tracked symlink is forbidden" not in symlink_result.stdout:
            failures.append(f"index symlink was not rejected: {symlink_result.stdout}{symlink_result.stderr}")
        else:
            print("[PASS MUTATION] tracked symlink rejected")

        gitlink_repo = initialize_test_repo(parent, "index-gitlink")
        head = run_git(gitlink_repo, ["rev-parse", "HEAD"]).decode().strip()
        subprocess.run(
            [
                "git",
                "-C",
                str(gitlink_repo),
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{head},vendor/escape",
            ],
            check=True,
        )
        gitlink_result = invoke_checker(script, gitlink_repo)
        if gitlink_result.returncode == 0 or "tracked gitlink/submodule is forbidden" not in gitlink_result.stdout:
            failures.append(f"index gitlink was not rejected: {gitlink_result.stdout}{gitlink_result.stderr}")
        else:
            print("[PASS MUTATION] tracked gitlink rejected")

    if failures:
        print(f"[FAIL MUTATION] public source hygiene self-test: failures={len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    total = len(negative_cases) + 2
    print(f"[PASS MUTATION] public source hygiene self-test: negatives={total} boundary_checks=2")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="Git top-level to audit")
    parser.add_argument("--require-clean", action="store_true", help="reject tracked, staged, and untracked worktree changes")
    parser.add_argument("--self-test", action="store_true", help="run isolated mutation negatives and exit")
    args = parser.parse_args()
    if args.self_test:
        return self_test(pathlib.Path(__file__).resolve())
    try:
        result = audit(args.root, args.require_clean)
    except GateError as exc:
        print(f"[FAIL] public source hygiene: gate_error={exc}")
        return 1
    print_result(result)
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
