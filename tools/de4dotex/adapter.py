#!/usr/bin/env python3
"""Narrow, fail-closed de4dotEx sidecar research adapter.

This is intentionally not a general plugin host.  de4dotEx is treated as
execution-capable even in detector mode: an invocation requires the existing
explicit target-runtime authorization, bound to the exact target SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import signal
import stat
import subprocess
import sys
import time
from typing import Any


SCHEMA_VERSION = 1
AUTH_SCHEMA = "auto-refirst.target-execution-authorization.v1"
PINNED_MANIFEST_SHA256 = "7e636d58afb2e61b3e479bbf40bd9926b71a7e6744b0b5de4f5255b7c90a4039"
DETECTED_RE = re.compile(r"^Detected (.+?) \(/input/target\.dll\)$", re.MULTILINE)
VERSION_RE = re.compile(r"^de4dotEx v([0-9]+(?:\.[0-9]+){3})$", re.MULTILINE)
CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_SELF_CGROUP = Path("/proc/self/cgroup")

LAUNCHER_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TMPDIR": "/tmp",
}

class AdapterError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def sha256_file(path: Path, limit: int | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if limit is not None and size > limit:
                raise AdapterError("INPUT_TOO_LARGE", f"file exceeds {limit} bytes")
            digest.update(chunk)
    return digest.hexdigest(), size


def hash_bytes(path: Path, limit: int) -> tuple[str, int, str]:
    digest = hashlib.sha256()
    size = 0
    retained = bytearray()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            if len(retained) < limit:
                retained.extend(chunk[:limit - len(retained)])
    return digest.hexdigest(), size, bytes(retained).decode("utf-8", "replace")


def require_plain_file(path: Path, code: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AdapterError(code, f"cannot stat {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AdapterError(code, f"expected a non-symlink regular file: {path}")
    return info


def require_plain_directory(path: Path, code: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AdapterError(code, f"cannot stat {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AdapterError(code, f"expected a non-symlink directory: {path}")
    return info


def open_plain_file(path: Path, code: str):
    before = require_plain_file(path, code)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AdapterError(code, f"cannot open {path}: {exc}") from exc
    opened = os.fstat(descriptor)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino):
        os.close(descriptor)
        raise AdapterError(code, f"file path changed while opening: {path}")
    return os.fdopen(descriptor, "rb")


def sha256_plain_file(path: Path, code: str, limit: int | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open_plain_file(path, code) as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if limit is not None and size > limit:
                raise AdapterError("INPUT_TOO_LARGE", f"file exceeds {limit} bytes")
            digest.update(chunk)
    return digest.hexdigest(), size


def load_small_json_with_identity(
    path: Path, code: str, max_bytes: int = 64 * 1024
) -> tuple[dict[str, Any], str, int]:
    info = require_plain_file(path, code)
    if info.st_size > max_bytes:
        raise AdapterError(code, f"JSON exceeds {max_bytes} bytes")
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_dev != info.st_dev or opened.st_ino != info.st_ino:
                raise AdapterError(code, "JSON path changed while opening")
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise AdapterError(code, f"JSON exceeds {max_bytes} bytes")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError(code, f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AdapterError(code, "JSON root must be an object")
    return value, hashlib.sha256(raw).hexdigest(), len(raw)


def load_small_json(path: Path, code: str, max_bytes: int = 64 * 1024) -> dict[str, Any]:
    return load_small_json_with_identity(path, code, max_bytes)[0]


def require_canonical_existing(path: Path, code: str, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AdapterError(code, f"cannot resolve {label} {path}: {exc}") from exc
    if resolved != path:
        raise AdapterError(code, f"{label} must be an absolute canonical path without symlink components")
    return resolved


def require_no_posix_acl(path: Path, code: str, label: str) -> None:
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        raise AdapterError(code, f"cannot inspect {label} ACL metadata: {exc}") from exc
    if "system.posix_acl_access" in attributes:
        raise AdapterError(code, f"{label} has an access ACL; immutability cannot be proven")


def require_root_owned_nonwritable(path: Path, code: str, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AdapterError(code, f"cannot stat {label} {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise AdapterError(code, f"{label} is a symlink: {path}")
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise AdapterError(code, f"{label} is not root-owned and group/world non-writable: {path}")
    require_no_posix_acl(path, code, label)
    if os.access(path, os.W_OK, effective_ids=True):
        raise AdapterError(code, f"{label} remains writable by the adapter identity: {path}")
    return info


def require_trusted_path_chain(path: Path, code: str, label: str) -> os.stat_result:
    require_canonical_existing(path, code, label)
    leaf_info: os.stat_result | None = None
    for index, component in enumerate((path, *path.parents)):
        info = require_root_owned_nonwritable(component, code, label if index == 0 else "ancestor")
        if index == 0:
            leaf_info = info
    assert leaf_info is not None
    return leaf_info


def validate_immutable_tool_tree(root: Path) -> None:
    code = "TOOL_TREE_NOT_IMMUTABLE"
    root_info = require_trusted_path_chain(root, code, "tool root")
    if not stat.S_ISDIR(root_info.st_mode):
        raise AdapterError(code, "tool root is not a directory")
    for path in root.rglob("*"):
        info = require_root_owned_nonwritable(path, code, "tool-tree object")
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise AdapterError(code, f"tool tree contains a symlink or special object: {path.relative_to(root)}")


def validate_sandbox_launcher(path: Path, sandbox: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    code = "SANDBOX_UNAVAILABLE"
    trust = sandbox.get("launcher_trust")
    if not isinstance(trust, dict) or trust.get("model") != "root-owned-system-dependency":
        raise AdapterError(code, "unsupported or missing bubblewrap trust model")
    info = require_trusted_path_chain(path, code, "bubblewrap executable")
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR:
        raise AdapterError(code, "bubblewrap is not an executable regular file")
    digest_before, size_before = sha256_file(path)
    expected_digest = trust.get("sha256")
    if expected_digest is not None:
        if not isinstance(expected_digest, str) or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
            raise AdapterError("MANIFEST_INVALID", "bubblewrap digest pin is malformed")
        if digest_before != expected_digest:
            raise AdapterError(code, "bubblewrap executable does not match the manifest digest")
    try:
        probe = subprocess.run(
            [str(path), "--version"], capture_output=True, text=True, timeout=2,
            check=False, env=LAUNCHER_ENV,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError(code, f"bubblewrap probe failed: {exc}") from exc
    match = re.fullmatch(r"bubblewrap ([0-9]+(?:\.[0-9]+){2})\s*", probe.stdout)
    minimum_text = sandbox.get("minimum_version")
    if not isinstance(minimum_text, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", minimum_text) is None:
        raise AdapterError("MANIFEST_INVALID", "bubblewrap minimum version is malformed")
    if probe.returncode != 0 or match is None:
        raise AdapterError(code, "bubblewrap version output is malformed")
    actual_version = tuple(int(value) for value in match.group(1).split("."))
    minimum_version = tuple(int(value) for value in minimum_text.split("."))
    if actual_version < minimum_version:
        raise AdapterError(code, f"bubblewrap {match.group(1)} is older than required {minimum_text}")
    digest_after, size_after = sha256_file(path)
    if digest_after != digest_before or size_after != size_before:
        raise AdapterError(code, "bubblewrap changed while it was being validated")
    return path, {"version": match.group(1), "sha256": digest_before, "size": size_before,
                  "trust_model": trust["model"], "digest_pinned": expected_digest is not None}


def read_small_control(path: Path, code: str) -> str:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise AdapterError(code, f"unsafe cgroup control: {path}")
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise AdapterError(code, f"cannot read cgroup control {path}: {exc}") from exc
    if len(value) > 64:
        raise AdapterError(code, f"oversized cgroup control: {path}")
    return value


def validate_hard_cgroup(
    max_memory_bytes: int, max_swap_bytes: int, max_processes: int
) -> dict[str, Any]:
    code = "HARD_RESOURCE_SANDBOX_UNAVAILABLE"
    try:
        membership_text = PROC_SELF_CGROUP.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise AdapterError(code, f"cannot read cgroup membership: {exc}") from exc
    memberships = [line[3:].strip() for line in membership_text.splitlines() if line.startswith("0::")]
    if len(memberships) != 1 or not memberships[0].startswith("/"):
        raise AdapterError(code, "process is not in one identifiable cgroup v2 hierarchy")
    try:
        root = CGROUP_ROOT.resolve(strict=True)
        group = (root / memberships[0].lstrip("/")).resolve(strict=True)
    except OSError as exc:
        raise AdapterError(code, f"cannot resolve current cgroup v2 path: {exc}") from exc
    if group != root and root not in group.parents:
        raise AdapterError(code, "resolved cgroup escapes the cgroup v2 hierarchy")
    raw_memory = read_small_control(group / "memory.max", code)
    raw_swap = read_small_control(group / "memory.swap.max", code)
    raw_processes = read_small_control(group / "pids.max", code)
    if raw_memory == "max" or raw_swap == "max" or raw_processes == "max":
        raise AdapterError(code, "current cgroup has an unbounded memory.max, memory.swap.max, or pids.max")
    try:
        memory_max = int(raw_memory)
        swap_max = int(raw_swap)
        processes_max = int(raw_processes)
    except ValueError as exc:
        raise AdapterError(code, "current cgroup limits are not numeric") from exc
    if not (
        0 < memory_max <= max_memory_bytes
        and 0 <= swap_max <= max_swap_bytes
        and 0 < processes_max <= max_processes
    ):
        raise AdapterError(
            code,
            "current cgroup limits exceed manifest maxima "
            f"(memory.max={memory_max}, memory.swap.max={swap_max}, pids.max={processes_max})",
        )
    return {
        "version": 2,
        "path": memberships[0],
        "memory_max": memory_max,
        "memory_swap_max": swap_max,
        "pids_max": processes_max,
        "inherited_by_process_tree": True,
    }


def compute_tree(root: Path) -> tuple[str, int, int]:
    require_plain_directory(root, "TOOL_MISSING")
    rows: list[bytes] = []
    total = 0
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise AdapterError("TOOL_TREE_MISMATCH", f"tool tree contains symlink: {path.relative_to(root)}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise AdapterError("TOOL_TREE_MISMATCH", f"tool tree contains special file: {path.relative_to(root)}")
        digest, size = sha256_file(path)
        relative = path.relative_to(root).as_posix()
        rows.append(f"{digest} {size} {relative}\n".encode("utf-8"))
        total += size
        count += 1
    return hashlib.sha256(b"".join(rows)).hexdigest(), count, total


def output_usage(root: Path, max_files: int) -> tuple[int, int, bool]:
    count = 0
    total = 0
    unsafe = False
    for path in root.rglob("*"):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            unsafe = True
            continue
        if stat.S_ISREG(info.st_mode):
            count += 1
            total += info.st_size
            if count > max_files:
                break
    return count, total, unsafe


def enumerate_artifacts(root: Path, max_files: int, max_bytes: int) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise AdapterError("UNSAFE_OUTPUT", f"sidecar produced a symlink or special file: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if len(artifacts) >= max_files:
            raise AdapterError("OVERSIZED_OUTPUT", f"sidecar produced more than {max_files} files")
        total += info.st_size
        if total > max_bytes:
            raise AdapterError("OVERSIZED_OUTPUT", f"sidecar output exceeds {max_bytes} bytes")
        digest, size = sha256_file(path)
        artifacts.append({"relative_path": relative, "size": size, "sha256": digest})
    return artifacts


def make_preexec(address_space_bytes: int, output_bytes: int, timeout_ms: int, max_processes: int):
    def apply_limits() -> None:
        os.setsid()
        cpu_seconds = max(1, math.ceil(timeout_ms / 1000) + 1)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (address_space_bytes, address_space_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_bytes, output_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_NPROC, (max_processes, max_processes))

    return apply_limits


def terminate_process_group(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def partial(code: str, detail: str, base: dict[str, Any], attempted: bool = False) -> dict[str, Any]:
    result = dict(base)
    result.update({"state": "PARTIAL", "reason_code": code, "detail": detail, "attempted": attempted})
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--tool-root", required=True)
    parser.add_argument("--bwrap", required=True, help="explicit absolute bubblewrap executable")
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", required=True, help="must not already exist")
    parser.add_argument("--mode", required=True, choices=("detect", "deobfuscate"))
    parser.add_argument("--timeout-ms", type=int)
    parser.add_argument("--output-bytes", type=int)
    return parser.parse_args(argv)


def run(argv: list[str]) -> dict[str, Any]:
    args = parse_args(argv)
    started = time.monotonic()
    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "provider": "de4dotex",
        "mode": args.mode,
        "state": "PARTIAL",
        "attempted": False,
    }

    manifest_path = Path(args.manifest)
    auth_path = Path(args.authorization)
    input_path = Path(args.input)
    tool_root = Path(args.tool_root)
    bwrap_path = Path(args.bwrap)
    output_dir = Path(args.output_dir)
    for name, path in (("manifest", manifest_path), ("authorization", auth_path), ("input", input_path),
                       ("tool root", tool_root), ("bubblewrap", bwrap_path), ("output", output_dir)):
        if not path.is_absolute():
            return partial("PATH_NOT_ABSOLUTE", f"{name} path must be absolute", base)

    try:
        if os.geteuid() == 0:
            raise AdapterError("UNSAFE_INVOKER_IDENTITY", "the sidecar adapter must not run as root")
        require_canonical_existing(manifest_path, "MANIFEST_INVALID", "manifest")
        manifest, manifest_hash, manifest_size = load_small_json_with_identity(
            manifest_path, "MANIFEST_INVALID", 256 * 1024
        )
        base["manifest"] = {"sha256": manifest_hash, "size": manifest_size}
        if manifest_hash != PINNED_MANIFEST_SHA256:
            raise AdapterError("MANIFEST_UNTRUSTED", "manifest does not match the adapter's compiled-in digest")
        if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("provider") != "de4dotex":
            raise AdapterError("MANIFEST_INVALID", "unsupported manifest schema or provider")
        if manifest.get("enabled_by_default") is not False:
            raise AdapterError("MANIFEST_INVALID", "provider must be disabled by default")

        limits = manifest.get("limits")
        release = manifest.get("release")
        installed = manifest.get("installed_tree")
        sandbox = manifest.get("sandbox")
        entrypoint = manifest.get("entrypoint")
        if not all(isinstance(item, dict) for item in (limits, release, installed, sandbox)) or not isinstance(entrypoint, str):
            raise AdapterError("MANIFEST_INVALID", "required manifest fields are missing")

        expected_platform = manifest.get("platform", {}).get("contract")
        actual_platform = f"{platform.system()}/{platform.machine()}"
        if expected_platform != actual_platform:
            raise AdapterError("PLATFORM_MISMATCH", f"manifest requires {expected_platform}, host is {actual_platform}")

        input_limit = int(limits["input_bytes"])
        timeout_limit = int(limits["timeout_ms"])
        physical_memory_limit = int(limits["physical_memory_bytes"])
        swap_limit = int(limits["swap_bytes"])
        address_space_limit = int(limits["address_space_bytes"])
        gc_heap_limit = int(limits["gc_heap_hard_limit_bytes"])
        output_limit = int(limits["output_bytes"])
        log_limit = int(limits["log_bytes"])
        max_files = int(limits["output_files"])
        max_processes = int(limits["processes"])
        timeout_ms = args.timeout_ms if args.timeout_ms is not None else timeout_limit
        output_bytes = args.output_bytes if args.output_bytes is not None else output_limit
        if not (1 <= timeout_ms <= timeout_limit and 64 * 1024 * 1024 <= physical_memory_limit
                and 0 <= swap_limit <= physical_memory_limit
                and physical_memory_limit <= address_space_limit
                and 64 * 1024 * 1024 <= gc_heap_limit <= physical_memory_limit
                and 1 <= output_bytes <= output_limit):
            raise AdapterError("LIMIT_INVALID", "requested limits must be positive and no greater than manifest maxima")
        if sandbox.get("require_cgroup_v2_hard_limits") is not True:
            raise AdapterError("MANIFEST_INVALID", "hard cgroup v2 resource limits may not be disabled")

        require_canonical_existing(input_path, "INPUT_INVALID", "input")
        require_canonical_existing(auth_path, "AUTHORIZATION_INVALID", "authorization")
        input_sha256, input_size = sha256_plain_file(input_path, "INPUT_INVALID", input_limit)
        base["input"] = {"sha256": input_sha256, "size": input_size}

        authorization, auth_hash, auth_size = load_small_json_with_identity(auth_path, "AUTHORIZATION_INVALID")
        expected_authorization_fields = {
            "schema", "authorization_source", "runtime_execution_authorized",
            "static_evidence_only", "target_sha256", "target_size",
        }
        if set(authorization) != expected_authorization_fields:
            raise AdapterError("AUTHORIZATION_INVALID", "authorization fields do not match the v1 schema")
        if (not isinstance(authorization.get("target_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", authorization["target_sha256"]) is None
                or type(authorization.get("target_size")) is not int):
            raise AdapterError("AUTHORIZATION_INVALID", "authorization target identity is malformed")
        base["authorization"] = {
            "sha256": auth_hash,
            "size": auth_size,
            "schema": authorization.get("schema"),
            "source": authorization.get("authorization_source"),
            "runtime_execution_authorized": authorization.get("runtime_execution_authorized") is True,
        }
        if authorization.get("schema") != AUTH_SCHEMA:
            raise AdapterError("AUTHORIZATION_INVALID", "unsupported authorization schema")
        if authorization.get("runtime_execution_authorized") is not True or authorization.get("static_evidence_only") is not False:
            raise AdapterError("RUNTIME_EXECUTION_NOT_AUTHORIZED", "de4dotEx is execution-capable and requires explicit --run authorization")
        if authorization.get("authorization_source") != "explicit --run":
            raise AdapterError("RUNTIME_EXECUTION_NOT_AUTHORIZED", "authorization source is not the explicit --run contract")
        if authorization.get("target_sha256") != input_sha256 or authorization.get("target_size") != input_size:
            raise AdapterError("AUTHORIZATION_TARGET_MISMATCH", "authorization is not bound to the exact target bytes")

        require_canonical_existing(tool_root, "TOOL_MISSING", "tool root")
        entry_relative = Path(entrypoint)
        if (entry_relative.is_absolute() or not entry_relative.parts
                or any(part in ("", ".", "..") for part in entry_relative.parts)):
            raise AdapterError("MANIFEST_INVALID", "tool entrypoint is not a safe relative path")
        validate_immutable_tool_tree(tool_root)
        tree_digest, tree_files, tree_bytes = compute_tree(tool_root)
        base["tool"] = {
            "version": release.get("version"),
            "reported_version": release.get("reported_version"),
            "commit": release.get("commit"),
            "asset_sha256": release.get("asset", {}).get("sha256"),
            "tree_sha256": tree_digest,
            "tree_files": tree_files,
            "tree_bytes": tree_bytes,
        }
        if (tree_digest != installed.get("sha256") or tree_files != installed.get("files")
                or tree_bytes != installed.get("bytes")):
            raise AdapterError("TOOL_TREE_MISMATCH", "unpacked tool tree does not match the pinned manifest")
        tool_entry = tool_root / entrypoint
        entry_info = require_plain_file(tool_entry, "TOOL_MISSING")
        if not (entry_info.st_mode & stat.S_IXUSR):
            raise AdapterError("TOOL_MISSING", "tool entrypoint is not executable")

        require_canonical_existing(bwrap_path, "SANDBOX_UNAVAILABLE", "bubblewrap")
        bwrap_path, launcher_proof = validate_sandbox_launcher(bwrap_path, sandbox)
        cgroup = validate_hard_cgroup(physical_memory_limit, swap_limit, max_processes)

        if output_dir.exists() or output_dir.is_symlink():
            raise AdapterError("OUTPUT_PATH_UNSAFE", "output directory must not already exist")
        try:
            resolved_output_parent = output_dir.parent.resolve(strict=True)
        except OSError as exc:
            raise AdapterError("OUTPUT_PATH_UNSAFE", f"cannot resolve output parent: {exc}") from exc
        if (resolved_output_parent != output_dir.parent
                or output_dir != resolved_output_parent / output_dir.name):
            raise AdapterError("OUTPUT_PATH_UNSAFE", "output path must be canonical and contain no symlink components")
        output_parent_info = require_plain_directory(output_dir.parent, "OUTPUT_PATH_UNSAFE")
        if output_parent_info.st_uid != os.geteuid() or output_parent_info.st_mode & 0o077:
            raise AdapterError("OUTPUT_PATH_UNSAFE", "output parent must be private and owned by the adapter identity")
        require_no_posix_acl(output_dir.parent, "OUTPUT_PATH_UNSAFE", "output parent")
        output_dir.mkdir(mode=0o700)
        run_input = output_dir / "input"
        tool_output = output_dir / "tool-output"
        adapter_output = output_dir / "adapter"
        run_input.mkdir(mode=0o700)
        tool_output.mkdir(mode=0o700)
        adapter_output.mkdir(mode=0o700)
        copied_input = run_input / "target.dll"
        copy_digest = hashlib.sha256()
        copied_size = 0
        with open_plain_file(input_path, "INPUT_INVALID") as source, copied_input.open("xb") as destination:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                copied_size += len(chunk)
                if copied_size > input_limit:
                    raise AdapterError("INPUT_TOO_LARGE", f"input exceeds {input_limit} bytes while copying")
                copy_digest.update(chunk)
                destination.write(chunk)
        copied_input.chmod(0o400)
        if copied_size != input_size or copy_digest.hexdigest() != input_sha256:
            raise AdapterError("INPUT_CHANGED_DURING_COPY", "input bytes changed after authorization was checked")

        ro_binds = sandbox.get("system_abi_ro_binds")
        if not isinstance(ro_binds, list) or not ro_binds:
            raise AdapterError("MANIFEST_INVALID", "system ABI bind list is missing")
        command = [
            str(bwrap_path),
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--ro-bind", str(tool_root), "/tool",
        ]
        resolved_binds: list[dict[str, str]] = []
        for bind in ro_binds:
            bind_path = Path(bind)
            try:
                resolved_bind = bind_path.resolve(strict=True)
            except OSError as exc:
                raise AdapterError("SANDBOX_UNAVAILABLE", f"cannot resolve system ABI bind {bind}: {exc}") from exc
            require_plain_directory(resolved_bind, "SANDBOX_UNAVAILABLE")
            command.extend(("--ro-bind", str(resolved_bind), str(bind_path)))
            resolved_binds.append({"source": str(resolved_bind), "destination": str(bind_path)})
        command.extend((
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--dir", "/tmp/home",
            "--dir", "/input",
            "--ro-bind", str(copied_input), "/input/target.dll",
            "--dir", "/output",
            "--bind", str(tool_output), "/output",
            "--chdir", "/output",
            "--setenv", "HOME", "/tmp/home",
            "--setenv", "TMPDIR", "/tmp",
            "--setenv", "PATH", "/tool",
            "--setenv", "DOTNET_BUNDLE_EXTRACT_BASE_DIR", "/tmp/dotnet",
            "--setenv", "DOTNET_GCHeapHardLimit", hex(gc_heap_limit),
            "--setenv", "DOTNET_EnableDiagnostics", "0",
            "--setenv", "COMPlus_EnableDiagnostics", "0",
            "--", f"/tool/{entrypoint}",
        ))
        if args.mode == "detect":
            tool_args = ["-d", "--default-strtyp", "none", "-f", "/input/target.dll"]
        else:
            tool_args = ["--default-strtyp", "static", "-f", "/input/target.dll", "-o", "/output/cleaned.dll"]
        command.extend(tool_args)

        stdout_path = adapter_output / "stdout.log"
        stderr_path = adapter_output / "stderr.log"
        base["sandbox"] = {
            "launcher": "bubblewrap",
            "launcher_identity": launcher_proof,
            "unshare_all_including_network": True,
            "new_pid_ipc_uts_user_mount_namespaces": True,
            "read_only_input": True,
            "private_output": True,
            "private_tmp": True,
            "empty_home": True,
            "system_abi_ro_binds": resolved_binds,
            "cgroup": cgroup,
        }
        base["execution"] = {
            "profile": "execution-capable-detect" if args.mode == "detect" else "execution-capable-static-string-deobfuscate",
            "tool_argv": tool_args,
            "timeout_ms": timeout_ms,
            "physical_memory_bytes": physical_memory_limit,
            "swap_bytes": swap_limit,
            "address_space_bytes": address_space_limit,
            "gc_heap_hard_limit_bytes": gc_heap_limit,
            "output_bytes": output_bytes,
            "log_bytes": log_limit,
            "processes": max_processes,
        }

        timed_out = False
        oversized = False
        unsafe_output = False
        with stdout_path.open("xb") as stdout_handle, stderr_path.open("xb") as stderr_handle:
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    close_fds=True,
                    env=LAUNCHER_ENV,
                    preexec_fn=make_preexec(address_space_limit, max(output_bytes, log_limit), timeout_ms, max_processes),
                )
            except OSError as exc:
                raise AdapterError("SANDBOX_UNAVAILABLE", f"cannot start bubblewrap: {exc}") from exc
            base["attempted"] = True
            try:
                deadline = time.monotonic() + timeout_ms / 1000
                while process.poll() is None:
                    now = time.monotonic()
                    if now >= deadline:
                        timed_out = True
                        break
                    file_count, current_output, current_unsafe = output_usage(tool_output, max_files)
                    unsafe_output = unsafe_output or current_unsafe
                    stdout_handle.flush()
                    stderr_handle.flush()
                    current_logs = stdout_path.stat().st_size + stderr_path.stat().st_size
                    if current_output > output_bytes or current_logs > log_limit or file_count > max_files:
                        oversized = True
                        break
                    time.sleep(0.02)
                if timed_out or oversized or unsafe_output:
                    terminate_process_group(process)
                return_code = process.wait()
            finally:
                terminate_process_group(process)

        elapsed_ms = int((time.monotonic() - started) * 1000)
        stdout_hash, stdout_size, stdout_text = hash_bytes(stdout_path, log_limit)
        stderr_hash, stderr_size, stderr_text = hash_bytes(stderr_path, log_limit)
        base["execution"].update({"exit_code": return_code, "elapsed_ms": elapsed_ms})
        base["logs"] = {
            "stdout": {
                "sha256": stdout_hash,
                "size": stdout_size,
                "text": stdout_text,
                "text_truncated": stdout_size > log_limit,
            },
            "stderr": {
                "sha256": stderr_hash,
                "size": stderr_size,
                "text": stderr_text,
                "text_truncated": stderr_size > log_limit,
            },
        }
        if timed_out:
            return partial("TIMEOUT", f"sidecar exceeded {timeout_ms} ms", base, attempted=True)
        if oversized:
            return partial("OVERSIZED_OUTPUT", "sidecar exceeded the output/file/log budget", base, attempted=True)
        if unsafe_output:
            return partial("UNSAFE_OUTPUT", "sidecar produced a symlink or special file", base, attempted=True)
        if return_code < 0:
            return partial("TOOL_CRASH", f"sidecar terminated by signal {-return_code}", base, attempted=True)
        if 128 <= return_code <= 192:
            return partial(
                "TOOL_CRASH",
                f"sidecar or sandbox launcher returned signal-style exit status {return_code}",
                base,
                attempted=True,
            )
        if return_code != 0:
            return partial("TOOL_EXIT_NONZERO", f"sidecar returned exit code {return_code}", base, attempted=True)

        combined = stdout_text + "\n" + stderr_text
        versions = VERSION_RE.findall(combined)
        expected_reported = str(release["reported_version"])
        if len(versions) != 1 or versions[0] != expected_reported:
            return partial("TOOL_VERSION_MISMATCH", "runtime banner is missing, ambiguous, or mismatched", base, attempted=True)
        detections = DETECTED_RE.findall(combined)
        if len(detections) != 1:
            return partial("MALFORMED_OUTPUT", "expected exactly one structured detector line", base, attempted=True)
        base["detector"] = {"name": detections[0], "detected": detections[0] != "Unknown Obfuscator"}

        try:
            artifacts = enumerate_artifacts(tool_output, max_files, output_bytes)
        except AdapterError as exc:
            return partial(exc.code, exc.detail, base, attempted=True)
        base["artifacts"] = artifacts
        if args.mode == "deobfuscate":
            cleaned = [item for item in artifacts if item["relative_path"] == "cleaned.dll"]
            if len(cleaned) != 1:
                return partial("MALFORMED_OUTPUT", "deobfuscation did not produce exactly one cleaned.dll", base, attempted=True)
            base["state"] = "PARTIAL"
            base["reason_code"] = "PENDING_CORE_REPARSE"
            base["detail"] = "tool output is untrusted until the core PE/CLR/ECMA-335 parser independently validates it"
            base["requires_core_reparse"] = True
            return base

        if artifacts:
            return partial("UNEXPECTED_OUTPUT", "detector mode produced filesystem artifacts", base, attempted=True)
        base["state"] = "COMPLETE"
        base["reason_code"] = "DETECTION_COMPLETED"
        base["detail"] = "execution-authorized sandboxed detector completed; this is a tool result, not proof of complete deobfuscation support"
        return base
    except (AdapterError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, AdapterError):
            return partial(exc.code, exc.detail, base, attempted=bool(base.get("attempted")))
        return partial("MANIFEST_INVALID", f"invalid manifest value: {exc}", base)
    except Exception as exc:
        return partial(
            "ADAPTER_INTERNAL_ERROR", f"{type(exc).__name__}: {exc}", base,
            attempted=bool(base.get("attempted")),
        )


def main() -> int:
    try:
        result = run(sys.argv[1:])
    except SystemExit:
        raise
    except Exception as exc:  # The adapter must still produce a bounded structured failure.
        result = {
            "schema_version": SCHEMA_VERSION,
            "provider": "de4dotex",
            "mode": "unknown",
            "state": "PARTIAL",
            "reason_code": "ADAPTER_INTERNAL_ERROR",
            "detail": f"{type(exc).__name__}: {exc}",
            "attempted": False,
        }
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
