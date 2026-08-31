#!/usr/bin/env python3
"""Generate compact PyInstaller bootstrap reference rows from built executables.

No upstream payload bytes are emitted. Raw references contain only label, declared
Python minor, module name, payload size, and SHA-256. Semantic hashes are computed
by the project's own public marshal helper so generation uses exactly the product's
semantic normalization implementation. Repeating the same LABEL for independently
built samples intentionally emits multiple rows for verified compiler-output variants.
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import struct
import subprocess
import tempfile
import zlib

MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE_SIZE = 88
KNOWN_MODULES = (
    "struct",
    "pyimod01_os_path",
    "pyimod02_archive",
    "pyimod03_importers",
    "pyimod04_ctypes",
    "pyimod01_archive",
    "pyimod02_importers",
    "pyimod03_ctypes",
    "pyimod04_pywin32",
)
SANE_TYPES = set("bdzZMmsxoln")


def be32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("big-endian uint32 lies outside input")
    return struct.unpack_from("!I", data, offset)[0]


def parse_sample(path: pathlib.Path) -> tuple[int, dict[str, bytes]]:
    data = path.read_bytes()
    pos = data.rfind(MAGIC)
    if pos < 0 or pos + COOKIE_SIZE > len(data):
        raise ValueError(f"{path}: standard PyInstaller MEI cookie not found")

    archive_length = be32(data, pos + 8)
    toc_offset = be32(data, pos + 12)
    toc_length = be32(data, pos + 16)
    python_version = be32(data, pos + 20)
    if archive_length < COOKIE_SIZE or archive_length > pos + COOKIE_SIZE:
        raise ValueError(f"{path}: invalid CArchive length")
    if toc_length < 18 or toc_offset >= archive_length or toc_offset + toc_length > archive_length - COOKIE_SIZE:
        raise ValueError(f"{path}: invalid CArchive TOC geometry")
    if not ((20 <= python_version < 100) or (200 <= python_version < 400)):
        raise ValueError(f"{path}: implausible Python version field {python_version}")

    archive_start = pos + COOKIE_SIZE - archive_length
    cursor = archive_start + toc_offset
    end = cursor + toc_length
    payloads: dict[str, bytes] = {}
    entry_count = 0
    while cursor < end:
        if cursor + 18 > end:
            raise ValueError(f"{path}: truncated CArchive TOC entry")
        entry_length = be32(data, cursor)
        offset = be32(data, cursor + 4)
        compressed_size = be32(data, cursor + 8)
        uncompressed_size = be32(data, cursor + 12)
        compressed = data[cursor + 16]
        typecode = chr(data[cursor + 17])
        if entry_length < 18 or entry_length > (1 << 20) or cursor + entry_length > end:
            raise ValueError(f"{path}: invalid CArchive TOC entry length")
        if offset > archive_length or offset + compressed_size > archive_length:
            raise ValueError(f"{path}: CArchive entry lies outside archive")
        if compressed not in (0, 1) or typecode not in SANE_TYPES:
            raise ValueError(f"{path}: invalid CArchive compression/typecode")
        raw_name = data[cursor + 18 : cursor + entry_length]
        name_bytes = raw_name.split(b"\0", 1)[0]
        if not name_bytes:
            raise ValueError(f"{path}: empty CArchive entry name")
        name = name_bytes.decode("utf-8")
        if name in payloads:
            raise ValueError(f"{path}: duplicate reference-relevant entry {name!r}")
        if name in KNOWN_MODULES:
            start = archive_start + offset
            raw = data[start : start + compressed_size]
            payload = zlib.decompress(raw) if compressed else raw
            if len(payload) != uncompressed_size:
                raise ValueError(f"{path}: decompressed size mismatch for {name}")
            payloads[name] = payload
        entry_count += 1
        cursor += entry_length
    if cursor != end or entry_count == 0:
        raise ValueError(f"{path}: CArchive TOC did not close exactly")
    if not payloads:
        raise ValueError(f"{path}: no recognized PyInstaller preload modules found")
    return python_version, payloads


def semantic_payload(payload: bytes) -> bytes:
    # PyInstaller 4.x type-m entries may retain a 16-byte .pyc header. Match the
    # product's bootstrap_semantic_payload() rule: CRLF pyc marker at bytes 2:4.
    if len(payload) > 16 and payload[2:4] == b"\r\n":
        return payload[16:]
    return payload


def semantic_hash(helper: pathlib.Path, payload: bytes, python_version: int) -> str:
    with tempfile.NamedTemporaryFile(prefix="auto-refirst-pyi-ref-", suffix=".marshal") as tmp:
        tmp.write(semantic_payload(payload))
        tmp.flush()
        cp = subprocess.run(
            [str(helper), "marshal-hash", tmp.name, str(python_version)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    if cp.returncode != 0:
        raise ValueError(f"semantic helper failed: {cp.stderr.strip()}")
    digest = cp.stdout.strip()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError(f"semantic helper returned invalid SHA-256 {digest!r}")
    return digest


def parse_spec(spec: str) -> tuple[str, pathlib.Path]:
    if "=" not in spec:
        raise argparse.ArgumentTypeError("sample must be LABEL=PATH")
    label, raw_path = spec.split("=", 1)
    if not label or not raw_path:
        raise argparse.ArgumentTypeError("sample must be LABEL=PATH")
    if any(c not in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.+-_" for c in label):
        raise argparse.ArgumentTypeError(f"unsupported label characters: {label!r}")
    path = pathlib.Path(raw_path)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"sample does not exist: {path}")
    return label, path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--semantic-helper", required=True, type=pathlib.Path)
    ap.add_argument("--sample", action="append", required=True, type=parse_spec, metavar="LABEL=PATH")
    args = ap.parse_args()
    if not args.semantic_helper.is_file():
        ap.error(f"semantic helper does not exist: {args.semantic_helper}")

    raw_rows: list[str] = []
    semantic_rows: list[str] = []
    for label, path in args.sample:
        python_version, payloads = parse_sample(path)
        for name in KNOWN_MODULES:
            payload = payloads.get(name)
            if payload is None:
                continue
            raw_sha = hashlib.sha256(payload).hexdigest()
            sem_sha = semantic_hash(args.semantic_helper, payload, python_version)
            raw_rows.append(f'  {{"{label}",{python_version},"{name}",{len(payload)}u,"{raw_sha}"}},')
            semantic_rows.append(f'  {{"{label}",{python_version},"{name}","{sem_sha}"}},')

    print("// raw reference rows")
    print("\n".join(raw_rows))
    print("// semantic reference rows")
    print("\n".join(semantic_rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
