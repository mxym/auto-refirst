#!/usr/bin/env python3
"""Bounded PE custom-loader surface routing checks; samples are never executed."""

import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe


def p32(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value)


def image(*, relocations: bool) -> bytes:
    buf = bytearray(minimal_pe())
    opt = 0x98
    raw = lambda rva: 0x200 + (rva - 0x1000)

    # Import descriptor, two resolver APIs, and the terminating thunk.
    p32(buf, opt + 96 + 8, 0x1080)
    p32(buf, opt + 96 + 12, 0x40)
    desc = raw(0x1080)
    p32(buf, desc + 0, 0x10C0)
    p32(buf, desc + 12, 0x10F0)
    p32(buf, desc + 16, 0x10C0)
    p32(buf, raw(0x10C0) + 0, 0x1120)
    p32(buf, raw(0x10C0) + 4, 0x1140)
    p32(buf, raw(0x10C0) + 8, 0)
    buf[raw(0x10F0):raw(0x10F0) + 13] = b"kernel32.dll\0"
    buf[raw(0x1120) + 2:raw(0x1120) + 2 + 13] = b"LoadLibraryA\0"
    buf[raw(0x1140) + 2:raw(0x1140) + 2 + 14] = b"GetProcAddress\0"

    if relocations:
        p32(buf, opt + 96 + 5 * 8, 0x1180)
        p32(buf, opt + 96 + 5 * 8 + 4, 8)
        struct.pack_into("<II", buf, raw(0x1180), 0x1000, 8)
    return bytes(buf)


def run(binary: pathlib.Path, payload: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-pe-loader-surface-") as raw:
        sample = pathlib.Path(raw) / "sample.exe"
        sample.write_bytes(payload)
        completed = subprocess.run(
            [str(binary), str(sample), "--json"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return json.loads(completed.stdout.decode("utf-8"))


def loader_finding(report: dict) -> dict | None:
    return next((f for f in report["findings"] if f["family"] == "PE custom loader surface"), None)


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    assert loader_finding(run(binary, image(relocations=False))) is None
    finding = loader_finding(run(binary, image(relocations=True)))
    assert finding is not None, "resolver imports without relocation geometry must not route"
    assert finding["state"] == "SUSPECTED", finding
    assert finding["variant"] == "resolver-relocation-low-import-surface", finding
    assert finding["fields"]["resolver_api_count"] == "2", finding
    assert finding["fields"]["relocation_directory"] == "true", finding
    assert finding["fields"]["relocation_geometry_valid"] == "true", finding
    assert finding["fields"]["relocation_blocks"] == "1", finding
    assert finding["fields"]["runtime_resolution"] == "NOT_ATTEMPTED_STATIC_ONLY", finding
    assert all(r["coordinate_space"] == "RVA" for r in finding["ranges"]), finding
    malformed = bytearray(image(relocations=True))
    p32(malformed, 0x200 + (0x1180 - 0x1000) + 4, 7)
    assert loader_finding(run(binary, bytes(malformed))) is None
    print("[PASS] bounded PE custom-loader surface: resolver/relocation route and sparse negative")


if __name__ == "__main__":
    main()
