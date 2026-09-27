#!/usr/bin/env python3
"""Bounded native IAT/code-write triage checks; samples are never executed."""

import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe, put16, put32


def sample(*, write_iat: bool, call_bridge: bool) -> bytes:
    data = bytearray(minimal_pe())
    optional = 0x98
    raw = lambda rva: 0x200 + (rva - 0x1000)
    data.extend(b"\0" * 0x200)
    section = optional + 224
    put32(data, section + 8, 0x400)
    put32(data, section + 16, 0x400)

    # One import descriptor with VirtualProtect and GetProcAddress.  The
    # import directory lives in the same bounded section as the test code.
    put32(data, optional + 96 + 8, 0x1180)
    put32(data, optional + 96 + 12, 0x80)
    descriptor = raw(0x1180)
    put32(data, descriptor + 0, 0x11C0)
    put32(data, descriptor + 12, 0x11E0)
    put32(data, descriptor + 16, 0x11F0)
    put32(data, raw(0x11C0) + 0, 0x1200)
    put32(data, raw(0x11C0) + 4, 0x1210)
    put32(data, raw(0x11F0) + 0, 0x1200)
    put32(data, raw(0x11F0) + 4, 0x1210)
    data[raw(0x11E0):raw(0x11E0) + 13] = b"kernel32.dll\0"
    data[raw(0x1200) + 2:raw(0x1200) + 2 + 14] = b"VirtualProtect\0"
    data[raw(0x1210) + 2:raw(0x1210) + 2 + 14] = b"GetProcAddress\0"

    code = bytearray()
    if write_iat:
        # mov dword ptr [0x004011F0], 0x00401234
        code += b"\xC7\x05" + struct.pack("<I", 0x004011F0) + struct.pack("<I", 0x00401234)
    if call_bridge:
        # call dword ptr [0x004011F4]
        code += b"\xFF\x15" + struct.pack("<I", 0x004011F4)
    code += b"\xC3"
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


def analyze(binary: pathlib.Path, payload: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-native-hook-") as raw:
        sample_path = pathlib.Path(raw) / "sample.exe"
        sample_path.write_bytes(payload)
        completed = subprocess.run(
            [str(binary), str(sample_path), "--json"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return json.loads(completed.stdout.decode("utf-8"))


def finding(report: dict) -> dict | None:
    return next((x for x in report["findings"] if x["family"] == "Native import hook surface"), None)


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    positive = finding(analyze(binary, sample(write_iat=True, call_bridge=True)))
    assert positive is not None and positive["state"] == "LIKELY", positive
    assert positive["variant"] == "iat-slot-write-with-loader-bridge", positive
    assert positive["fields"]["iat_write_count"] == "1", positive
    assert positive["fields"]["bridge_call_count"] == "1", positive
    assert positive["fields"]["iat_targets"] == "kernel32.dll!VirtualProtect", positive
    assert positive["fields"]["runtime_reachability"] == "NOT_RESOLVED_STATIC_ONLY", positive
    assert all(x["coordinate_space"] == "RVA" for x in positive["ranges"]), positive

    write_only = finding(analyze(binary, sample(write_iat=True, call_bridge=False)))
    assert write_only is not None and write_only["state"] == "SUSPECTED", write_only
    assert write_only["variant"] == "iat-slot-write", write_only

    assert finding(analyze(binary, sample(write_iat=False, call_bridge=True))) is None
    assert finding(analyze(binary, sample(write_iat=False, call_bridge=False))) is None
    assert finding(analyze(binary, sample(write_iat=True, call_bridge=True)[:0x210])) is None
    print("[PASS] bounded native IAT/code-write hook surface and bridge/negative boundaries")


if __name__ == "__main__":
    main()
