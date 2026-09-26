#!/usr/bin/env python3
"""Synthetic PE/CLR bootstrap import contract checks (static only)."""
import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe


def p16(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<H", buf, off, value)


def p32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value)


def with_imports(*, clr: bool, function: bytes = b"_CorExeMain\0", dll: bool = False) -> bytes:
    image = bytearray(minimal_pe())
    opt = 0x98
    if dll:
        p16(image, 0x96, 0x2102)
    raw = lambda rva: 0x200 + (rva - 0x1000)
    # Import descriptor at 0x1080, thunk at 0x10c0, and one mscoree name.
    p32(image, opt + 96 + 8, 0x1080)
    p32(image, opt + 96 + 12, 0x40)
    base = raw(0x1080)
    p32(image, base + 0, 0x10C0)
    p32(image, base + 12, 0x10F0)
    p32(image, base + 16, 0x10C0)
    p32(image, raw(0x10C0), 0x1120)
    p32(image, raw(0x10C4), 0)
    module = b"mscoree.dll\0"
    image[raw(0x10F0):raw(0x10F0) + len(module)] = module
    p16(image, raw(0x1120), 0)
    image[raw(0x1122):raw(0x1122) + len(function)] = function
    if clr:
        p32(image, opt + 96 + 14 * 8, 0x1140)
        p32(image, opt + 96 + 14 * 8 + 4, 0x48)
        # A bounded but intentionally incomplete COR20 header. The loader
        # contract reports the import relationship while metadata stays PARTIAL.
        p32(image, raw(0x1140), 0x48)
        p16(image, raw(0x1144), 2)
        p16(image, raw(0x1146), 5)
    return bytes(image)


def run(binary: pathlib.Path, payload: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-dotnet-loader-") as raw:
        sample = pathlib.Path(raw) / "sample.exe"
        sample.write_bytes(payload)
        cp = subprocess.run([str(binary), str(sample), "--json"], check=True,
                            capture_output=True, timeout=30)
        return json.loads(cp.stdout.decode("utf-8"))


def finding(report: dict) -> dict:
    return next(f for f in report["findings"] if f["family"] == "CLR bootstrap import contract")


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    plain = run(binary, minimal_pe())
    assert not any(f["family"] == "CLR bootstrap import contract" for f in plain["findings"])

    standard = finding(run(binary, with_imports(clr=True)))
    assert standard["state"] == "PARTIAL", standard
    assert standard["variant"] == "STANDARD_EXE_BOOTSTRAP", standard
    assert standard["fields"]["standard_bootstrap_imports"] == "1", standard
    assert standard["fields"]["runtime_resolution"] == "NOT_ATTEMPTED_STATIC_ONLY", standard
    assert standard["ranges"][0]["coordinate_space"] == "RVA", standard

    orphan = finding(run(binary, with_imports(clr=False)))
    assert orphan["state"] == "PARTIAL", orphan
    assert orphan["variant"] == "MSCOREE_IMPORT_WITHOUT_CLR_DIRECTORY", orphan

    host = finding(run(binary, with_imports(clr=True, function=b"CLRCreateInstance\0")))
    assert host["variant"] == "CUSTOM_CLR_HOST_API_IMPORTS", host
    assert host["fields"]["host_api_imports"] == "1", host

    damaged = finding(run(binary, with_imports(clr=True, function=b"_CorExeMaiX\0")))
    assert damaged["state"] == "PARTIAL", damaged
    assert damaged["variant"] == "MSCOREE_IMPORT_WITHOUT_KNOWN_ENTRYPOINT", damaged

    mismatch = finding(run(binary, with_imports(clr=True, dll=True)))
    assert mismatch["state"] == "PARTIAL", mismatch
    assert "does not match" in " ".join(mismatch["negative_evidence"]), mismatch
    print("[PASS] bounded CLR bootstrap import contract, custom host and mismatch boundaries")


if __name__ == "__main__":
    main()
