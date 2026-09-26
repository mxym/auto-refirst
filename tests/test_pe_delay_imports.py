#!/usr/bin/env python3
"""Synthetic PE delay-import descriptor/thunk evidence contract."""
import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe


def put32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value)


def delay_pe(*, malformed: bool = False, va_based: bool = False) -> bytes:
    image = bytearray(minimal_pe())
    opt = 0x98
    put32(image, 0x178 + 8, 0x300)
    put32(image, opt + 96 + 13 * 8, 0x1100)
    put32(image, opt + 96 + 13 * 8 + 4, 0x20 if malformed else 0x80)
    raw = lambda rva: 0x200 + (rva - 0x1000)
    descriptor = raw(0x1100)
    put32(image, descriptor + 0, 0 if va_based else 1)  # IMAGE_DELAY_IMPORT_ATTRIBUTE_RVA
    base = 0x400000 if va_based else 0
    put32(image, descriptor + 4, base + 0x1150)  # DLL name
    put32(image, descriptor + 12, base + 0x1160) # delay IAT
    put32(image, descriptor + 16, base + 0x1170) # delay INT
    image[raw(0x1150):raw(0x1150) + 11] = b"USER32.dll\0"
    put32(image, raw(0x1170), base + 0x1180)
    put32(image, raw(0x1174), 0)
    put32(image, raw(0x1160), base + 0x1180)
    put32(image, raw(0x1164), 0)
    struct.pack_into("<H", image, raw(0x1180), 0)
    image[raw(0x1182):raw(0x1182) + 13] = b"LoadLibraryA\0"
    return bytes(image)


def run(binary: pathlib.Path, payload: bytes) -> dict:
    root = pathlib.Path(tempfile.mkdtemp(prefix="ar-delay-import-"))
    sample = root / "delayed.dll"
    sample.write_bytes(payload)
    cp = subprocess.run([str(binary), str(sample), "--json"], check=True,
                        capture_output=True, timeout=30)
    return json.loads(cp.stdout.decode("utf-8"))


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    plain = run(binary, minimal_pe())
    assert not any(f["family"] == "PE delay-load imports" for f in plain["findings"])
    report = run(binary, delay_pe())
    finding = next(f for f in report["findings"] if f["family"] == "PE delay-load imports")
    assert finding["state"] == "CONFIRMED"
    assert finding["fields"]["descriptor_count"] == "1"
    assert finding["fields"]["function_count"] == "1"
    assert finding["fields"]["rva_based_descriptors"] == "1"
    assert finding["fields"]["libraries"] == "USER32.dll"
    assert finding["fields"]["symbols"] == "USER32.dll!LoadLibraryA"
    assert finding["fields"]["load_resolution"] == "NOT_ATTEMPTED_STATIC_ONLY"
    assert finding["ranges"][0]["coordinate_space"] == "RVA"
    assert finding["ranges"][0]["basis"] == "CURRENT_INPUT_IMAGE"

    va = run(binary, delay_pe(va_based=True))
    finding = next(f for f in va["findings"] if f["family"] == "PE delay-load imports")
    assert finding["state"] == "CONFIRMED"
    assert finding["fields"]["va_based_descriptors"] == "1"

    broken = run(binary, delay_pe(malformed=True))
    finding = next(f for f in broken["findings"] if f["family"] == "PE delay-load imports")
    assert finding["state"] == "PARTIAL"
    assert finding["fields"]["parse_complete"] == "false"
    print("[PASS] bounded PE delay-load descriptors/thunks and malformed boundaries")


if __name__ == "__main__":
    main()
