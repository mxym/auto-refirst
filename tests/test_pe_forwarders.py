#!/usr/bin/env python3
"""Synthetic PE export-forwarder/API-set evidence contract."""
import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe


def put32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value)


def forwarder_pe(target: bytes = b"KERNEL32.Sleep\0") -> bytes:
    image = bytearray(minimal_pe())
    opt = 0x98
    put32(image, 0x178 + 8, 0x300)           # enlarge .text virtual extent
    # Export directory lives inside the existing .text raw extent.
    put32(image, opt + 96, 0x1080)
    put32(image, opt + 100, 0x80)
    raw = lambda rva: 0x200 + (rva - 0x1000)
    base = raw(0x1080)
    put32(image, base + 12, 0x10E0)       # module name
    put32(image, base + 16, 1)             # ordinal base
    put32(image, base + 20, 1)             # address count
    put32(image, base + 24, 1)             # name count
    put32(image, base + 28, 0x10D0)        # address table
    put32(image, base + 32, 0x10D4)        # name pointer table
    put32(image, base + 36, 0x10D8)        # ordinal table
    image[raw(0x10A0):raw(0x10A0) + len(target)] = target
    module_name = b"proxy.dll\0"
    image[raw(0x10E0):raw(0x10E0) + len(module_name)] = module_name
    image[raw(0x10C0):raw(0x10C0) + 6] = b"Proxy\0"
    put32(image, raw(0x10D0), 0x10A0)
    put32(image, raw(0x10D4), 0x10C0)
    struct.pack_into("<H", image, raw(0x10D8), 0)
    return bytes(image)


def run(binary: pathlib.Path, payload: bytes) -> dict:
    root = pathlib.Path(tempfile.mkdtemp(prefix="ar-forwarder-"))
    sample = root / "proxy.dll"
    sample.write_bytes(payload)
    cp = subprocess.run([str(binary), str(sample), "--json"], check=True,
                        capture_output=True, timeout=30)
    return json.loads(cp.stdout.decode("utf-8"))


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    plain = run(binary, minimal_pe())
    assert not any(f["family"] == "PE export forwarders" for f in plain["findings"])
    report = run(binary, forwarder_pe())
    finding = next(f for f in report["findings"] if f["family"] == "PE export forwarders")
    assert finding["state"] == "CONFIRMED"
    assert finding["fields"]["validated_forwarders"] == "1"
    assert finding["fields"]["api_set_forwarders"] == "0"
    assert finding["ranges"][0]["coordinate_space"] == "RVA"
    assert finding["ranges"][0]["basis"] == "CURRENT_INPUT_IMAGE"

    api = run(binary, forwarder_pe(b"api-ms-win-core-file-l1-1-0.GetFileAttributesW\0"))
    finding = next(f for f in api["findings"] if f["family"] == "PE export forwarders")
    assert finding["fields"]["api_set_forwarders"] == "1"

    malformed = run(binary, forwarder_pe(b"not-a-forwarder\0"))
    finding = next(f for f in malformed["findings"] if f["family"] == "PE export forwarders")
    assert finding["state"] == "PARTIAL"
    assert finding["fields"]["malformed_forwarders"] == "1"
    print("[PASS] bounded PE export forwarder/API-set evidence and malformed target refusal")


if __name__ == "__main__":
    main()
