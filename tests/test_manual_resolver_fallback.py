#!/usr/bin/env python3
"""Bounded manual-resolver detection when an x64 PE has no .pdata."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def p16(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buf, offset, value)


def p32(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value)


def p64(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buf, offset, value)


def manual_resolver_image(modified_hash: bool = False) -> bytes:
    """Create an inert x64 PE carrying only the resolver instruction shape."""
    image = bytearray(0x2200)
    image[:2] = b"MZ"
    p32(image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    p16(image, 0x84, 0x8664)
    p16(image, 0x86, 1)
    p16(image, 0x94, 240)
    p16(image, 0x96, 0x2022)

    optional = 0x98
    p16(image, optional, 0x20B)
    p32(image, optional + 4, 0x2000)
    p32(image, optional + 16, 0x1000)
    p32(image, optional + 20, 0x1000)
    p64(image, optional + 24, 0x140000000)
    p32(image, optional + 32, 0x1000)
    p32(image, optional + 36, 0x200)
    p32(image, optional + 56, 0x3000)
    p32(image, optional + 60, 0x200)
    p16(image, optional + 68, 3)
    p32(image, optional + 72, 0x100000)
    p32(image, optional + 76, 0x1000)
    p32(image, optional + 80, 0x100000)
    p32(image, optional + 84, 0x1000)
    p32(image, optional + 108, 16)

    section = optional + 240
    image[section:section + 8] = b".text\0\0\0"
    p32(image, section + 8, 0x2000)
    p32(image, section + 12, 0x1000)
    p32(image, section + 16, 0x2000)
    p32(image, section + 20, 0x200)
    p32(image, section + 36, 0x60000020)

    # PEB -> loader list -> PE/export directory geometry, FNV-1a32 loop,
    # indexed name/function table accesses and module-relative return.
    code_hex = (
        "65488b042560000000"
        "488b4018 488b4020 8b403c 3d50450000 8b8088000000"
        "8b4818 8b4820 8b481c 8b4824"
        "b9c59d1c81 69c993010001"
        "4c8b00 4c8b4808 75fe"
        "81f978563412 0fb70441 8b0481 4801c8 c3"
    ).replace(" ", "")
    if modified_hash:
        code_hex = code_hex.replace(
            "b9c59d1c8169c993010001", "b97856341269c911223344"
        )
    code = bytes.fromhex(code_hex)
    image[0x200:0x200 + len(code)] = code
    return bytes(image)


def run(binary: Path, payload: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-manual-resolver-") as raw:
        sample = Path(raw) / "sample.exe"
        sample.write_bytes(payload)
        completed = subprocess.run(
            [str(binary), str(sample), "--json"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return json.loads(completed.stdout.decode("utf-8"))


def main() -> None:
    binary = Path(sys.argv[1]).resolve()
    payload = manual_resolver_image()
    report = run(binary, payload)
    finding = next(
        (x for x in report["findings"] if x.get("family") == "Manual API resolver"),
        None,
    )
    assert finding is not None, report["findings"]
    assert finding["state"] == "SUSPECTED", finding
    assert finding["variant"] == "x64 PEB/export/FNV1A32/no-pdata-entry-window", finding
    assert finding["fields"]["function_boundary_state"] == "ENTRY_SECTION_WINDOW", finding
    assert finding["ranges"] and all(
        item["coordinate_space"] == "RVA" for item in finding["ranges"]
    ), finding

    modified_report = run(binary, manual_resolver_image(modified_hash=True))
    modified = next(
        (x for x in modified_report["findings"] if x.get("family") == "Manual API resolver"),
        None,
    )
    assert modified is not None, modified_report["findings"]
    assert modified["state"] == "SUSPECTED", modified
    assert modified["variant"] == "x64 PEB/export/modified-name-hash/no-pdata-entry-window", modified
    assert modified["fields"]["hash_algorithm"] == "MODIFIED_OR_UNKNOWN_NAME_HASH", modified
    assert modified["fields"]["known_api_name_matches"] == "0", modified
    assert modified["fields"]["target_identity_state"] == "MODIFIED_OR_UNKNOWN_HASH_NO_STATIC_API_NAME", modified

    damaged = bytearray(payload)
    damaged[0x200 + 0x2C] ^= 0x01  # FNV seed no longer passes the raw gate.
    damaged_report = run(binary, bytes(damaged))
    assert not any(
        x.get("family") == "Manual API resolver" for x in damaged_report["findings"]
    ), damaged_report["findings"]
    print("[PASS] bounded no-.pdata manual API resolver entry-window fallback")


if __name__ == "__main__":
    main()
