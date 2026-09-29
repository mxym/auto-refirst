#!/usr/bin/env python3
"""Exercise ReadyToRun routing through the product PE/report path."""
import json
import pathlib
import struct
import subprocess
import sys
import tempfile


def p16(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", data, offset, value)


def p32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def r2r_pe() -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    p32(data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    p16(data, 0x84, 0x14C)
    p16(data, 0x86, 2)
    p16(data, 0x94, 224)
    p16(data, 0x96, 0x0102)
    opt = 0x98
    p16(data, opt, 0x10B)
    p32(data, opt + 4, 0x400)
    p32(data, opt + 16, 0x1000)
    p32(data, opt + 20, 0x1000)
    p32(data, opt + 24, 0x2000)
    p32(data, opt + 28, 0x400000)
    p32(data, opt + 32, 0x1000)
    p32(data, opt + 36, 0x200)
    p16(data, opt + 40, 6)
    p16(data, opt + 48, 6)
    p32(data, opt + 56, 0x3000)
    p32(data, opt + 60, 0x200)
    p16(data, opt + 68, 3)
    p32(data, opt + 72, 0x100000)
    p32(data, opt + 76, 0x1000)
    p32(data, opt + 80, 0x100000)
    p32(data, opt + 84, 0x1000)
    p32(data, opt + 92, 16)
    # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14).
    p32(data, opt + 96 + 14 * 8, 0x1100)
    p32(data, opt + 96 + 14 * 8 + 4, 0x48)
    first = opt + 224
    data[first:first + 8] = b".text\0\0\0"
    p32(data, first + 8, 0x400)
    p32(data, first + 12, 0x1000)
    p32(data, first + 16, 0x200)
    p32(data, first + 20, 0x200)
    p32(data, first + 36, 0x60000020)
    second = first + 40
    data[second:second + 8] = b".rrdata\0"
    p32(data, second + 8, 0x400)
    p32(data, second + 12, 0x2000)
    p32(data, second + 16, 0x400)
    p32(data, second + 20, 0x400)
    p32(data, second + 36, 0x40000040)
    # COR20 header at file+0x300 (RVA 0x1100), with ManagedNativeHeader.
    p32(data, 0x300, 0x48)
    p16(data, 0x304, 2)
    p16(data, 0x306, 5)
    p32(data, 0x300 + 64, 0x2000)
    p32(data, 0x300 + 68, 52)
    # READYTORUN_HEADER and three sorted section records at file+0x400.
    header = 0x400
    p32(data, header, 0x00525452)
    p16(data, header + 4, 29)
    p16(data, header + 6, 3)
    p32(data, header + 8, 0x210)
    p32(data, header + 12, 3)
    for index in range(3):
        row = header + 16 + index * 12
        p32(data, row, 101 + index)
        p32(data, row + 4, 0x2050 + index * 0x30)
        p32(data, row + 8, 0x20)
    return bytes(data)


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="ar-readytorun-") as temp:
        path = pathlib.Path(temp) / "renamed.bin"
        path.write_bytes(r2r_pe())
        report = subprocess.run([str(binary), str(path), "--json"], capture_output=True, check=True, timeout=30)
        obj = json.loads(report.stdout.decode("utf-8"))
        r2r = obj["ready_to_run"]
        assert r2r["candidate"] is True and r2r["valid"] is True, r2r
        assert r2r["state"] == "CONFIRMED" and r2r["source"] == "CLI_MANAGED_NATIVE_HEADER", r2r
        assert r2r["section_count"] == 3 and r2r["runtime_function_section_count"] == 1, r2r
        finding = next(item for item in obj["findings"] if item["family"] == ".NET ReadyToRun")
        assert finding["state"] == "CONFIRMED", finding
        text = subprocess.run([str(binary), str(path)], capture_output=True, check=True, timeout=30).stdout.decode("utf-8")
        assert ".NET ReadyToRun:" in text and "method_entrypoints=1" in text, text
    print("[PASS] ReadyToRun PE header routing, section geometry, JSON, and text contract")


if __name__ == "__main__":
    main()
