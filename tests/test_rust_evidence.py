#!/usr/bin/env python3
"""Check that Rust findings separate symbol evidence from marker-only hints."""

from __future__ import annotations

import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe


def with_coff_rust_symbol(data: bytes) -> bytes:
    out = bytearray(data)
    symbol_offset = 0x320
    name = b"_ZN4main4main17h59ae6b2ff26e2dfdE\0"
    struct.pack_into("<II", out, 0x8C, symbol_offset, 1)
    record = bytearray(18)
    struct.pack_into("<II", record, 0, 0, 4)
    struct.pack_into("<I", record, 8, 0)
    struct.pack_into("<h", record, 12, 1)
    struct.pack_into("<H", record, 14, 0x20)
    record[16] = 2
    end = symbol_offset + 18 + 4 + len(name)
    if len(out) < end:
        out.extend(b"\0" * (end - len(out)))
    out[symbol_offset : symbol_offset + 18] = record
    struct.pack_into("<I", out, symbol_offset + 18, 4 + len(name))
    out[symbol_offset + 22 : symbol_offset + 22 + len(name)] = name
    return bytes(out)


def analyze(binary: pathlib.Path, data: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-rust-evidence-") as raw:
        path = pathlib.Path(raw) / "sample.bin"
        path.write_bytes(data)
        cp = subprocess.run(
            [str(binary), str(path), "--json"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        report = json.loads(cp.stdout)
        return report[0] if isinstance(report, list) else report


def finding(report: dict) -> dict:
    return next(item for item in report["findings"] if item.get("family") == "Rust")


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    marker = minimal_pe() + b"rust_begin_unwind\0"
    weak_report = analyze(binary, marker)
    weak = finding(weak_report)
    assert weak["state"] == "LIKELY", weak
    assert weak["fields"]["evidence_mode"] == "RUNTIME_MARKER_ONLY", weak
    assert weak["fields"]["runtime_marker_count"] == "1", weak
    assert weak["negative_evidence"], weak
    assert weak_report["rust"]["state"] == "LIKELY", weak_report["rust"]
    assert weak_report["rust"]["runtime_marker_offsets"], weak_report["rust"]

    symbol_report = analyze(binary, with_coff_rust_symbol(minimal_pe()))
    symbol = finding(symbol_report)
    assert symbol["state"] == "CONFIRMED", symbol
    assert symbol["fields"]["evidence_mode"] == "SYMBOLS", symbol
    assert int(symbol["fields"]["demangled_symbols"]) >= 1, symbol
    assert symbol_report["rust"]["state"] == "CONFIRMED", symbol_report["rust"]
    print("[PASS] Rust marker-only evidence is LIKELY and demangled COFF symbols remain CONFIRMED")


if __name__ == "__main__":
    main()
