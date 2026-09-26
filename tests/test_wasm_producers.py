#!/usr/bin/env python3
"""Focused checks for bounded WebAssembly producers metadata evidence."""
from __future__ import annotations

import json
import pathlib
import struct
import subprocess
import sys
import tempfile


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        out.append(b | (0x80 if value else 0))
        if not value:
            return bytes(out)


def wasm_section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + uleb(len(payload)) + payload


def wasm_name(text: bytes) -> bytes:
    return uleb(len(text)) + text


def base_module(producers: bytes) -> bytes:
    # One () -> () function exported as main. The body is deliberately tiny;
    # the test targets the optional custom metadata, not instruction recovery.
    module = bytearray(b"\x00asm\x01\x00\x00\x00")
    module += wasm_section(1, b"\x01\x60\x00\x00")
    module += wasm_section(3, b"\x01\x00")
    module += wasm_section(7, b"\x01" + wasm_name(b"main") + b"\x00\x00")
    module += wasm_section(10, b"\x01\x02\x00\x0b")
    module += wasm_section(0, wasm_name(b"producers") + producers)
    return bytes(module)


def valid_producers() -> bytes:
    return b"\x01" + wasm_name(b"language") + b"\x01" + wasm_name(b"Rust") + wasm_name(b"1.80.0")


def run(binary: pathlib.Path, payload: bytes) -> dict:
    with tempfile.NamedTemporaryFile(prefix="ar-wasm-producers-", suffix=".wasm", delete=False) as f:
        path = pathlib.Path(f.name)
        f.write(payload)
    try:
        cp = subprocess.run([str(binary), str(path), "--json"], capture_output=True, timeout=90)
        assert cp.returncode == 0, (cp.returncode, cp.stderr.decode("utf-8", "replace"))
        return json.loads(cp.stdout.decode("utf-8"))
    finally:
        path.unlink(missing_ok=True)


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    good = run(binary, base_module(valid_producers()))
    wasm = good["wasm"]
    assert wasm["valid"] and wasm["producer_parse_complete"], wasm
    assert wasm["producer_field_count"] == 1 and wasm["producer_value_count"] == 1, wasm
    assert wasm["producers"] == [{"field": "language", "name": "Rust", "version": "1.80.0"}], wasm
    finding = next(f for f in good["findings"] if f["family"] == "WebAssembly")
    assert finding["state"] == "CONFIRMED" and finding["fields"]["producers"] == "1", finding

    # Optional metadata must fail closed without invalidating an otherwise
    # structurally valid module. This also exercises truncation at the parser
    # boundary rather than relying on a filename hint.
    malformed = run(binary, base_module(b"\x01\x08language"))
    wasm = malformed["wasm"]
    assert wasm["valid"] and not wasm["producer_parse_complete"], wasm
    assert wasm["producer_value_count"] == 0, wasm
    finding = next(f for f in malformed["findings"] if f["family"] == "WebAssembly")
    assert finding["state"] == "CONFIRMED", finding
    assert any("producers" in item.lower() for item in finding["negative_evidence"]), finding

    # A producer string beyond the bounded 256-byte metadata field is retained
    # only as an incomplete hint and never admitted into the result vector.
    oversized = b"\x01" + wasm_name(b"language") + b"\x01" + wasm_name(b"A" * 257) + wasm_name(b"1")
    limited = run(binary, base_module(oversized))["wasm"]
    assert limited["valid"] and not limited["producer_parse_complete"], limited
    assert limited["producer_value_count"] == 0, limited
    print("[PASS] bounded WebAssembly producers metadata evidence and malformed/oversized boundaries")


if __name__ == "__main__":
    main()
