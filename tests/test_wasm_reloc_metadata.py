#!/usr/bin/env python3
"""Bounded WebAssembly linking/relocation metadata checks."""
import json
import pathlib
import subprocess
import sys
import tempfile


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def section(kind: int, payload: bytes) -> bytes:
    return bytes([kind]) + uleb(len(payload)) + payload


def custom(name: bytes, body: bytes) -> bytes:
    return section(0, uleb(len(name)) + name + body)


def module(linking: bytes, reloc: bytes) -> bytes:
    data = bytearray(b"\0asm\1\0\0\0")
    data += section(1, b"\1\x60\0\0")
    data += section(3, b"\1\0")
    data += section(7, b"\1" + uleb(4) + b"main\0\0")
    data += section(10, b"\1\2\0\x0b")
    if linking:
        data += custom(b"linking", linking)
    if reloc:
        data += custom(b"reloc.CODE", reloc)
    return bytes(data)


def run(binary: pathlib.Path, payload: bytes) -> dict:
    root = pathlib.Path(tempfile.mkdtemp(prefix="ar-wasm-reloc-"))
    path = root / "sample.wasm"
    path.write_bytes(payload)
    cp = subprocess.run([str(binary), str(path), "--json"], capture_output=True,
                        timeout=90, check=True)
    return json.loads(cp.stdout.decode("utf-8"))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_wasm_reloc_metadata.py <auto-refirst>")
    binary = pathlib.Path(sys.argv[1]).resolve()
    linking = uleb(2) + bytes([1]) + uleb(0)
    reloc = uleb(10) + uleb(1) + uleb(0) + uleb(0) + uleb(0)
    report = run(binary, module(linking, reloc))
    wasm = report["wasm"]
    assert wasm["valid"] and wasm["linking_section_present"]
    assert wasm["linking_metadata_valid"] and wasm["relocatable"]
    assert wasm["linking_version"] == 2
    assert wasm["relocation_section_count"] == 1
    assert wasm["relocation_entry_count"] == 1
    assert wasm["relocation_parse_complete"]
    finding = next(f for f in report["findings"] if f["family"] == "WebAssembly")
    assert finding["fields"]["linking_state"] == "CONFIRMED"
    assert finding["fields"]["relocation_state"] == "BOUNDED"

    malformed = run(binary, module(uleb(3), b""))
    wasm = malformed["wasm"]
    assert wasm["valid"] and wasm["linking_section_present"]
    assert not wasm["linking_metadata_valid"] and not wasm["relocatable"]
    finding = next(f for f in malformed["findings"] if f["family"] == "WebAssembly")
    assert any("linking" in item.lower() for item in finding["negative_evidence"])

    truncated = run(binary, module(linking, uleb(10) + uleb(1) + b"\0"))
    wasm = truncated["wasm"]
    assert wasm["valid"] and wasm["relocation_section_count"] == 1
    assert not wasm["relocation_parse_complete"]
    print("[PASS] bounded Wasm linking/relocatable metadata: valid geometry, unsupported version and truncated relocation")


if __name__ == "__main__":
    main()
