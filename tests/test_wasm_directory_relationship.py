#!/usr/bin/env python3
"""Bounded WebAssembly import/export routing regression."""
from __future__ import annotations
import json, pathlib, struct, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
AR = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "auto-refirst.exe"

def leb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)

def text(s: str) -> bytes:
    b = s.encode()
    return leb(len(b)) + b

def section(kind: int, payload: bytes) -> bytes:
    return bytes([kind]) + leb(len(payload)) + payload

def wasm_import(module: str, name: str) -> bytes:
    # type: () -> (); import: one function using type 0
    types = section(1, b"\x01\x60\x00\x00")
    item = text(module) + text(name) + b"\x00\x00"
    imports = section(2, b"\x01" + item)
    return b"\x00asm\x01\x00\x00\x00" + types + imports

def wasm_export(name: str, extra: int = 0) -> bytes:
    types = section(1, b"\x01\x60\x00\x00")
    exports = bytearray(leb(extra + 1))
    exports += text(name) + b"\x00\x00"
    for i in range(extra):
        exports += text(f"f{i}") + b"\x00\x00"
    return b"\x00asm\x01\x00\x00\x00" + types + section(7, bytes(exports))

def run(root: pathlib.Path) -> dict:
    cp = subprocess.run([str(AR), str(root), "--json"], text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if cp.returncode:
        raise AssertionError(f"rc={cp.returncode}\n{cp.stderr[-2000:]}\n{cp.stdout[-1000:]}")
    return json.loads(cp.stdout)

def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ar-wasm-rel-") as raw:
        root = pathlib.Path(raw)
        (root / "app.wasm").write_bytes(wasm_import("host", "run"))
        (root / "host.wasm").write_bytes(wasm_export("run"))
        good = run(root)
        rels = [x for x in good["directory_plan"]["relationships"]
                if x["kind"] == "wasm_import_module_dependency"]
        assert len(rels) == 1 and rels[0]["state"] == "BOUNDED", rels
        assert rels[0]["priority_eligible"] is True and rels[0]["second_priority_delta"] == 8, rels[0]
        assert "not asserted" in rels[0]["provenance_scope"], rels[0]

        # Two exact module candidates make endpoint selection ambiguous and must
        # not create a priority-bearing relation.
        (root / "alt").mkdir()
        (root / "alt" / "host.wasm").write_bytes(wasm_export("run"))
        ambiguous = run(root)
        assert not [x for x in ambiguous["directory_plan"]["relationships"]
                    if x["kind"] == "wasm_import_module_dependency"], ambiguous["directory_plan"]["relationships"]

        # A large export section is still compacted to the fixed 4096-name view;
        # the unique module/function relation remains bounded and finite.
        (root / "alt" / "host.wasm").unlink()
        (root / "host.wasm").write_bytes(wasm_export("run", 5000))
        capped = run(root)
        assert len([x for x in capped["directory_plan"]["relationships"]
                    if x["kind"] == "wasm_import_module_dependency"]) == 1
        assert capped["directory_summary"]["artifact_relationship_count"] <= 128

        # Truncated/similar input is analyzed as a failed candidate and never
        # yields a cross-file relation.
        (root / "host.wasm").write_bytes(b"\x00asm\x01\x00")
        broken = run(root)
        assert not [x for x in broken["directory_plan"]["relationships"]
                    if x["kind"] == "wasm_import_module_dependency"], broken["directory_plan"]["relationships"]
    print("[PASS] bounded Wasm import/export routing: unique, ambiguous, capped and truncated cases")

if __name__ == "__main__":
    main()
