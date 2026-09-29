#!/usr/bin/env python3
"""Bounded ASAR JavaScript literal-to-Wasm/native member routing checks."""

import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe

ROOT = pathlib.Path(__file__).resolve().parents[1]
WASM = (ROOT / "tests/corpus/wasm/check_flag.o").read_bytes()


def make_asar(files: list[tuple[str, bytes, bool]]) -> bytes:
    offset = 0
    metadata: dict[str, object] = {}
    payload = bytearray()
    for name, data, unpacked in files:
        entry: dict[str, object] = {"size": len(data)}
        if unpacked:
            entry["unpacked"] = True
        else:
            entry["offset"] = str(offset)
            payload.extend(data)
            offset += len(data)
        metadata[name] = entry
    header = json.dumps({"files": metadata}, separators=(",", ":")).encode()
    aligned = (len(header) + 3) & ~3
    payload_size = 4 + aligned
    header_size = payload_size + 4
    return struct.pack("<IIII", 4, header_size, payload_size, len(header)) + header + b"\0" * (aligned - len(header)) + payload


def run(binary: pathlib.Path, files: list[tuple[str, bytes, bool]], *, unpacked_sibling: bool = False) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-asar-bridge-") as raw:
        root = pathlib.Path(raw)
        archive = root / "app.asar"
        archive.write_bytes(make_asar(files))
        if unpacked_sibling:
            sibling = pathlib.Path(str(archive) + ".unpacked")
            (sibling / "app.wasm").parent.mkdir(parents=True)
            (sibling / "app.wasm").write_bytes(WASM)
        cp = subprocess.run([str(binary), str(archive), "--json"], check=True, capture_output=True, timeout=30)
        return json.loads(cp.stdout.decode("utf-8"))


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    direct = run(binary, [("package.json", b"{}", False), ("app.js", b"WebAssembly.instantiateStreaming(fetch('app.wasm'));\n", False), ("app.wasm", WASM, False)])
    assert "app.wasm" in direct["asar"]["interesting_paths"], direct["asar"]
    assert any(x["kind"] == "asar_script_wasm_dependency" for x in direct["asar"]["script_references"]), direct["asar"]
    direct_ref = next(x for x in direct["asar"]["script_references"] if x["target_path"] == "app.wasm")
    assert direct_ref["source_line"] == 1 and direct_ref["resolution_basis"] == "ASAR_PACKED_OFFSET", direct_ref
    assert direct_ref["target_unpacked"] is False and direct_ref["target_size"] == len(WASM), direct_ref
    assert direct["asar"]["script_reference_scanned_files"] == 1, direct["asar"]
    assert direct["asar"]["script_reference_scanned_bytes"] > 0, direct["asar"]
    assert direct["asar"]["script_reference_scan_limited"] is False, direct["asar"]
    relation = next(x for x in direct["artifact_relationships"] if x["kind"] == "asar_script_wasm_dependency")
    assert relation["state"] == "BOUNDED" and relation["evidence_level"] == "R2_STRUCTURAL_RELATION", relation
    assert relation["priority_eligible"] is False, relation
    assert ";line=1;" in relation["source_coordinate"] and ";basis=ASAR_PACKED_OFFSET;" in relation["target_coordinate"], relation
    finding = next(x for x in direct["findings"] if x["family"] == "ASAR script child route")
    assert finding["fields"]["target_validation"] == "CONFIRMED", finding
    assert finding["fields"]["source_line"] == "1", finding
    assert finding["fields"]["resolution_basis"] == "ASAR_PACKED_OFFSET", finding

    native = run(binary, [("app.js", b"require('./addon.node');\n", False), ("addon.node", minimal_pe(), False)])
    assert any(x["kind"] == "asar_script_native_dependency" for x in native["artifact_relationships"]), native["artifact_relationships"]

    dynamic = run(binary, [("app.js", b"const p='app.wasm'; fetch(p); fetch('app.' + 'wasm'); // fetch('app.wasm')\n", False), ("app.wasm", WASM, False)])
    assert not dynamic["artifact_relationships"], dynamic["artifact_relationships"]
    assert not dynamic["asar"]["script_references"], dynamic["asar"]

    strict_cases = {
        "suffix": b"fetch('app.wasm' + suffix);\n",
        "regex": b"const decoy = /fetch('app.wasm')/;\n",
        "property": b"obj.fetch('app.wasm');\n",
    }
    for label, code in strict_cases.items():
        strict = run(binary, [("app.js", code, False), ("app.wasm", WASM, False)])
        assert not strict["asar"]["script_references"], (label, strict["asar"])
        assert not strict["artifact_relationships"], (label, strict["artifact_relationships"])

    missing = run(binary, [("app.js", b"fetch('app.wasm');\n", False), ("app.wasm", WASM, True)])
    assert not missing["artifact_relationships"], missing["artifact_relationships"]
    unresolved = next(x for x in missing["findings"] if x["family"] == "ASAR script child route")
    assert unresolved["state"] == "LOCATED_NOT_MATERIALIZED" and unresolved["fields"]["target_materialized"] == "false", unresolved

    unpacked = run(binary, [("app.js", b"fetch('./app.wasm');\n", False), ("app.wasm", WASM, True)], unpacked_sibling=True)
    relation = next(x for x in unpacked["artifact_relationships"] if x["kind"] == "asar_script_wasm_dependency")
    assert relation["state"] == "BOUNDED", relation
    print("[PASS] bounded ASAR literal-to-Wasm/native routing, dynamic and unpacked boundaries")


if __name__ == "__main__":
    main()
