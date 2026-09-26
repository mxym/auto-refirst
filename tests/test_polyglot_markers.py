#!/usr/bin/env python3
"""Bounded regression for non-standard layered/polyglot marker triage."""
import json
import pathlib
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe


def analyze(binary: pathlib.Path, payload: bytes) -> dict:
    root = pathlib.Path(tempfile.mkdtemp(prefix="ar-polyglot-"))
    sample = root / "layered.bin"
    sample.write_bytes(payload)
    cp = subprocess.run([str(binary), str(sample), "--json"], check=True,
                        capture_output=True, timeout=30)
    return json.loads(cp.stdout.decode("utf-8"))


def analyze_text(binary: pathlib.Path, payload: bytes) -> str:
    root = pathlib.Path(tempfile.mkdtemp(prefix="ar-polyglot-text-"))
    sample = root / "layered.bin"
    sample.write_bytes(payload)
    cp = subprocess.run([str(binary), str(sample)], check=True,
                        capture_output=True, timeout=30)
    return cp.stdout.decode("utf-8")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_polyglot_markers.py <auto-refirst>")
    binary = pathlib.Path(sys.argv[1]).resolve()
    outer = bytearray(minimal_pe())
    outer.extend(b"\0" * 128)
    outer.extend(b"%PDF-1.7\n")
    outer.extend(b"\0" * 256)
    outer.extend(bytes.fromhex("cffaedfe"))
    outer.extend(b"\0" * 256)
    outer.extend(b"PK\x03\x04")
    report = analyze(binary, bytes(outer))
    finding = next((f for f in report["findings"]
                    if f["family"] == "Layered/polyglot format markers"), None)
    assert finding is not None, report["findings"]
    assert finding["state"] == "SUSPECTED"
    assert float(finding["confidence"]) < 0.5
    assert finding["fields"]["offset_space"] == "current_input_file"
    assert int(finding["fields"]["distinct_format_count"]) >= 2
    assert all(r["offset"] > 0 for r in finding["ranges"])
    assert "Layered/polyglot format markers" in analyze_text(binary, bytes(outer))

    single = analyze(binary, bytes(minimal_pe()) + b"\0" * 256 + b"%PDF-1.7\n")
    assert not any(f["family"] == "Layered/polyglot format markers"
                   for f in single["findings"]), single["findings"]
    late = bytearray(minimal_pe())
    late.extend(b"\0" * (16 * 1024 * 1024))
    late.extend(b"%PDF-1.7\n\0\0\0\0" + bytes.fromhex("cffaedfe"))
    assert not any(f["family"] == "Layered/polyglot format markers"
                   for f in analyze(binary, bytes(late))["findings"])
    print("[PASS] bounded layered/polyglot markers: multi-format offsets, coordinate evidence, single-marker negative")


if __name__ == "__main__":
    main()
