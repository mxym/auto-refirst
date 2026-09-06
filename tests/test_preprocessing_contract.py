#!/usr/bin/env python3
"""Static-only checks for search and directory evidence handoff."""
from __future__ import annotations
import json
import pathlib
import subprocess
import sys
import tempfile

from run_public_regression import minimal_elf, minimal_pe


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()

    def run(path, *args, code=0):
        cp = subprocess.run([str(binary), str(path), *args], capture_output=True, timeout=90)
        stdout = cp.stdout.decode("utf-8", errors="strict")
        stderr = cp.stderr.decode("utf-8", errors="strict")
        assert cp.returncode == code, (cp.returncode, stderr, stdout[-1000:])
        return stdout

    with tempfile.TemporaryDirectory(prefix="ar-preprocessing-") as raw:
        root = pathlib.Path(raw)
        search = root / "搜索-данные-✓"
        (search / "nested" / "deep").mkdir(parents=True)
        source = search / "样本-✓.数据"
        source.write_bytes(b"prefix NeEdLe suffix\0" + "needle".encode("utf-16le"))
        (search / "nested" / "child.txt").write_bytes(b"needle")
        (search / "nested" / "deep" / "grandchild.txt").write_bytes(b"needle")
        hits = [json.loads(line) for line in run(source, "--search=needle", "--search-ignore-case", "--json").splitlines()]
        assert len(hits) == 2, hits
        assert all(pathlib.Path(hit["file"]) == source for hit in hits)
        assert {hit["encoding"] for hit in hits} == {"ascii", "utf16le"}
        assert {hit["offset"] for hit in hits} == {7, 21}, hits
        assert str(source) in run(source, "--search=needle", "--search-ignore-case")
        for depth, expected in ((0, 2), (1, 3), (2, 4)):
            hits = run(search, "--search=needle", "--search-ignore-case", "--json", f"--max-depth={depth}").splitlines()
            assert len(hits) == expected, (depth, hits)
        assert run(source, "--search=absent", "--json", code=1) == ""

        directory = root / "inventory"
        (directory / "nested").mkdir(parents=True)
        (directory / "nested" / "hidden.txt").write_text("ordinary text", encoding="utf-8")
        (directory / "native.bin").write_bytes(minimal_pe())
        # Ordinary truncated headers remain useful route hints, not validated
        # executable roots. No target is executed by this regression.
        (directory / "short-pe.bin").write_bytes(minimal_pe()[:0x98])
        (directory / "short-elf.bin").write_bytes(minimal_elf()[:18])
        (directory / "module.bin").write_bytes(b"\0asm\x01\0\0\0")
        report = json.loads(run(directory, "--json", "--max-depth=0"))
        states = {pathlib.Path(x["path"]).name: x for x in report["directory_plan"]["file_states"]}
        assert len(states) == 4, states
        for name in ("short-pe.bin", "short-elf.bin"):
            assert states[name]["structural_confidence"] == "rejected", states[name]
            assert states[name]["runtime_eligible"] is False, states[name]
            assert states[name]["role"] == "unvalidated_candidate", states[name]
        assert states["native.bin"]["structural_confidence"] == "validated"
        assert states["module.bin"]["structural_confidence"] == "validated"
        assert states["module.bin"]["type_hint"] == "WebAssembly"
        assert report["directory_summary"]["partial"] is True
        assert report["directory_plan"]["depth_limited_directories"] == 1
        assert report["directory_plan"]["traversal_skips_total"] == 1
        # Bounded diagnostic retention must preserve the true total count.
        scope = root / "scope"
        scope.mkdir()
        (scope / "root.txt").write_text("ordinary text", encoding="utf-8")
        for i in range(140):
            (scope / f"child-{i}").mkdir()
        plan = json.loads(run(scope, "--json", "--max-depth=0"))["directory_plan"]
        assert plan["traversal_skips_total"] == 140, plan
        assert plan["traversal_skips_rendered"] == 64, plan
        assert plan["traversal_skips_truncated"] is True
        # Static preparation must preserve prior authorized runtime outputs and
        # owner markers, while removing stale generated analysis derivatives.
        preserved = root / "preserved"
        preserved.mkdir()
        source = preserved / "plain.txt"
        source.write_text("ordinary static input", encoding="utf-8")
        owned = pathlib.Path(str(source) + ".auto-refirst")
        (owned / "runtime").mkdir(parents=True)
        observation = owned / "runtime" / "retained-observation.bin"
        observation.write_bytes(b"prior runtime observation")
        marker = owned / ".auto-refirst-owner"
        marker.write_text("retained marker", encoding="utf-8")
        (owned / "maps").mkdir()
        stale = owned / "maps" / "stale.csv"
        stale.write_text("stale derivative", encoding="utf-8")
        result = json.loads(run(preserved, "--json"))
        assert observation.read_bytes() == b"prior runtime observation"
        assert marker.read_text(encoding="utf-8") == "retained marker"
        assert not stale.exists()
        assert result["artifact_materialization"]["scope"] == "automatic_static_preparation"
        assert result["artifact_materialization"]["materialized_bytes"] == 0
    print("[PASS] UTF-8 search/offsets/depth + full-analysis directory states + bounded traversal diagnostics")


if __name__ == "__main__":
    main()
