#!/usr/bin/env python3
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "create_handoff_manifest.py"


def run(report, *args):
    with tempfile.TemporaryDirectory(prefix="ar-handoff-") as td:
        td = pathlib.Path(td)
        src = td / "report.json"
        src.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        cp = subprocess.run([sys.executable, str(TOOL), str(src), *args], text=True,
                            encoding="utf-8", capture_output=True)
        return cp, src.read_bytes()


def main():
    report = {
        "report_schema_version": "1.0",
        "input": "/untrusted/root.bin",
        "input_snapshot": {"exists": True, "size": 12, "sha256": "a" * 64},
        "artifacts": [
            {"path": "/untrusted/z.dll", "kind": "managed", "role": "sidecar", "state": "CONFIRMED", "size": 3, "sha256": "b" * 64},
            {"path": "/untrusted/a.bin", "kind": "opaque", "role": "payload", "state": "PARTIAL", "size": 9, "sha256": "c" * 64},
        ],
        "runtime": {"artifacts": [{"path": "/runtime/memory.bin", "kind": "runtime_dump", "state": "OBSERVED", "runtime_confirmed": True}]},
        "findings": [{"kind": "artifact", "family": "Route", "state": "SUSPECTED", "confidence": 0.5,
                      "evidence": ["z", "a"], "negative_evidence": ["no execution"],
                      "suggested_actions": ["inspect", "inspect"], "fields": {"z": 2, "a": 1}}],
        "artifact_relationships": [{"kind": "loader_route", "state": "CONFIRMED", "first": "/untrusted/root.bin",
                                     "second": "/untrusted/z.dll", "evidence_level": "R2"}],
        "analysis_guidance": {"priority_guidance": ["inspect"]},
    }
    cp, raw = run(report)
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout)
    assert out["kind"] == "auto-refirst.static-handoff-manifest"
    assert out["policy"]["static_only"] and not out["policy"]["execution_authorized"]
    assert not out["policy"]["installation_authorized"] and not out["policy"]["writeback_authorized"]
    assert out["policy"]["path_resolution"] == "DECLARED_ONLY_NO_FOLLOW"
    paths = [x["path"] for x in out["entries"]]
    assert set(paths) == {"/untrusted/a.bin", "/untrusted/z.dll", "/runtime/memory.bin"}
    assert next(x for x in out["entries"] if x["path"] == "/runtime/memory.bin")["trust_state"] == "RUNTIME_OBSERVED_UNTRUSTED"
    assert all(x["execution_allowed"] is False for x in out["entries"])
    assert out["findings"][0]["evidence"] == ["a", "z"]
    assert out["next_actions"] == ["inspect"]
    assert out["truncation"]["entries_total"] == 3
    assert out["generated_from"]["report_sha256"] == hashlib.sha256(raw).hexdigest()

    # Stable output and explicit bounds are part of the transport contract.
    cp1, _ = run(report, "--max-entries", "1", "--max-findings", "0", "--max-relationships", "0")
    cp2, _ = run(report, "--max-entries", "1", "--max-findings", "0", "--max-relationships", "0")
    assert cp1.returncode == cp2.returncode == 0 and cp1.stdout == cp2.stdout
    bounded = json.loads(cp1.stdout)
    assert len(bounded["entries"]) == 1 and not bounded["findings"] and not bounded["relationships"]
    assert bounded["truncation"]["findings_omitted"] == 1
    assert bounded["truncation"]["relationships_omitted"] == 1

    # Envelope and malformed input handling.
    cp, _ = run({"reports": [report]})
    assert cp.returncode == 0 and json.loads(cp.stdout)["generated_from"]["report_count"] == 1
    with tempfile.TemporaryDirectory(prefix="ar-handoff-invalid-") as td:
        bad = pathlib.Path(td) / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        cp = subprocess.run([sys.executable, str(TOOL), str(bad)], text=True, capture_output=True)
        assert cp.returncode == 2 and "not valid" in cp.stderr
    print("[PASS] Deterministic static handoff manifest")


if __name__ == "__main__":
    main()
