#!/usr/bin/env python3
"""Regression for bounded Linux debugger-control evidence.

Only explicit debugger-restriction/self-tracing controls are surfaced.  The
report retains the operation and return status; an observed call is not turned
into an intent claim.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


POSITIVE_SOURCE = r'''
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/ptrace.h>
int main(void) {
    (void)prctl(PR_SET_DUMPABLE, 0);
    (void)prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    (void)ptrace(PTRACE_TRACEME, 0, 0, 0);
    return 0;
}
'''

NEGATIVE_SOURCE = r'''
int main(void) { return 0; }
'''


def build_and_run(cc: str, binary: Path, source: str, runner: str,
                  artifact_root: Path) -> dict:
    src = binary.with_suffix(".c")
    src.write_text(source)
    cp = subprocess.run([cc, "-O2", "-Wall", str(src), "-o", str(binary)],
                        capture_output=True, text=True)
    if cp.returncode:
        raise AssertionError(cp.stderr)
    cp = subprocess.run(
        [runner, str(binary), "--run", "--timeout=5000",
         f"--artifact-root={artifact_root}", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    if cp.returncode:
        raise AssertionError(cp.stderr or cp.stdout)
    return json.loads(cp.stdout)


def main() -> int:
    if sys.platform != "linux":
        print("[SKIP] Linux runtime backend")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_runtime_debugger_control.py AUTO_REFIRST")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-debugger-control-") as td:
        root = Path(td)
        positive = build_and_run(cc, root / "positive", POSITIVE_SOURCE,
                                 sys.argv[1], root / "positive-artifacts")
        events = [
            event for event in positive["runtime"]["timeline"]
            if event.get("kind") == "debugger_control"
        ]
        assert len(events) >= 3, events
        operations = {event.get("fields", {}).get("operation") for event in events}
        assert {"PR_SET_DUMPABLE", "PR_SET_PTRACER", "PTRACE_TRACEME"} <= operations, events
        for event in events:
            fields = event["fields"]
            assert fields.get("scope") == "root_process", fields
            assert fields.get("source") in {"prctl", "ptrace"}, fields
            assert fields.get("success") in {"true", "false"}, fields
        negative = build_and_run(cc, root / "negative", NEGATIVE_SOURCE,
                                 sys.argv[1], root / "negative-artifacts")
        assert not [
            event for event in negative["runtime"]["timeline"]
            if event.get("kind") == "debugger_control"
        ], negative["runtime"]["timeline"]
    print("[PASS] Linux debugger-control evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
