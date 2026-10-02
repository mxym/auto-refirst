#!/usr/bin/env python3
"""Regression for successful Linux ptrace memory-write provenance.

The runtime tracer should report PTRACE_POKEDATA/PTRACE_POKETEXT only when the
request succeeds, preserving the target PID/address/word so a report can point
to the actual cross-process mutation without claiming that it executed.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile


POSITIVE_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static int child_fn(void *arg) {
    volatile uint64_t *word = (volatile uint64_t *)arg;
    if (raise(SIGSTOP) != 0) _exit(12);
    _exit(*word == UINT64_C(0x1122334455667788) ? 0 : 13);
}

int main(void) {
    volatile uint64_t *word = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (word == MAP_FAILED) return 10;
    *word = 0;
    void *stack = malloc(1 << 20);
    if (!stack) return 11;
    pid_t child = clone(child_fn, (char *)stack + (1 << 20),
                        CLONE_UNTRACED | SIGCHLD, (void *)word);
    if (child < 0) return 12;
    int status = 0;
    if (waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status))
        return 13;
    errno = 0;
    if (ptrace(PTRACE_ATTACH, child, 0, 0) != 0) {
        if (errno == EPERM || errno == ESRCH) return 77;
        return 14;
    }
    if (waitpid(child, &status, 0) != child) return 15;
    errno = 0;
    if (ptrace(PTRACE_POKEDATA, child, (void *)word,
               (void *)(uintptr_t)UINT64_C(0x1122334455667788)) != 0) {
        if (errno == EPERM || errno == ESRCH) return 77;
        return 16;
    }
    if (ptrace(PTRACE_CONT, child, 0, 0) != 0) return 17;
    for (;;) {
        if (waitpid(child, &status, 0) != child) return 18;
        if (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_CONT, child, 0, 0) != 0) return 19;
            continue;
        }
        break;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 20;
}
'''


NEGATIVE_SOURCE = r'''
#include <stdint.h>
int main(void) {
    volatile uint64_t value = 0;
    return value != 0;
}
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
        raise SystemExit("usage: test_runtime_ptrace_write.py AUTO_REFIRST")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-ptrace-") as td:
        root = Path(td)
        positive = build_and_run(cc, root / "positive", POSITIVE_SOURCE,
                                 sys.argv[1], root / "positive-artifacts")
        if positive["runtime"].get("exit_code") == 77:
            print("[SKIP] ptrace memory writes unavailable in this Linux environment")
            return 0
        events = positive["runtime"]["timeline"]
        writes = [
            event for event in events
            if event.get("kind") == "memory_write"
            and event.get("subject") == "ptrace_memory_write"
            and event.get("fields", {}).get("source") == "ptrace"
        ]
        assert len(writes) == 1, writes
        fields = writes[0]["fields"]
        assert fields.get("scope") == "root_process", fields
        assert fields.get("request") == "PTRACE_POKEDATA", fields
        assert int(fields.get("target_pid", "0")) > 0, fields
        assert fields.get("target_address", "").startswith("0x"), fields
        assert fields.get("data_word", "").lower().endswith("1122334455667788"), fields
        assert fields.get("written_bytes") == str(struct.calcsize("l")), fields
        assert fields.get("write_width") == fields.get("written_bytes"), fields

        negative = build_and_run(cc, root / "negative", NEGATIVE_SOURCE,
                                 sys.argv[1], root / "negative-artifacts")
        negative_events = negative["runtime"]["timeline"]
        assert not [
            event for event in negative_events
            if event.get("kind") == "memory_write"
            and event.get("subject") == "ptrace_memory_write"
            and event.get("fields", {}).get("source") == "ptrace"
        ], negative_events
    print("[PASS] ptrace memory-write provenance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
