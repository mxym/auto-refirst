#!/usr/bin/env python3
"""Regression for bounded process_vm_writev cross-process provenance.

The Linux runtime tracer should emit a MemoryWrite event only after a
successful process_vm_writev return.  The event identifies the caller and
target PID separately, records bounded iovec parsing state, and exposes the
remote ranges only when their arithmetic is safe.  A similar anonymous
mapping that does not call process_vm_writev must not produce that event.
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
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int address_pipe[2], go_pipe[2];
    if (pipe(address_pipe) || pipe(go_pipe)) return 10;
    pid_t child = fork();
    if (child < 0) return 11;
    if (child == 0) {
        close(address_pipe[0]);
        close(go_pipe[1]);
        void *remote = mmap(NULL, 7, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (remote == MAP_FAILED) _exit(12);
        uintptr_t address = (uintptr_t)remote;
        if (write(address_pipe[1], &address, sizeof(address)) !=
            (ssize_t)sizeof(address)) _exit(13);
        close(address_pipe[1]);
        char go;
        if (read(go_pipe[0], &go, 1) != 1) _exit(14);
        close(go_pipe[0]);
        if (go == 's') _exit(77);
        if (mprotect(remote, 7, PROT_READ | PROT_EXEC) != 0) _exit(15);
        int value = ((int (*)(void))remote)();
        _exit(value == 43 ? 0 : 16);
    }
    close(address_pipe[1]);
    close(go_pipe[0]);
    uintptr_t address = 0;
    if (read(address_pipe[0], &address, sizeof(address)) !=
        (ssize_t)sizeof(address)) return 17;
    close(address_pipe[0]);
    unsigned char code[] = {0xb8, 43, 0, 0, 0, 0xc3, 0};
    struct iovec local[2] = {{code, 0}, {code, sizeof(code)}};
    struct iovec remote_iov[2] = {{(void *)address, 0},
                                  {(void *)address, sizeof(code)}};
    ssize_t written = syscall(SYS_process_vm_writev, child, local, 2,
                              remote_iov, 2, 0);
    int write_errno = errno;
    char go = 'x';
    if (written < 0 && write_errno == ENOSYS) {
        go = 's';
        if (write(go_pipe[1], &go, 1) != 1) return 18;
        close(go_pipe[1]);
        int status = 0;
        if (waitpid(child, &status, 0) != child) return 19;
        return WIFEXITED(status) && WEXITSTATUS(status) == 77 ? 77 : 21;
    }
    if (written != (ssize_t)sizeof(code)) go = 's';
    if (write(go_pipe[1], &go, 1) != 1) return 18;
    close(go_pipe[1]);
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 19;
    if (written != (ssize_t)sizeof(code)) return 20;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 21;
}
'''


NEGATIVE_SOURCE = r'''
#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>
int main(void) {
    unsigned char code[] = {0xb8, 43, 0, 0, 0, 0xc3, 0};
    void *memory = mmap(NULL, sizeof(code), PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return 10;
    memcpy(memory, code, sizeof(code));
    if (mprotect(memory, sizeof(code), PROT_READ | PROT_EXEC) != 0) return 11;
    return ((int (*)(void))memory)() == 43 ? 0 : 12;
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
        raise SystemExit("usage: test_runtime_process_vm_writev.py AUTO_REFIRST")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-process-vm-") as td:
        root = Path(td)
        positive = build_and_run(cc, root / "positive", POSITIVE_SOURCE,
                                 sys.argv[1], root / "positive-artifacts")
        if positive["runtime"].get("exit_code") == 77:
            print("[SKIP] process_vm_writev unavailable in this Linux environment")
            return 0
        events = positive["runtime"]["timeline"]
        writes = [
            event for event in events
            if event.get("kind") == "memory_write"
            and event.get("fields", {}).get("source") == "process_vm_writev"
        ]
        assert len(writes) == 1, writes
        fields = writes[0]["fields"]
        assert fields.get("scope") == "root_process", fields
        assert int(fields.get("target_pid", "0")) > 0, fields
        assert fields.get("local_iov_count") == "2", fields
        assert fields.get("remote_iov_count") == "2", fields
        assert fields.get("local_iov_entries_parsed") == "2", fields
        assert fields.get("remote_iov_entries_parsed") == "2", fields
        assert fields.get("written_bytes") == "7", fields
        assert fields.get("local_iov_parse_state") == "COMPLETE", fields
        assert fields.get("remote_iov_parse_state") == "COMPLETE", fields
        assert fields.get("iov_parse_complete") == "true", fields
        assert fields.get("remote_ranges", "").startswith("0x"), fields
        assert fields.get("remote_iov_range_overflow_entries") == "0", fields
        assert fields.get("local_iov_zero_length_entries") == "1", fields
        assert fields.get("remote_iov_zero_length_entries") == "1", fields
        assert fields.get("root_replacement_eligible") is None, fields

        negative = build_and_run(cc, root / "negative", NEGATIVE_SOURCE,
                                 sys.argv[1], root / "negative-artifacts")
        negative_events = negative["runtime"]["timeline"]
        assert not [
            event for event in negative_events
            if event.get("kind") == "memory_write"
            and event.get("fields", {}).get("source") == "process_vm_writev"
        ], negative_events
    print("[PASS] process_vm_writev bounded cross-process provenance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
