#!/usr/bin/env python3
"""Linux integration check for runtime-created released-file ELF reingest.

The fixture writes /bin/true to a fresh O_CREAT|O_EXCL file, closes the
writable descriptor, then executes a read-only alias with execveat.  The
runtime backend must correlate the device/inode, persist the ELF snapshot and
feed it back to the static child analyzer without replacing or executing the
child artifact a second time.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


SOURCE = r'''
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
int main(void) {
    char path[256];
    snprintf(path, sizeof path, "/tmp/auto-refirst-runtime-%ld", (long)getpid());
    int out = open(path, O_CREAT | O_EXCL | O_RDWR, 0700);
    if (out < 0) return 10;
    int src = open("/bin/true", O_RDONLY);
    if (src < 0) return 11;
    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof buf)) > 0) {
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(out, p, (size_t)n);
            if (w <= 0) return 12;
            p += w;
            n -= w;
        }
    }
    close(src);
    close(out);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 13;
    unlink(path);
    char *const argv[] = {"released-true", NULL};
    char *const envp[] = {"PATH=/usr/bin:/bin", NULL};
    syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
    return errno ? errno : 14;
}
'''


def main() -> int:
    if os.name == "nt":
        print("[SKIP] Linux runtime backend")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_runtime_reingest.py AUTO_REFIRST")
    binary = pathlib.Path(sys.argv[1]).resolve()
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-reingest-") as td:
        root = pathlib.Path(td)
        fixture = root / "released_exec"
        source = root / "released_exec.c"
        source.write_text(SOURCE, encoding="utf-8")
        cp = subprocess.run([cc, "-O2", "-Wall", str(source), "-o", str(fixture)], capture_output=True, text=True)
        if cp.returncode:
            raise AssertionError(cp.stderr)
        artifact_root = root / "artifacts"
        cp = subprocess.run(
            [str(binary), str(fixture), "--run", "--timeout=3000",
             f"--artifact-root={artifact_root}", "--json"],
            capture_output=True, text=True, timeout=30,
        )
        if cp.returncode:
            raise AssertionError(cp.stderr)
        report = json.loads(cp.stdout)
        candidates = []
        for artifact in report["runtime"]["artifacts"]:
            fields = artifact.get("fields", {})
            if artifact.get("kind") == "runtime_backing_elf" and fields.get("backing_kind") == "released_file":
                candidates.append((artifact, fields))
        assert len(candidates) == 1, report["runtime"]["artifacts"]
        artifact, fields = candidates[0]
        assert artifact["state"] == "RUNTIME_BACKING_EXEC_HANDOFF_STANDALONE_VALIDATED"
        assert fields["runtime_candidate_format"] == "ELF"
        assert fields["runtime_reingest_state"] == "ELIGIBLE_VALIDATED_IMAGE"
        assert fields["static_child_analysis"] == "COMPLETED"
        assert fields["static_child_format"] == "ELF"
        assert pathlib.Path(fields["static_child_report"]).is_file()
        assert not report["replacement"]["performed"]
    print("[PASS] released-file ELF runtime reingest and static child handoff")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
