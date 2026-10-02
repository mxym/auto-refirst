#!/usr/bin/env python3
"""Regression for vectorized writes into a runtime-created executable memfd."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SOURCE = r'''
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main(void) {
    int fd = (int)syscall(SYS_memfd_create, "writev-payload", 0);
    if (fd < 0 || ftruncate(fd, 7) != 0) return 11;
    unsigned char a[] = {0xb8, 43, 0};
    unsigned char b[] = {0, 0, 0, 0xc3};
    struct iovec v[2] = {{a, sizeof(a)}, {b, sizeof(b)}};
    if (writev(fd, v, 2) != 7) return 12;
    void *rx = mmap(NULL, 7, PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
    if (rx == MAP_FAILED) return 13;
    close(fd);
    int value = ((int (*)(void))rx)();
    munmap(rx, 7);
    return value == 43 ? 0 : 14;
}
'''


def main() -> int:
    if sys.platform != "linux":
        print("[SKIP] Linux runtime backend")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_runtime_writev_backing.py AUTO_REFIRST")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-writev-") as td:
        root = Path(td)
        src, fixture = root / "writev.c", root / "writev"
        src.write_text(SOURCE)
        cp = subprocess.run([cc, "-O2", str(src), "-o", str(fixture)],
                            capture_output=True, text=True)
        if cp.returncode:
            raise AssertionError(cp.stderr)
        artifacts = root / "run" / "artifacts"
        cp = subprocess.run(
            [sys.argv[1], str(fixture), "--run", "--timeout=3000",
             f"--artifact-root={artifacts}", "--json"],
            capture_output=True, text=True, timeout=30,
        )
        if cp.returncode:
            raise AssertionError(cp.stderr or cp.stdout)
        report = json.loads(cp.stdout)
        events = report["runtime"]["timeline"]
        writes = [e for e in events if e.get("kind") == "file_write"
                  and e.get("fields", {}).get("source") == "writev"]
        assert writes, events
        assert writes[0]["fields"].get("vectorized") == "true", writes
        assert writes[0]["fields"].get("iov_count") == "2", writes
        assert any(e.get("kind") == "materialized_execute"
                   and e.get("fields", {}).get("backing_kind") == "memfd"
                   for e in events), events
    print("[PASS] vectorized memfd writes retain runtime backing provenance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
