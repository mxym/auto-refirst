#!/usr/bin/env python3
"""Regression for copy_file_range into a runtime-created executable memfd."""
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
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char path[] = "/tmp/auto-refirst-copy-range-XXXXXX";
    int src = mkstemp(path);
    if (src < 0) return 11;
    unsigned char code[] = {0xb8, 43, 0, 0, 0, 0xc3, 0};
    if (write(src, code, sizeof(code)) != (ssize_t)sizeof(code)) return 12;
    lseek(src, 0, SEEK_SET);
    char dst_path[] = "/tmp/auto-refirst-copy-dst-XXXXXX";
    int dst = mkstemp(dst_path);
    if (dst < 0 || ftruncate(dst, 7) != 0) return 13;
    off_t in = 0, out = 0;
    if (syscall(SYS_copy_file_range, src, &in, dst, &out, 7, 0) != 7) return 14;
    void *rx = mmap(NULL, 7, PROT_READ|PROT_EXEC, MAP_SHARED, dst, 0);
    if (rx == MAP_FAILED) return 15;
    close(src); close(dst); unlink(path); unlink(dst_path);
    int value = ((int (*)(void))rx)();
    munmap(rx, 7);
    return value == 43 ? 0 : 16;
}
'''

def main() -> int:
    if sys.platform != "linux":
        print("[SKIP] Linux runtime backend")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_runtime_copy_file_range.py AUTO_REFIRST")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-copy-range-") as td:
        root = Path(td); src = root / "copy.c"; fixture = root / "copy"
        src.write_text(SOURCE)
        cp = subprocess.run([cc, "-O2", str(src), "-o", str(fixture)], capture_output=True, text=True)
        if cp.returncode: raise AssertionError(cp.stderr)
        cp = subprocess.run([sys.argv[1], str(fixture), "--run", "--timeout=3000", f"--artifact-root={root/'run'/'artifacts'}", "--json"], capture_output=True, text=True, timeout=30)
        if cp.returncode: raise AssertionError(cp.stderr or cp.stdout)
        report = json.loads(cp.stdout); events = report["runtime"]["timeline"]
        writes = [e for e in events if e.get("kind") == "file_write" and e.get("fields", {}).get("source") == "copy_file_range"]
        assert writes, events
        assert writes[0]["fields"].get("source_fd") and writes[0]["fields"].get("copied_bytes_requested") == "7", writes
        assert any(e.get("kind") == "memory_allocate" and e.get("fields", {}).get("backing_kind") == "runtime_released_file" and e.get("fields", {}).get("requested_prot") == "0x5" for e in events), events
    print("[PASS] copy_file_range destination retains runtime backing provenance")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
