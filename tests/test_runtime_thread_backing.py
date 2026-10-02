#!/usr/bin/env python3
"""Regression for runtime-created memfd executable mappings in a pthread worker."""
from __future__ import annotations
import json, pathlib, shutil, subprocess, sys, tempfile, os

SOURCE = r'''
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
static void *worker(void *arg) {
    (void)arg;
    int fd = (int)syscall(SYS_memfd_create, "worker-payload", 0);
    if (fd < 0 || ftruncate(fd, 7) != 0) return (void*)1;
    unsigned char *rw = mmap(NULL, 7, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) return (void*)2;
    /* mov eax, 42; ret */
    const unsigned char code[] = {0xb8, 42, 0, 0, 0, 0xc3};
    memcpy(rw, code, sizeof(code));
    munmap(rw, 7);
    void *rx = mmap(NULL, 7, PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
    if (rx == MAP_FAILED) return (void*)3;
    close(fd);
    int (*entry)(void) = (int (*)(void))rx;
    int value = entry();
    munmap(rx, 7);
    return value == 42 ? 0 : (void*)4;
}
int main(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) return 10;
    void *result = NULL;
    if (pthread_join(t, &result) != 0) return 11;
    return result == NULL ? 0 : (int)(uintptr_t)result;
}
'''

def main() -> int:
    if os.name == "nt":
        print("[SKIP] Linux runtime backend"); return 0
    if len(sys.argv) != 2: raise SystemExit("usage: test_runtime_thread_backing.py AUTO_REFIRST")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc: print("[SKIP] no C compiler"); return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-thread-") as td:
        root = pathlib.Path(td); src = root / "worker.c"; fixture = root / "worker"
        src.write_text(SOURCE)
        cp = subprocess.run([cc, "-O2", "-pthread", str(src), "-o", str(fixture)], capture_output=True, text=True)
        if cp.returncode: raise AssertionError(cp.stderr)
        cp = subprocess.run([sys.argv[1], str(fixture), "--run", "--timeout=3000", f"--artifact-root={root/'artifacts'}", "--json"], capture_output=True, text=True, timeout=30)
        if cp.returncode: raise AssertionError(cp.stderr)
        report = json.loads(cp.stdout)
        events = report["runtime"]["timeline"]
        maps = [e for e in events if e.get("kind") == "memory_allocate" and e.get("fields", {}).get("backing_kind") == "runtime_memfd" and e.get("fields", {}).get("scope") == "root_thread"]
        assert maps, events
        assert any(e.get("kind") == "materialized_execute" and e.get("fields", {}).get("backing_kind") == "memfd" for e in events), events
        artifacts = [a for a in report["runtime"]["artifacts"] if a.get("kind") == "materialized_region" and a.get("fields", {}).get("backing_kind") == "memfd"]
        assert artifacts, report["runtime"]["artifacts"]
    print("[PASS] pthread worker memfd executable mmap tracking")
    return 0
if __name__ == "__main__": raise SystemExit(main())
