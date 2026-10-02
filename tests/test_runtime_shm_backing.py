#!/usr/bin/env python3
"""Regression for runtime-created POSIX shared-memory executable payloads."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SOURCE = r'''
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    const char *name = "SHM_NAME_PLACEHOLDER";
    const int remove_first = REMOVE_FIRST_PLACEHOLDER;
    if (remove_first) shm_unlink(name);
    int fd = shm_open(name, O_CREAT|O_RDWR|O_CLOEXEC, 0700);
    if (fd < 0 || ftruncate(fd, 7) != 0) return 11;
    unsigned char code[] = {0xb8, 43, 0, 0, 0, 0xc3};
    unsigned char *rw = mmap(NULL, 7, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) return 12;
    memcpy(rw, code, sizeof(code));
    munmap(rw, 7);
    void *rx = mmap(NULL, 7, PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
    if (rx == MAP_FAILED) return 13;
    close(fd);
    int (*entry)(void) = (int (*)(void))rx;
    int value = entry();
    munmap(rx, 7);
    printf("shm=%d\n", value);
    return value == 43 ? 0 : 14;
}
'''


def run(binary: str, fixture: Path, root: Path, label: str) -> dict:
    parent = root / (label + "-run")
    artifact_root = parent / "artifacts"
    cp = subprocess.run(
        [binary, str(fixture), "--run", "--timeout=3000",
         f"--artifact-root={artifact_root}", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    if cp.returncode:
        raise AssertionError(cp.stderr or cp.stdout)
    return json.loads(cp.stdout)


def main() -> int:
    if sys.platform != "linux":
        print("[SKIP] POSIX shared-memory runtime backend")
        return 0
    if not Path("/dev/shm").is_dir():
        print("[SKIP] /dev/shm unavailable")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_runtime_shm_backing.py AUTO_REFIRST")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-shm-") as td:
        root = Path(td)
        name = "/auto-refirst-regression-shm-" + str(os.getpid())
        shm_path = Path("/dev/shm") / name[1:]
        try:
            src = root / "positive.c"
            fixture = root / "positive"
            src.write_text(SOURCE.replace("SHM_NAME_PLACEHOLDER", name)
                           .replace("REMOVE_FIRST_PLACEHOLDER", "1"))
            cp = subprocess.run([cc, "-O2", str(src), "-o", str(fixture), "-lrt"],
                                capture_output=True, text=True)
            if cp.returncode:
                raise AssertionError(cp.stderr)
            positive = run(sys.argv[1], fixture, root, "positive")
            events = positive["runtime"]["timeline"]
            assert any(e["kind"] == "file_create" and
                       e.get("fields", {}).get("backing_kind") == "runtime_shm"
                       for e in events), events
            assert any(e["kind"] == "materialized_execute" and
                       e.get("fields", {}).get("backing_kind") == "shm" and
                       e.get("fields", {}).get("image_relation") == "runtime_created_shm"
                       for e in events), events
            assert any(a["kind"] == "materialized_region" and
                       a.get("fields", {}).get("backing_kind") == "shm"
                       for a in positive["runtime"]["artifacts"]), positive["runtime"]["artifacts"]

            shm_path.write_bytes(b"\0" * 7)
            src = root / "negative.c"
            fixture = root / "negative"
            src.write_text(SOURCE.replace("SHM_NAME_PLACEHOLDER", name)
                           .replace("REMOVE_FIRST_PLACEHOLDER", "0"))
            cp = subprocess.run([cc, "-O2", str(src), "-o", str(fixture), "-lrt"],
                                capture_output=True, text=True)
            if cp.returncode:
                raise AssertionError(cp.stderr)
            negative = run(sys.argv[1], fixture, root, "negative")
            nevents = negative["runtime"]["timeline"]
            assert not any(e.get("fields", {}).get("backing_kind") == "runtime_shm"
                           for e in nevents), nevents
            assert not any(e["kind"] == "materialized_execute" for e in nevents), nevents
        finally:
            shm_path.unlink(missing_ok=True)
    print("[PASS] runtime-created POSIX shm payload is materialized; pre-existing shm is quiet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
