#!/usr/bin/env python3
"""Linux runtime regression for a late dlopen of an existing ELF shared object."""
from __future__ import annotations
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

MAIN = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *h = dlopen(PAYLOAD_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!h) return 11;
    int (*f)(void) = (int (*)(void))dlsym(h, "payload_value");
    if (!f || f() != 7) return 12;
    puts("loaded");
    dlclose(h);
    return 0;
}
'''
LIB = r'''
__attribute__((visibility("default"))) int payload_value(void) { return 7; }
'''


def main() -> int:
    if os.name == "nt":
        print("[SKIP] Linux runtime backend")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_runtime_dynamic_loader.py AUTO_REFIRST")
    binary = pathlib.Path(sys.argv[1]).resolve()
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="ar-runtime-dlopen-") as td:
        root = pathlib.Path(td)
        source = root / "loader.c"
        lib_source = root / "payload.c"
        fixture = root / "loader"
        lib = root / "payload.so"
        source.write_text(MAIN.replace("PAYLOAD_PATH", "\"" + str(lib) + "\""), encoding="utf-8")
        lib_source.write_text(LIB, encoding="utf-8")
        cp = subprocess.run([cc, "-O2", "-Wall", "-Wextra", str(lib_source), "-fPIC", "-shared", "-o", str(lib)], capture_output=True, text=True)
        if cp.returncode:
            raise AssertionError(cp.stderr)
        cp = subprocess.run([cc, "-O2", "-Wall", "-Wextra", str(source), "-ldl", "-o", str(fixture)], capture_output=True, text=True)
        if cp.returncode:
            raise AssertionError(cp.stderr)
        artifacts = root / "artifacts"
        cp = subprocess.run([str(binary), str(fixture), "--run", "--timeout=3000", f"--artifact-root={artifacts}", "--json"], capture_output=True, text=True, timeout=30)
        if cp.returncode:
            raise AssertionError(cp.stderr or cp.stdout[-1000:])
        report = json.loads(cp.stdout)
        loads = [e for e in report["runtime"]["timeline"] if e.get("kind") == "module_load" and e.get("fields", {}).get("source") == "runtime_dynamic_loader"]
        payload_loads = [e for e in loads if e.get("fields", {}).get("module_path") == str(lib)]
        assert len(payload_loads) == 1, loads
        assert len(loads) == 1, loads
        assert all(e.get("fields", {}).get("initial_image") == "false" for e in loads), loads
        hit = payload_loads[0]
        fields = hit["fields"]
        assert fields.get("initial_image") == "false", hit
        assert fields.get("address", "").startswith("0x"), hit
        assert int(fields.get("size", "0")) > 0, hit
        assert int(fields.get("module_inode", "0")) > 0, hit
        assert report["runtime"]["stdout"].find("loaded") >= 0
    print("[PASS] late dlopen executable mapping is retained as ModuleLoad with identity/range")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
