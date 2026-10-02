#!/usr/bin/env python3
"""Regression for ELF DT_FILTER/DT_AUXILIARY loader indirection metadata."""

from __future__ import annotations

import json
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile


def main() -> int:
    if shutil.which("gcc") is None:
        print("[SKIP] gcc is unavailable")
        return 0
    binary = pathlib.Path(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="ar-elf-loader-indirection-") as raw:
        root = pathlib.Path(raw)
        source = root / "filter.c"
        source.write_text("int marker(void) { return 7; }\n", encoding="utf-8")
        target = root / "libfiltertarget.so"
        subprocess.run(
            ["gcc", "-shared", "-fPIC", str(source), "-Wl,-soname,libfiltertarget.so", "-o", str(target)],
            check=True,
        )
        wrapper = root / "libwrapper.so"
        subprocess.run(
            ["gcc", "-shared", "-fPIC", str(source), "-Wl,-F,libfiltertarget.so", "-o", str(wrapper)],
            check=True,
        )
        out = subprocess.run([str(binary), str(wrapper), "--json"], check=True, text=True, capture_output=True)
        report = json.loads(out.stdout)
        indirection = report["elf_loader_indirection"]
        assert [x["name"] for x in indirection["filters"]] == ["libfiltertarget.so"], indirection
        assert indirection["filters"][0]["file_offset"] > 0, indirection
        auxiliary = root / "libauxwrapper.so"
        subprocess.run(
            ["gcc", "-shared", "-fPIC", str(source), "-Wl,-f,libauxiliary.so", "-o", str(auxiliary)],
            check=True,
        )
        out = subprocess.run([str(binary), str(auxiliary), "--json"], check=True, text=True, capture_output=True)
        aux_report = json.loads(out.stdout)
        aux_indirection = aux_report["elf_loader_indirection"]
        assert not aux_indirection["filters"], aux_indirection
        assert [x["name"] for x in aux_indirection["auxiliary"]] == ["libauxiliary.so"], aux_indirection
        assert aux_indirection["auxiliary"][0]["file_offset"] > 0, aux_indirection
        malformed = bytearray(wrapper.read_bytes())
        phoff, phentsize, phnum = struct.unpack_from("<QHH", malformed, 32)[0], struct.unpack_from("<H", malformed, 54)[0], struct.unpack_from("<H", malformed, 56)[0]
        dynamic = None
        for index in range(phnum):
            entry = phoff + index * phentsize
            p_type = struct.unpack_from("<I", malformed, entry)[0]
            p_offset = struct.unpack_from("<Q", malformed, entry + 8)[0]
            p_filesz = struct.unpack_from("<Q", malformed, entry + 32)[0]
            if p_type == 2:
                dynamic = (p_offset, p_filesz)
                break
        assert dynamic is not None
        dyn_off, dyn_size = dynamic
        for entry in range(dyn_off, dyn_off + dyn_size, 16):
            tag = struct.unpack_from("<q", malformed, entry)[0]
            if tag == 0x7FFFFFFF:
                struct.pack_into("<Q", malformed, entry + 8, 0xFFFFFFFFFFFFFFFF)
                break
        else:
            raise AssertionError("generated fixture has no DT_FILTER")
        bad = root / "malformed-filter.so"
        bad.write_bytes(malformed)
        out = subprocess.run([str(binary), str(bad), "--json"], check=True, text=True, capture_output=True)
        bad_report = json.loads(out.stdout)
        assert bad_report["elf_loader_indirection"]["filters"] == [], bad_report["elf_loader_indirection"]
    print("[PASS] ELF DT_FILTER loader indirection is retained with exact string offset")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
