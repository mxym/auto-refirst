#!/usr/bin/env python3
"""Rebuild the project-owned public APK/JNI relation fixture."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from zipfile import ZIP_STORED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[2]
JAVA_SOURCE = ROOT / "tests/apk/JniRelationFixture.java"
C_SOURCE = ROOT / "tests/apk/jni_relation.c"


def run(argv: list[object], *, temp: Path) -> None:
    env = dict(os.environ, TMPDIR=str(temp), TMP=str(temp), TEMP=str(temp))
    completed = subprocess.run(
        [str(value) for value in argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed rc={completed.returncode}: {' '.join(map(str, argv))}\n"
            f"stdout:\n{completed.stdout[-4000:]}\nstderr:\n{completed.stderr[-4000:]}"
        )


def encoded_length(value: int) -> bytes:
    if not 0 <= value <= 0x7FFF:
        raise ValueError(value)
    return bytes([value]) if value <= 0x7F else bytes([0x80 | (value >> 8), value & 0xFF])


def binary_manifest() -> bytes:
    strings: list[str] = []

    def string_index(value: str) -> int:
        if value not in strings:
            strings.append(value)
        return strings.index(value)

    for value in ("manifest", "package", "application", "com.example.jnirelation"):
        string_index(value)

    def string_pool() -> bytearray:
        data = bytearray()
        offsets: list[int] = []
        for value in strings:
            offsets.append(len(data))
            raw = value.encode("utf-8")
            data += encoded_length(len(value.encode("utf-16le")) // 2)
            data += encoded_length(len(raw)) + raw + b"\0"
        start = 28 + 4 * len(offsets)
        result = bytearray(
            struct.pack("<HHI", 1, 28, 0)
            + struct.pack("<IIIII", len(offsets), 0, 0x100, start, 0)
        )
        result += b"".join(struct.pack("<I", offset) for offset in offsets) + data
        while len(result) % 4:
            result += b"\0"
        struct.pack_into("<I", result, 4, len(result))
        return result

    def start_element(tag: str, attributes: tuple[tuple[str, str], ...] = ()) -> bytes:
        encoded = bytearray()
        for name, value in attributes:
            encoded += struct.pack(
                "<IIIHBBI", 0xFFFFFFFF, string_index(name), string_index(value),
                8, 0, 3, string_index(value),
            )
        extension = struct.pack(
            "<IIHHHHHH", 0xFFFFFFFF, string_index(tag), 20, 20,
            len(attributes), 0, 0, 0,
        )
        size = 16 + len(extension) + len(encoded)
        return struct.pack("<HHIII", 0x102, 16, size, 1, 0xFFFFFFFF) + extension + encoded

    def end_element(tag: str) -> bytes:
        return struct.pack(
            "<HHIIIII", 0x103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, string_index(tag)
        )

    body = string_pool()
    body += start_element("manifest", (("package", "com.example.jnirelation"),))
    body += start_element("application")
    body += end_element("application") + end_element("manifest")
    return struct.pack("<HHI", 3, 8, 8 + len(body)) + body


def write_member(archive: ZipFile, name: str, data: bytes) -> None:
    info = ZipInfo(name)
    info.date_time = (1980, 1, 1, 0, 0, 0)
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r8", type=Path, required=True, help="R8 9.4.12 jar")
    parser.add_argument("--javac", default=shutil.which("javac") or "javac")
    parser.add_argument("--java", default=shutil.which("java") or "java")
    parser.add_argument("--cc", default=shutil.which("cc") or "cc")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for source in (JAVA_SOURCE, C_SOURCE, args.r8):
        if not source.is_file():
            parser.error(f"missing required input: {source}")

    javac = Path(args.javac).resolve(strict=True)
    java = Path(args.java).resolve(strict=True)
    cc = Path(args.cc).resolve(strict=True)
    jdk = javac.parents[1]
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="auto-refirst-apk-jni-") as raw:
        temp = Path(raw)
        classes = temp / "classes"
        dex_out = temp / "dex"
        classes.mkdir()
        dex_out.mkdir()
        run(
            [javac, "-g:none", "-source", "8", "-target", "8", "-Xlint:-options",
             "-d", classes, JAVA_SOURCE],
            temp=temp,
        )
        class_files = sorted(classes.rglob("JniRelationFixture*.class"))
        if not class_files:
            raise RuntimeError("javac produced no fixture class")
        run(
            [java, "-cp", args.r8, "com.android.tools.r8.D8", "--release",
             "--min-api", "21", "--output", dex_out, *class_files],
            temp=temp,
        )
        native = temp / "libjni_relation.so"
        run(
            [cc, "-shared", "-fPIC", "-O1", "-g0", "-funwind-tables",
             "-Wl,--eh-frame-hdr", "-Wl,--hash-style=both",
             "-Wl,-soname,libjni_relation.so", "-I", jdk / "include",
             "-I", jdk / "include/linux", C_SOURCE, "-o", native],
            temp=temp,
        )
        with ZipFile(output, "w", allowZip64=False) as archive:
            write_member(archive, "AndroidManifest.xml", binary_manifest())
            write_member(archive, "classes.dex", (dex_out / "classes.dex").read_bytes())
            write_member(archive, "lib/x86_64/libjni_relation.so", native.read_bytes())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
