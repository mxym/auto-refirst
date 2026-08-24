#!/usr/bin/env python3
"""Small source-generated .NET bundle/NativeAOT parser boundary suite.

The byte builders are an independent format oracle: they never call the product
parser to construct or repair a sample.  These synthetic samples cover bounded
parser behavior only and do not replace evidence from official .NET artifacts.
No generated sample is executed.
"""

import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


BUNDLE_SIGNATURE = bytes.fromhex(
    "8b1202b96a612038727b930214d7a032"
    "13f5b9e6efae3318ee3b2dce24b36aae"
)
GENERATED_LIMIT = 10 * 1024 * 1024
SANITIZER_MARKERS = (
    "addresssanitizer",
    "leaksanitizer",
    "undefinedbehaviorsanitizer",
    "runtime error:",
)


def p16(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buf, offset, value)


def p32(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value)


def p64(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buf, offset, value)


def minimal_pe() -> bytearray:
    """Repository-public minimal PE layout, with no executable test behavior."""
    buf = bytearray(0x400)
    buf[:2] = b"MZ"
    p32(buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    p16(buf, 0x84, 0x14C)
    p16(buf, 0x86, 1)
    p16(buf, 0x94, 224)
    p16(buf, 0x96, 0x0102)
    opt = 0x98
    p16(buf, opt, 0x10B)
    p32(buf, opt + 4, 0x200)
    p32(buf, opt + 16, 0x1000)
    p32(buf, opt + 20, 0x1000)
    p32(buf, opt + 24, 0x2000)
    p32(buf, opt + 28, 0x400000)
    p32(buf, opt + 32, 0x1000)
    p32(buf, opt + 36, 0x200)
    p16(buf, opt + 40, 6)
    p16(buf, opt + 48, 6)
    p32(buf, opt + 56, 0x2000)
    p32(buf, opt + 60, 0x200)
    p16(buf, opt + 68, 3)
    p32(buf, opt + 72, 0x100000)
    p32(buf, opt + 76, 0x1000)
    p32(buf, opt + 80, 0x100000)
    p32(buf, opt + 84, 0x1000)
    p32(buf, opt + 92, 16)
    section = opt + 224
    buf[section:section + 8] = b".text\0\0\0"
    p32(buf, section + 8, 0x100)
    p32(buf, section + 12, 0x1000)
    p32(buf, section + 16, 0x200)
    p32(buf, section + 20, 0x200)
    p32(buf, section + 36, 0x60000020)
    return buf


def encoded_path(raw: bytes) -> bytes:
    assert 0 < len(raw) < 0x80
    return bytes([len(raw)]) + raw


def make_bundle(major: int) -> tuple[bytes, dict]:
    assert major in (2, 6)
    buf = minimal_pe()
    locator = 0x240
    signature = locator + 8
    header = 0x3C0
    p64(buf, locator, header)
    buf[signature:signature + len(BUNDLE_SIGNATURE)] = BUNDLE_SIGNATURE

    specs = [
        (b"A.dll", 1, b"tiny-managed"),
        (b"B.bin", 2, b"tiny-native"),
        (b"app.deps.json", 3, b'{"deps":{}}'),
        (b"app.runtimeconfig.json", 4, b'{"runtimeOptions":{}}'),
    ]
    cursor = signature + len(BUNDLE_SIGNATURE) + 0x18
    entries = []
    for path, kind, payload in specs:
        offset = cursor
        buf[offset:offset + len(payload)] = payload
        cursor += len(payload) + 3
        entries.append(
            {"path": path, "type": kind, "offset": offset, "size": len(payload)}
        )
    assert cursor < header

    deps = next(entry for entry in entries if entry["type"] == 3)
    config = next(entry for entry in entries if entry["type"] == 4)
    manifest = bytearray(struct.pack("<III", major, 0, len(entries)))
    manifest += encoded_path(b"tinyBundle01")
    deps_cache_field = header + len(manifest)
    manifest += struct.pack(
        "<QQQQQ",
        deps["offset"],
        deps["size"],
        config["offset"],
        config["size"],
        0,
    )
    entry_meta = []
    for entry in entries:
        fixed = header + len(manifest)
        manifest += struct.pack("<QQ", entry["offset"], entry["size"])
        compressed_field = None
        if major >= 6:
            compressed_field = header + len(manifest)
            manifest += struct.pack("<Q", 0)
        type_field = header + len(manifest)
        manifest += bytes([entry["type"]])
        path_prefix = header + len(manifest)
        manifest += encoded_path(entry["path"])
        entry_meta.append(
            {
                **entry,
                "fixed": fixed,
                "compressed_field": compressed_field,
                "type_field": type_field,
                "path_prefix": path_prefix,
                "path_start": path_prefix + 1,
            }
        )
    if len(buf) < header:
        buf.extend(bytes(header - len(buf)))
    buf[header:header + len(manifest)] = manifest
    end = header + len(manifest)
    return bytes(buf[:end]), {
        "locator": locator,
        "signature": signature,
        "header": header,
        "count_field": header + 8,
        "deps_cache_field": deps_cache_field,
        "entries": entry_meta,
        "end": end,
    }


def make_native_aot_elf() -> tuple[bytes, dict]:
    """Build a tiny ELF64 image with a file-backed NativeAOT R2R table."""
    base = 0x400000
    modules_offset = 0x180
    rtr_offset = 0x200
    managed_offset = 0x300
    eh_offset = 0x320
    strings_offset = 0x400
    sections_offset = 0x500
    file_size = 0x700
    buf = bytearray(file_size)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        buf,
        0,
        ident,
        2,
        62,
        1,
        base + managed_offset,
        64,
        sections_offset,
        0,
        64,
        56,
        1,
        64,
        6,
        5,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        buf,
        64,
        1,
        5,
        0,
        base,
        base,
        file_size,
        0x1000,
        0x1000,
    )

    p64(buf, modules_offset, base + rtr_offset)
    struct.pack_into("<IHHIHBB", buf, rtr_offset, 0x00525452, 16, 0, 0, 4, 24, 1)
    rows = [
        (204, 1, base + managed_offset, base + managed_offset + 8),
        (205, 0, base + managed_offset + 8, 0),
        (300, 1, base + eh_offset, base + eh_offset + 8),
        (201, 1, base + eh_offset + 8, base + eh_offset + 0x10),
    ]
    row_offsets = []
    for index, row in enumerate(rows):
        offset = rtr_offset + 16 + index * 24
        row_offsets.append(offset)
        struct.pack_into("<IIQQ", buf, offset, *row)
    buf[managed_offset:managed_offset + 0x10] = b"\x90" * 0x10
    buf[eh_offset:eh_offset + 0x10] = bytes(range(0x10))

    names = (
        b"\0__modules\0__managedcode\0.dotnet_eh_table\0"
        b".hydrated\0.shstrtab\0"
    )
    buf[strings_offset:strings_offset + len(names)] = names

    def name_offset(name: bytes) -> int:
        offset = names.find(name)
        assert offset > 0
        return offset

    section_specs = [
        (b"__modules", 1, 2, base + modules_offset, modules_offset, 8, 8),
        (b"__managedcode", 1, 6, base + managed_offset, managed_offset, 0x10, 16),
        (b".dotnet_eh_table", 1, 2, base + eh_offset, eh_offset, 0x10, 8),
        (b".hydrated", 8, 2, base + 0x800, 0x380, 0x20, 8),
        (b".shstrtab", 3, 0, 0, strings_offset, len(names), 1),
    ]
    section_headers = {}
    for index, spec in enumerate(section_specs, start=1):
        name, kind, flags, address, offset, size, align = spec
        section_header = sections_offset + index * 64
        section_headers[name.decode()] = section_header
        struct.pack_into(
            "<IIQQQQIIQQ",
            buf,
            section_header,
            name_offset(name),
            kind,
            flags,
            address,
            offset,
            size,
            0,
            0,
            align,
            0,
        )
    return bytes(buf), {
        "base": base,
        "modules_offset": modules_offset,
        "rtr_offset": rtr_offset,
        "count_field": rtr_offset + 12,
        "rows": row_offsets,
        "section_headers": section_headers,
        "file_size": file_size,
    }


class Runner:
    def __init__(self, cli: Path, root: Path):
        self.cli = cli
        self.root = root
        self.generated_bytes = 0
        self.cases = 0

    def run(self, name: str, data: bytes) -> dict:
        self.generated_bytes += len(data)
        assert self.generated_bytes < GENERATED_LIMIT, self.generated_bytes
        self.cases += 1
        path = self.root / name
        path.write_bytes(data)
        sidecar = Path(str(path) + ".auto-refirst")
        try:
            completed = subprocess.run(
                [str(self.cli), str(path), "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            lowered = completed.stderr.lower()
            diagnostics = [marker for marker in SANITIZER_MARKERS if marker in lowered]
            assert not diagnostics, (name, diagnostics, completed.stderr[-4000:])
            assert completed.returncode == 0, (
                name,
                completed.returncode,
                completed.stdout[-2000:],
                completed.stderr[-4000:],
            )
            return json.loads(completed.stdout)
        finally:
            path.unlink(missing_ok=True)
            if sidecar.is_symlink():
                sidecar.unlink()
            elif sidecar.exists():
                shutil.rmtree(sidecar)


def changed(source: bytes, mutator) -> bytes:
    result = bytearray(source)
    mutator(result)
    return bytes(result)


def assert_bundle_failure(report: dict, label: str, message: str) -> None:
    bundle = report["dotnet_bundle"]
    assert bundle["candidate"], (label, bundle)
    assert not bundle["valid"] and bundle["state"] == "FAILED", (label, bundle)
    assert message in bundle["error"], (label, bundle["error"])


def assert_native_failure(report: dict, label: str, message: str) -> None:
    native = report["native_aot"]
    assert native["candidate"], (label, native)
    assert not native["valid"] and native["state"] == "FAILED", (label, native)
    assert message in native["error"], (label, native["error"])


def run_suite(runner: Runner) -> None:
    v2, v2_meta = make_bundle(2)
    v6, v6_meta = make_bundle(6)
    native, native_meta = make_native_aot_elf()

    for label, sample, version in (
        ("bundle-v2.exe", v2, "2.0"),
        ("bundle-v6.exe", v6, "6.0"),
    ):
        bundle = runner.run(label, sample)["dotnet_bundle"]
        assert bundle["valid"] and bundle["state"] == "CONFIRMED", (label, bundle)
        assert bundle["version"] == version and bundle["file_count"] == 4, bundle
        assert bundle["compressed_file_count"] == 0, bundle

    native_result = runner.run("native-aot.elf", native)["native_aot"]
    assert native_result["valid"] and native_result["state"] == "CONFIRMED", native_result
    assert native_result["platform"] == "ELF", native_result
    assert native_result["section_count"] == 4, native_result

    short_header = v6[:v6_meta["header"] + 10]
    assert_bundle_failure(
        runner.run("bundle-short-header.exe", short_header),
        "short header",
        "truncated",
    )
    assert_bundle_failure(
        runner.run("bundle-duplicate-locator.exe", v6 + BUNDLE_SIGNATURE),
        "duplicate locator",
        "not unique",
    )
    assert_bundle_failure(
        runner.run(
            "bundle-large-count.exe",
            changed(v6, lambda data: p32(data, v6_meta["count_field"], 4097)),
        ),
        "large count",
        "entry count",
    )

    first = v6_meta["entries"][0]
    second = v6_meta["entries"][1]

    def unsafe_parent(data: bytearray) -> None:
        data[first["path_start"]:first["path_start"] + 5] = b"../x."

    assert_bundle_failure(
        runner.run("bundle-path-parent.exe", changed(v6, unsafe_parent)),
        "path normalization",
        "normalized relative UTF-8",
    )

    def duplicate_path(data: bytearray) -> None:
        assert len(first["path"]) == len(second["path"])
        start = second["path_start"]
        data[start:start + len(second["path"])] = first["path"]

    assert_bundle_failure(
        runner.run("bundle-path-duplicate.exe", changed(v6, duplicate_path)),
        "duplicate path",
        "duplicate normalized path",
    )
    assert_bundle_failure(
        runner.run(
            "bundle-span-overlap.exe",
            changed(v6, lambda data: p64(data, second["fixed"], first["offset"] + 1)),
        ),
        "overlapping spans",
        "spans overlap",
    )
    assert_bundle_failure(
        runner.run(
            "bundle-compressed-size-relation.exe",
            changed(
                v6,
                lambda data: p64(data, first["compressed_field"], first["size"]),
            ),
        ),
        "compressed length relation",
        "invalid size geometry",
    )
    assert_bundle_failure(
        runner.run(
            "bundle-cache-table-mismatch.exe",
            changed(
                v2,
                lambda data: p64(
                    data,
                    v2_meta["deps_cache_field"],
                    v2_meta["entries"][2]["offset"] + 1,
                ),
            ),
        ),
        "cached/table mapping mismatch",
        "cached JSON locations",
    )

    assert_native_failure(
        runner.run(
            "native-large-count.elf",
            changed(native, lambda data: p16(data, native_meta["count_field"], 4097)),
        ),
        "large native table count",
        "unique bounded legal",
    )
    assert_native_failure(
        runner.run(
            "native-duplicate-id.elf",
            changed(
                native,
                lambda data: p32(data, native_meta["rows"][1], 204),
            ),
        ),
        "duplicate section ID",
        "duplicate section IDs",
    )

    modules_header = native_meta["section_headers"]["__modules"]
    assert_native_failure(
        runner.run(
            "native-modules-file-map-mismatch.elf",
            changed(native, lambda data: p64(data, modules_header + 24, 0x188)),
        ),
        "section/file mapping mismatch",
        "does not map to file-backed ELF data",
    )
    assert_native_failure(
        runner.run(
            "native-table-memory-map-mismatch.elf",
            changed(
                native,
                lambda data: p64(
                    data,
                    native_meta["rows"][0] + 8,
                    native_meta["base"] + 0x1000,
                ),
            ),
        ),
        "table/load mapping mismatch",
        "start pointer is outside ELF load memory",
    )

    eh_header = native_meta["section_headers"][".dotnet_eh_table"]
    assert_native_failure(
        runner.run(
            "native-section-evidence-mismatch.elf",
            changed(native, lambda data: p64(data, eh_header + 8, 0)),
        ),
        "section/table evidence mismatch",
        "lacks the required",
    )
    assert_native_failure(
        runner.run(
            "native-end-before-start.elf",
            changed(
                native,
                lambda data: p64(
                    data,
                    native_meta["rows"][0] + 16,
                    native_meta["base"] + 0x2FF,
                ),
            ),
        ),
        "native length relation",
        "end pointer is outside ELF load memory",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run small source-generated .NET parser boundaries without executing samples."
    )
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument(
        "--tmp-root",
        type=Path,
        default=Path(tempfile.gettempdir()),
        help="existing parent for the auto-cleaned per-run directory",
    )
    args = parser.parse_args()
    cli = args.cli.resolve(strict=True)
    temp_root = args.tmp_root.resolve(strict=True)
    assert cli.is_file(), cli
    assert temp_root.is_dir(), temp_root

    work_path = None
    with tempfile.TemporaryDirectory(prefix="dotnet-native-small-", dir=temp_root) as raw:
        work_path = Path(raw)
        runner = Runner(cli, work_path)
        run_suite(runner)
        generated_bytes = runner.generated_bytes
        cases = runner.cases
    assert work_path is not None and not work_path.exists(), work_path
    print(
        "dotnet native small synthetic tests: PASS "
        f"({cases} cases, {generated_bytes} generated bytes, temp cleaned)"
    )
    print(
        "boundary: synthetic parser checks only; not a substitute for official .NET evidence; "
        "generated samples were not executed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
