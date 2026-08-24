#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import os
import struct
import subprocess
import sys
import tempfile
import warnings
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
AUTO = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "auto-refirst"
SMOKE = "--smoke" in sys.argv[2:]
CORPUS = ROOT / "tests" / "corpus" / "hermes"
MAGIC = bytes.fromhex("c61fbc03c103191f")
PROBE_ENTRIES = 512
PROBE_BYTES = 64 * 1024 * 1024
DEX = (ROOT / "tests" / "corpus" / "android" / "LambdaSample.dex").read_bytes()
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _len8(value: int) -> bytes:
    return bytes([value]) if value <= 0x7F else bytes([0x80 | (value >> 8), value & 0xFF])


def build_axml() -> bytes:
    strings = ["android", ANDROID_NS, "manifest", "package", "com.example.hermes"]
    encoded = bytearray()
    offsets = []
    for value in strings:
        offsets.append(len(encoded))
        raw = value.encode("utf-8")
        encoded += _len8(len(value.encode("utf-16le")) // 2)
        encoded += _len8(len(raw)) + raw + b"\0"
    pool_header = 28
    pool = bytearray(
        struct.pack("<HHI", 1, pool_header, 0)
        + struct.pack("<IIIII", len(strings), 0, 0x100, pool_header + 4 * len(strings), 0)
    )
    pool += b"".join(struct.pack("<I", value) for value in offsets)
    pool += encoded
    while len(pool) % 4:
        pool += b"\0"
    struct.pack_into("<I", pool, 4, len(pool))

    namespace_start = struct.pack("<HHIIIII", 0x100, 16, 24, 1, 0xFFFFFFFF, 0, 1)
    attribute = struct.pack("<IIIHBBI", 0xFFFFFFFF, 3, 0xFFFFFFFF, 8, 0, 3, 4)
    extension = struct.pack("<IIHHHHHH", 0xFFFFFFFF, 2, 20, 20, 1, 0, 0, 0)
    start = struct.pack("<HHIII", 0x102, 16, 16 + len(extension) + len(attribute), 1, 0xFFFFFFFF)
    start += extension + attribute
    end = struct.pack("<HHIIIII", 0x103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, 2)
    namespace_end = struct.pack("<HHIIIII", 0x101, 16, 24, 1, 0xFFFFFFFF, 0, 1)
    body = bytes(pool) + namespace_start + start + end + namespace_end
    return struct.pack("<HHI", 3, 8, 8 + len(body)) + body


AXML = build_axml()


def run(path: Path, *args: str) -> dict:
    cp = subprocess.run(
        [str(AUTO), str(path), *args, "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode:
        raise AssertionError(
            f"auto-refirst rc={cp.returncode} for {path}: "
            f"{cp.stderr.decode(errors='replace')}"
        )
    try:
        report = json.loads(cp.stdout)
    except json.JSONDecodeError as exc:
        begin = max(0, exc.pos - 400)
        end = min(len(cp.stdout), exc.pos + 400)
        sample = cp.stdout[begin:end].decode(errors="replace")
        raise AssertionError(f"invalid JSON at byte {exc.pos}: {sample!r}") from exc
    assert isinstance(report, dict), "focused Hermes APK tests expect the root JSON object"
    return report


def make(path: Path, entries) -> None:
    with ZipFile(path, "w") as z:
        for name, data, method in entries:
            z.writestr(name, data, compress_type=method)


def route_finding(report: dict) -> dict:
    rows = [x for x in report["findings"] if x["family"] == "Hermes APK/ZIP child routing"]
    assert len(rows) == 1, [(x["family"], x["state"]) for x in report["findings"]]
    return rows[0]


def hermes_artifacts(report: dict):
    return [x for x in report["artifacts"] if x["kind"] == "hermes_bytecode"]


def hermes_relationships(report: dict):
    return [x for x in report["artifact_relationships"] if x["kind"] == "apk_hermes_bytecode_child"]


def child_report(report: dict, artifact: dict) -> dict:
    edges = [
        x for x in report["artifact_graph"]["edges"]
        if x["child"] == artifact["path"] and x["relation"] == "apk_hermes_bytecode_child"
    ]
    assert len(edges) == 1 and edges[0]["state"] == "ANALYZED_STATIC", edges
    root = Path(report["apk"]["extraction"]["output_dir"]).parents[1]
    child_path = root / "children" / edges[0]["sha256"] / "analysis.json"
    assert child_path.is_file(), child_path
    return json.loads(child_path.read_text(encoding="utf-8"))


def mutate_epoch(source: bytes, version: int) -> bytes:
    data = bytearray(source)
    struct.pack_into("<I", data, 8, version)
    data[-20:] = hashlib.sha1(data[:-20]).digest()
    return bytes(data)


def assert_exact_binding(report: dict, member_name: str, source: bytes) -> dict:
    entries = [x for x in report["apk"]["hermes_entries"] if x["name"] == member_name]
    assert len(entries) == 1
    entry = entries[0]
    digest = hashlib.sha256(source).hexdigest()
    assert entry["integrity_valid"] and entry["sha256"] == digest
    artifacts = [x for x in hermes_artifacts(report) if Path(x["path"]).as_posix().endswith(member_name)]
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["priority"] == "HIGH"
    assert artifact["relation"] == "apk_hermes_bytecode_child"
    assert artifact["sha256"] == digest and artifact["size"] == len(source)
    rels = [x for x in hermes_relationships(report) if x["second"] == artifact["path"]]
    assert len(rels) == 1
    rel = rels[0]
    assert rel["state"] == "CONFIRMED" and rel["directed"]
    source_coord = rel["source_coordinate"]
    for field in (
        f"zip_entry={entry['index']}",
        f"name={member_name}",
        f"central_directory_offset={entry['central_directory_offset']}",
        f"local_header_offset={entry['local_header_offset']}",
        f"data_offset={entry['data_offset']}",
        f"compressed_size={entry['compressed_size']}",
        f"uncompressed_size={len(source)}",
        f"crc32={entry['crc32']}",
    ):
        assert field in source_coord, (field, source_coord)
    assert f"size={len(source)}" in rel["target_coordinate"]
    assert f"sha256={digest}" in rel["target_coordinate"]
    assert "no JavaScript source recovery" in rel["provenance_scope"]
    assert "runtime loading" in rel["provenance_scope"]
    return artifact


def main() -> None:
    v89 = (CORPUS / "v89.hbc").read_bytes()
    v96 = (CORPUS / "v96.hbc").read_bytes()
    v98 = (CORPUS / "v98.hbc").read_bytes()
    assert all(x.startswith(MAGIC) for x in (v89, v96, v98))

    temp_root = os.environ.get("PRTS_TEST_TMPDIR")
    with tempfile.TemporaryDirectory(prefix="ar-hermes-apk-", dir=temp_root) as raw_temp:
        temp = Path(raw_temp)

        apk = temp / "standard.apk"
        make(
            apk,
            [
                ("AndroidManifest.xml", AXML, ZIP_DEFLATED),
                ("classes.dex", DEX, ZIP_DEFLATED),
                ("assets/index.android.bundle", v89, ZIP_DEFLATED),
            ],
        )
        report = run(apk)
        assert report["apk"]["valid"]
        assert report["apk"]["hermes_magic_count"] == 1
        assert report["apk"]["hermes_integrity_valid_count"] == 1
        assert report["apk"]["hermes_supported_epoch_count"] == 1
        assert report["apk"]["hermes_parse_complete_count"] == 1
        artifact = assert_exact_binding(report, "assets/index.android.bundle", v89)
        route = route_finding(report)
        assert route["state"] == "CONFIRMED"
        assert route["fields"]["javascript_source_recovery_claimed"] == "false"
        assert route["fields"]["runtime_load_claimed"] == "false"
        assert route["fields"]["automatic_runtime_execution"] == "false"
        child = child_report(report, artifact)
        assert child["hermes"]["state"] == "CONFIRMED"
        assert child["hermes"]["version"] == 89
        assert child["hermes"]["functions"] and child["hermes"]["strings"]
        assert child["artifact"]["relation"] == "apk_hermes_bytecode_child"

        renamed = temp / "renamed.payload"
        make(
            renamed,
            [
                ("assets/", b"", ZIP_STORED),
                ("assets/index.android.bundle", b"console.log('extension decoy')", ZIP_STORED),
                ("assets/releases/", b"", ZIP_STORED),
                ("payload/classes.dex", DEX, ZIP_DEFLATED),
                ("assets/releases/app.payload", v96, ZIP_DEFLATED),
            ],
        )
        report = run(renamed)
        assert report["apk"]["zip_valid"] and not report["apk"]["valid"]
        assert report["apk"]["hermes_magic_count"] == 1
        assert report["apk"]["hermes_probe_entry_count"] == 3
        assert report["apk"]["extraction"]["file_count"] == 1
        assert report["apk"]["extraction"]["files"][0].endswith("assets/releases/app.payload")
        artifact = assert_exact_binding(report, "assets/releases/app.payload", v96)
        assert route_finding(report)["state"] == "CONFIRMED"
        assert child_report(report, artifact)["hermes"]["version"] == 96
        assert not [x for x in report["findings"] if x["family"] == "Android APK"]

        embedded_magic_decoy = temp / "generic-embedded-magic.zip"
        make(
            embedded_magic_decoy,
            [
                ("ordinary.bin", b"prefix" + v89, ZIP_DEFLATED),
                ("note.txt", b"generic ZIP; no routed artifact", ZIP_STORED),
            ],
        )
        report = run(embedded_magic_decoy)
        assert report["apk"]["zip_valid"] and not report["apk"]["valid"]
        assert report["apk"]["hermes_magic_count"] == 0
        assert report["apk"]["hermes_integrity_valid_count"] == 0
        assert not report["apk"]["hermes_entries"]
        assert not hermes_artifacts(report) and not hermes_relationships(report)
        assert not [x for x in report["findings"] if x["family"] == "Hermes APK/ZIP child routing"]
        assert report["apk"]["extraction"]["file_count"] == 0

        if SMOKE:
            print("[PASS] Hermes APK/ZIP exact child route smoke")
            return

        duplicate_sha = temp / "duplicate-sha.zip"
        make(
            duplicate_sha,
            [
                ("one/index.android.bundle", v98, ZIP_DEFLATED),
                ("two/renamed.data", v98, ZIP_STORED),
            ],
        )
        report = run(duplicate_sha)
        assert report["apk"]["hermes_integrity_valid_count"] == 2
        assert len(hermes_relationships(report)) == 2
        assert len(hermes_artifacts(report)) == 2
        states = [
            x["state"] for x in report["artifact_graph"]["edges"]
            if x["relation"] == "apk_hermes_bytecode_child"
        ]
        assert states.count("ANALYZED_STATIC") == 1
        assert states.count("DUPLICATE_SKIPPED") == 1
        assert report["artifact_graph"]["deduplicated"] == 1

        duplicate_path = temp / "duplicate-path.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with ZipFile(duplicate_path, "w") as z:
                z.writestr("assets/index.android.bundle", v89, compress_type=ZIP_DEFLATED)
                z.writestr("assets/index.android.bundle", v96, compress_type=ZIP_STORED)
        report = run(duplicate_path)
        assert report["apk"]["path_collision_entry_count"] == 2
        assert report["apk"]["hermes_integrity_valid_count"] == 0
        assert not hermes_artifacts(report) and not hermes_relationships(report)
        assert route_finding(report)["state"] == "PARTIAL"
        assert all(x["duplicate_path"] for x in report["apk"]["hermes_entries"])

        crc_bad = temp / "bad-crc.container"
        make(crc_bad, [("any/name.bin", v89, ZIP_STORED)])
        raw = bytearray(crc_bad.read_bytes())
        local = raw.find(b"PK\x03\x04")
        assert local >= 0
        name_len, extra_len = struct.unpack_from("<HH", raw, local + 26)
        data_offset = local + 30 + name_len + extra_len
        raw[data_offset + 32] ^= 1
        crc_bad.write_bytes(raw)
        report = run(crc_bad)
        assert report["apk"]["hermes_magic_count"] == 1
        assert report["apk"]["hermes_integrity_valid_count"] == 0
        assert report["apk"]["hermes_integrity_failure_count"] == 1
        assert report["apk"]["hermes_entries"][0]["integrity_valid"] is False
        assert "CRC" in report["apk"]["hermes_entries"][0]["error"]
        assert not hermes_artifacts(report) and not hermes_relationships(report)
        assert route_finding(report)["state"] == "PARTIAL"

        truncated = temp / "truncated.zip"
        make(truncated, [("assets/index.android.bundle", v89[:-21], ZIP_DEFLATED)])
        report = run(truncated)
        artifact = assert_exact_binding(report, "assets/index.android.bundle", v89[:-21])
        assert report["apk"]["hermes_parse_complete_count"] == 0
        child = child_report(report, artifact)
        assert child["hermes"]["state"] == "FAILED"
        assert "fileLength" in child["hermes"]["error"]

        unknown = temp / "unknown-epoch.zip"
        unknown_hbc = mutate_epoch(v89, 97)
        make(unknown, [("assets/versionless.bin", unknown_hbc, ZIP_DEFLATED)])
        report = run(unknown)
        artifact = assert_exact_binding(report, "assets/versionless.bin", unknown_hbc)
        assert report["apk"]["hermes_supported_epoch_count"] == 0
        child = child_report(report, artifact)
        assert child["hermes"]["state"] == "PARTIAL"
        assert child["hermes"]["version"] == 97
        assert child["hermes"]["supported_epoch"] is False

        entry_budget = temp / "entry-budget.zip"
        with ZipFile(entry_budget, "w", compression=ZIP_DEFLATED) as z:
            for i in range(50):
                z.writestr(f"directory-{i:02d}/", b"")
            z.writestr("first/app.payload", v96)
            for i in range(PROBE_ENTRIES - 1):
                z.writestr(f"noise/{i:04d}.blob", b"not hermes")
            z.writestr("late/app.payload", v98)
        report = run(entry_budget)
        assert report["apk"]["hermes_probe_entry_count"] == PROBE_ENTRIES
        assert report["apk"]["hermes_probe_entry_limit"] == PROBE_ENTRIES
        assert report["apk"]["hermes_probe_budget_exhausted"]
        assert report["apk"]["hermes_magic_count"] == 1
        assert report["apk"]["hermes_integrity_valid_count"] == 1
        assert_exact_binding(report, "first/app.payload", v96)
        assert route_finding(report)["state"] == "PARTIAL"

        byte_budget = temp / "total-budget.archive"
        exact_limit_decoy = MAGIC + bytes(PROBE_BYTES - len(MAGIC))
        make(
            byte_budget,
            [
                ("first/small.payload", v89, ZIP_DEFLATED),
                ("second/limit.payload", exact_limit_decoy, ZIP_DEFLATED),
            ],
        )
        report = run(byte_budget, "--artifact-bytes=1")
        assert report["apk"]["hermes_magic_count"] == 2
        assert report["apk"]["hermes_integrity_valid_count"] == 1
        assert report["apk"]["hermes_probe_skipped_budget_count"] == 1
        assert report["apk"]["hermes_probe_budget_exhausted"]
        assert report["apk"]["hermes_probe_validated_bytes"] == len(v89)
        assert report["apk"]["hermes_probe_byte_limit"] == PROBE_BYTES
        entries = {x["name"]: x for x in report["apk"]["hermes_entries"]}
        assert entries["second/limit.payload"]["probe_skipped_budget"]
        assert "64 MiB aggregate byte budget" in entries["second/limit.payload"]["error"]
        assert not hermes_relationships(report)
        assert route_finding(report)["state"] == "PARTIAL"

    print("[PASS] Hermes APK/ZIP exact child routing, identity, budgets, retention, and malformed cases")


if __name__ == "__main__":
    main()
