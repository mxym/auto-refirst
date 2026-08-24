#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
AR = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build/auto-refirst"
CORPUS = ROOT / "tests/corpus/hermes"


def analyze(path: Path) -> dict:
    result = subprocess.run(
        [str(AR), str(path), "--json"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return json.loads(result.stdout)


def analyze_text(path: Path) -> str:
    return subprocess.run(
        [str(AR), str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    ).stdout


def rewrite_footer(data: bytearray) -> None:
    data[-20:] = hashlib.sha1(data[:-20]).digest()


def write_mutation(path: Path, source: bytes, offset: int, value: int) -> None:
    data = bytearray(source)
    struct.pack_into("<I", data, offset, value)
    rewrite_footer(data)
    path.write_bytes(data)


def hermes_finding(report: dict) -> dict:
    rows = [row for row in report["findings"] if row["family"] == "Hermes bytecode"]
    assert len(rows) == 1
    return rows[0]


def build_v89_overflow(*, mismatched_info: bool = False, duplicate_overflow: bool = False) -> bytes:
    string_count = 2 if duplicate_overflow else 1
    overflow_count = 2 if duplicate_overflow else 0
    string_table_offset = 148
    overflow_table_offset = string_table_offset + string_count * 4
    string_storage_offset = overflow_table_offset + overflow_count * 8
    function_body = (string_storage_offset + string_count + 3) & ~3
    large_header = (function_body + 1 + 3) & ~3
    debug_offset = (large_header + 31 + 3) & ~3
    total_size = debug_offset + 20 + 20
    data = bytearray(total_size)
    data[:8] = bytes.fromhex("c61fbc03c103191f")
    for offset, value in (
        (8, 89), (32, total_size), (36, 0), (40, 1), (44, 1),
        (48, 0), (52, string_count), (56, overflow_count),
        (60, string_count), (104, debug_offset),
    ):
        struct.pack_into("<I", data, offset, value)
    struct.pack_into("<I", data, 128, large_header & 0xFFFF)
    struct.pack_into("<I", data, 136, large_header >> 16)
    data[143] = 0x20
    struct.pack_into("<I", data, 144, string_count)
    for index in range(string_count):
        if duplicate_overflow:
            struct.pack_into("<I", data, string_table_offset + index * 4, 0xFF << 24)
        else:
            struct.pack_into("<I", data, string_table_offset, 1 << 24)
    if duplicate_overflow:
        struct.pack_into("<II", data, overflow_table_offset, 0, 1)
        struct.pack_into("<II", data, overflow_table_offset + 8, 1, 1)
    data[string_storage_offset:string_storage_offset + string_count] = b"g" * string_count
    data[function_body] = 0
    for offset, value in (
        (large_header, function_body),
        (large_header + 4, 0),
        (large_header + 8, 1),
        (large_header + 12, 0),
        (large_header + 16, large_header + (4 if mismatched_info else 0)),
        (large_header + 20, 0),
        (large_header + 24, 0),
    ):
        struct.pack_into("<I", data, offset, value)
    rewrite_footer(data)
    return bytes(data)


def build_v89_string_budget(lengths: list[int], *, final_utf16: bool = False) -> bytes:
    assert lengths and max(lengths) <= 0xFFFFFFFF
    string_count = 1 + len(lengths)
    overflow_count = len(lengths)
    string_table_offset = 148
    overflow_table_offset = string_table_offset + string_count * 4
    string_storage_offset = overflow_table_offset + overflow_count * 8
    string_storage_size = max(lengths)
    function_body = (string_storage_offset + string_storage_size + 3) & ~3
    debug_offset = (function_body + 1 + 3) & ~3
    total_size = debug_offset + 20 + 20
    data = bytearray(total_size)
    data[:8] = bytes.fromhex("c61fbc03c103191f")
    for offset, value in (
        (8, 89), (32, total_size), (36, 0), (40, 1), (44, 1),
        (48, 0), (52, string_count), (56, overflow_count),
        (60, string_storage_size), (104, debug_offset),
    ):
        struct.pack_into("<I", data, offset, value)
    struct.pack_into("<I", data, 128, function_body)
    struct.pack_into("<I", data, 132, 1)
    struct.pack_into("<I", data, 144, string_count)
    for index, length in enumerate(lengths):
        utf16 = final_utf16 and index == len(lengths) - 1
        word = (0xFF << 24) | (index << 1) | int(utf16)
        struct.pack_into("<I", data, string_table_offset + (index + 1) * 4, word)
        struct.pack_into("<II", data, overflow_table_offset + index * 8, 0, length)
    data[function_body] = 0
    rewrite_footer(data)
    return bytes(data)

def assert_failed(report: dict, needle: str) -> None:
    hermes = report["hermes"]
    finding = hermes_finding(report)
    assert hermes["candidate"] and hermes["supported_epoch"]
    assert not hermes["valid"] and not hermes["parse_complete"]
    assert finding["state"] == "FAILED"
    assert needle in hermes["error"]


def main() -> None:
    expected = {
        89: (824, "ec40d157573d2790e3cb9155a70fbf7755ee088cce57f8956c7602f93bcf6ae6"),
        96: (1056, "47a027e701a11b017fddcb0fc9608fdf237ed158e59843dbe8f45c8b325a05ad"),
        98: (964, "5fde3c00967fa2ba73de4ad6760813c62e4226cd557f2ee732a7ec43b2a16f7e"),
    }
    with tempfile.TemporaryDirectory(prefix="auto-refirst-hermes-") as temp:
        temp = Path(temp)
        inputs = {}
        for version, (size, digest) in expected.items():
            fixture = CORPUS / f"v{version}.hbc"
            data = fixture.read_bytes()
            assert len(data) == size and hashlib.sha256(data).hexdigest() == digest
            candidate = temp / f"epoch-{version}.bin"
            candidate.write_bytes(data)
            inputs[version] = (candidate, data)

            report = analyze(candidate)
            hermes = report["hermes"]
            finding = hermes_finding(report)
            assert hermes["candidate"] and hermes["supported_epoch"]
            assert hermes["valid"] and hermes["parse_complete"]
            assert hermes["state"] == "CONFIRMED" and finding["state"] == "CONFIRMED"
            assert hermes["version"] == version and hermes["function_count"] == 4
            assert hermes["string_count"] == 10 and hermes["debug"]["valid"]
            assert hermes["footer_hash_checked"] and hermes["footer_hash_matches"]
            assert {row["function_name"] for row in hermes["functions"]} == {"global", "greet", "score", "choose"}
            assert "AUTO_REFIRST_HERMES_FIXTURE" in {row["value"] for row in hermes["strings"]}
            assert hermes["opcodes"] and all(row["count"] > 0 for row in hermes["opcodes"])
            assert finding["fields"]["javascript_source_recovery_claimed"] == "false"
            assert finding["fields"]["runtime_load_claimed"] == "false"
            extraction = hermes["extraction"]
            assert extraction["success"]
            for key in ("functions_csv", "strings_csv", "opcodes_csv"):
                output = Path(extraction[key])
                assert output.is_file() and output.stat().st_size > 20

        source = inputs[89][1]

        renamed = temp / "renamed.data"
        renamed.write_bytes(source)
        assert analyze(renamed)["hermes"]["state"] == "CONFIRMED"

        truncated = temp / "truncated.hbc"
        truncated.write_bytes(source[:-21])
        assert_failed(analyze(truncated), "fileLength")

        bad_footer = temp / "bad-footer.hbc"
        bad_footer_data = bytearray(source)
        bad_footer_data[200] ^= 1
        bad_footer.write_bytes(bad_footer_data)
        assert_failed(analyze(bad_footer), "footer SHA-1")

        count_budget = temp / "count-budget.hbc"
        write_mutation(count_budget, source, 40, 131073)
        budget_report = analyze(count_budget)
        budget = budget_report["hermes"]
        assert budget["state"] == "PARTIAL" and budget["budget_limited"]
        assert not budget["valid"] and not budget["parse_complete"]
        assert hermes_finding(budget_report)["state"] == "PARTIAL"
        budget_text = analyze_text(count_budget)
        assert "  state: PARTIAL version=89" in budget_text
        assert "  state: FAILED version=89" not in budget_text

        unknown = temp / "unknown-epoch.hbc"
        write_mutation(unknown, source, 8, 97)
        unknown_report = analyze(unknown)
        unknown_hbc = unknown_report["hermes"]
        assert unknown_hbc["state"] == "PARTIAL" and not unknown_hbc["supported_epoch"]
        assert not unknown_hbc["valid"] and not unknown_hbc["parse_complete"]
        assert hermes_finding(unknown_report)["state"] == "PARTIAL"

        bad_offset = temp / "bad-offset.hbc"
        first_word = struct.unpack_from("<I", source, 128)[0]
        write_mutation(bad_offset, source, 128, first_word & ~0x01FFFFFF)
        assert_failed(analyze(bad_offset), "bytecode range")

        overlap = temp / "overlap.hbc"
        second_word = struct.unpack_from("<I", source, 144)[0]
        write_mutation(overlap, source, 144, (second_word & ~0x01FFFFFF) | 353)
        assert_failed(analyze(overlap), "partially overlap")

        bad_opcode = temp / "bad-opcode.hbc"
        opcode_data = bytearray(source)
        opcode_data[352] = 0xFF
        rewrite_footer(opcode_data)
        bad_opcode.write_bytes(opcode_data)
        assert_failed(analyze(bad_opcode), "opcode outside")

        valid_overflow = temp / "valid-overflow.hbc"
        valid_overflow.write_bytes(build_v89_overflow())
        valid_overflow_report = analyze(valid_overflow)
        assert valid_overflow_report["hermes"]["state"] == "CONFIRMED"
        assert valid_overflow_report["hermes"]["functions"][0]["overflow_header"]

        mismatched_overflow = temp / "mismatched-overflow.hbc"
        mismatched_overflow.write_bytes(build_v89_overflow(mismatched_info=True))
        assert_failed(analyze(mismatched_overflow), "pointer/infoOffset binding")

        duplicate_overflow = temp / "duplicate-overflow-string.hbc"
        duplicate_overflow.write_bytes(build_v89_overflow(duplicate_overflow=True))
        assert_failed(analyze(duplicate_overflow), "referenced more than once")

        decoded_chunk = 2 * 1024 * 1024
        decoded_lengths = [decoded_chunk] * 32
        decoded_boundary_source = build_v89_string_budget(decoded_lengths)
        assert len(decoded_boundary_source) < 3 * 1024 * 1024
        decoded_boundary = temp / "decoded-string-budget-boundary.hbc"
        decoded_boundary.write_bytes(decoded_boundary_source)
        boundary_text = analyze_text(decoded_boundary)
        assert "  state: CONFIRMED version=89" in boundary_text

        decoded_over = temp / "decoded-string-budget-plus-one.hbc"
        decoded_over.write_bytes(build_v89_string_budget(decoded_lengths + [1], final_utf16=True))
        decoded_over_text = analyze_text(decoded_over)
        assert "  state: PARTIAL version=89" in decoded_over_text
        assert "  state: FAILED version=89" not in decoded_over_text
        assert "decoded string/function-name output exceeded the bounded 64 MiB map budget" in decoded_over_text

        wide_length = bytearray(decoded_boundary_source)
        overflow_table_offset = 148 + (1 + len(decoded_lengths)) * 4
        struct.pack_into("<I", wide_length, overflow_table_offset + 4, 0xFFFFFFFF)
        rewrite_footer(wide_length)
        wide_length_path = temp / "decoded-string-wide-length.hbc"
        wide_length_path.write_bytes(wide_length)
        assert_failed(analyze(wide_length_path), "string entry exceeds string storage")

        decoy = temp / "embedded-magic.bin"
        decoy.write_bytes(b"not-a-bytecode-prefix" + source)
        decoy_report = analyze(decoy)
        assert not decoy_report["hermes"]["candidate"]
        assert not [row for row in decoy_report["findings"] if row["family"] == "Hermes bytecode"]

    print("[PASS] Hermes HBC v89/v96/v98 parser, maps, bounds, mutations, and claim limits")


if __name__ == "__main__":
    main()
