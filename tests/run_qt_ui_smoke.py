#!/usr/bin/env python3
"""Run the optional Qt GUI through a real offscreen render.

The CLI is replaced with a tiny deterministic producer so this test exercises
QProcess, report parsing, relationship/runtime rendering, screenshot capture,
and the bounded/empty report states without needing a platform window server.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import zlib


def fail(message: str) -> None:
    raise SystemExit(f"qt-ui smoke failed: {message}")


def write_fake_cli(path: Path, report: dict) -> None:
    payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"print({payload!r})\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def png_stats(path: Path) -> tuple[int, int, int, float]:
    raw = path.read_bytes()
    if raw[:8] != b"\x89PNG\r\n\x1a\n":
        fail(f"screenshot is not PNG: {path}")
    pos = 8
    idat = bytearray()
    width = height = bit_depth = color_type = None
    while pos < len(raw):
        length = struct.unpack(">I", raw[pos : pos + 4])[0]
        kind = raw[pos + 4 : pos + 8]
        data = raw[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            width, height, bit_depth, color_type = struct.unpack(">IIBB", data[:10])
        elif kind == b"IDAT":
            idat.extend(data)
        elif kind == b"IEND":
            break
    if width is None or height is None or bit_depth != 8 or color_type not in (2, 6):
        fail(f"unsupported screenshot format: {width}x{height}, depth={bit_depth}, type={color_type}")
    channels = 4 if color_type == 6 else 3
    stride = width * channels
    decoded = zlib.decompress(bytes(idat))
    rows: list[bytes] = []
    prior = bytearray(stride)
    cursor = 0
    for _ in range(height):
        filter_type = decoded[cursor]
        cursor += 1
        row = bytearray(decoded[cursor : cursor + stride])
        cursor += stride
        for i in range(stride):
            left = row[i - channels] if i >= channels else 0
            up = prior[i]
            up_left = prior[i - channels] if i >= channels else 0
            if filter_type == 1:
                row[i] = (row[i] + left) & 255
            elif filter_type == 2:
                row[i] = (row[i] + up) & 255
            elif filter_type == 3:
                row[i] = (row[i] + ((left + up) // 2)) & 255
            elif filter_type == 4:
                p = left + up - up_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - up_left)
                predictor = left if pa <= pb and pa <= pc else up if pb <= pc else up_left
                row[i] = (row[i] + predictor) & 255
            elif filter_type != 0:
                fail(f"unsupported PNG filter {filter_type}")
        rows.append(bytes(row))
        prior = row
    sample_step = max(1, (width * height) // 200_000)
    colors: set[bytes] = set()
    background = rows[0][:channels]
    changed = 0
    sampled = 0
    for index in range(0, width * height, sample_step):
        y, x = divmod(index, width)
        pixel = rows[y][x * channels : (x + 1) * channels]
        colors.add(pixel)
        sampled += 1
        if pixel != background:
            changed += 1
    return width, height, len(colors), changed / max(1, sampled)


def run_case(gui: Path, root: Path, name: str, report: dict, required: tuple[str, ...], absent: tuple[str, ...]) -> None:
    case = root / name
    case.mkdir()
    cli = case / "fake-cli.py"
    sample = case / ("sample-<escaped>&-" + "very-long-label-" * 10 + ".bin")
    sample.write_bytes(b"fixture")
    write_fake_cli(cli, report)
    screenshot = case / "ui.png"
    detail = case / "detail.txt"
    env = os.environ.copy()
    env.update(
        {
            "QT_QPA_PLATFORM": "offscreen",
            "AUTO_REFIRST_CLI": str(cli),
            "AUTO_REFIRST_GUI_OUTPUT": str(case / "reports"),
            "AUTO_REFIRST_GUI_SCREENSHOT": str(screenshot),
            "AUTO_REFIRST_GUI_DETAIL_DUMP": str(detail),
            "AUTO_REFIRST_GUI_EXIT_AFTER_ANALYSIS": "1",
            "AUTO_REFIRST_GUI_LANGUAGE": "en",
        }
    )
    completed = subprocess.run([str(gui), str(sample)], env=env, text=True, capture_output=True, timeout=35)
    if completed.returncode != 0:
        fail(f"{name} exited {completed.returncode}: stdout={completed.stdout[-500:]} stderr={completed.stderr[-500:]}")
    if not screenshot.is_file() or screenshot.stat().st_size < 10_000:
        fail(f"{name} did not produce a substantive screenshot")
    if not detail.is_file():
        fail(f"{name} did not produce the rendered detail dump")
    text = detail.read_text(encoding="utf-8")
    for marker in required:
        if marker not in text:
            fail(f"{name} detail missing {marker!r}")
    for marker in absent:
        if marker in text:
            fail(f"{name} detail unexpectedly contains {marker!r}")
    width, height, colors, changed = png_stats(screenshot)
    if width < 900 or height < 600 or colors < 200 or changed < 0.05:
        fail(f"{name} screenshot is visually empty: {width}x{height}, colors={colors}, changed={changed:.2%}")
    print(f"[PASS] {name}: {width}x{height}, colors={colors}, changed={changed:.1%}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gui", required=True, type=Path)
    args = parser.parse_args()
    gui = args.gui.resolve()
    if not gui.is_file():
        fail(f"GUI binary does not exist: {gui}")
    with tempfile.TemporaryDirectory(prefix="auto-refirst-qt-smoke-") as temp:
        root = Path(temp)
        long_a_name = "parent-" + "A" * 80 + ".bin"
        long_b_name = "child-" + "B" * 80 + ".bin"
        long_a = str(root / long_a_name)
        long_b = str(root / long_b_name)
        relationships = [
            {
                "kind": "escaped <relationship> & route",
                "first": long_a,
                "second": long_b,
                "directed": True,
                "state": "CONFIRMED",
                "evidence_level": "STATIC",
                "ambiguity": "NONE",
            }
            for _ in range(40)
        ]
        escaped_marker = 'literal <tag> & "quoted"'
        rich = {
            "input": "sample-<escaped>&.bin",
            "format": {"kind": "PE"},
            "findings": [
                {
                    "family": "Escaping family <&>",
                    "variant": "long variant " + "x" * 160,
                    "state": "CONFIRMED",
                    "evidence": [escaped_marker + " survives as plain text"],
                }
            ],
            "artifact_relationships": relationships,
            "orchestration": {
                "runtime_plan": {
                    "runtime_eligible": False,
                    "policy": "static-only",
                    "runtime_eligibility_reason": "runtime evidence is intentionally unavailable in this fixture",
                    "steps": [
                        {"analyzer": f"step-{i}-" + "z" * 40, "state": "SKIPPED", "selected": False, "reason": "bounded fixture"}
                        for i in range(12)
                    ],
                }
            },
            "artifact_graph": {"truncated": True},
        }
        empty = {
            "input": "empty.bin",
            "format": {"kind": "EMPTY"},
            "findings": [],
            "artifact_relationships": [],
            "artifact_graph": {"truncated": True},
        }
        run_case(gui, root, "rich", rich, ("RELATIONSHIPS", "more relationships hidden", escaped_marker, "long variant", long_a_name, long_b_name, "LIMITS", "RUNTIME"), ())
        run_case(gui, root, "empty-truncated", empty, ("No findings match the filter.", "LIMITS"), ("RELATIONSHIPS",))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
