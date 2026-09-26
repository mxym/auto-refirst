#!/usr/bin/env python3
"""Offline contract check for the optional Qt drag-and-drop client.

This check deliberately does not require Qt or launch a GUI.  It protects the
integration boundary that is easy to regress while keeping the normal public
CLI gate independent of a desktop toolkit.
"""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
CMAKE = ROOT / "CMakeLists.txt"
SOURCE = ROOT / "tools" / "qt_gui" / "main.cpp"


def fail(message: str) -> None:
    raise SystemExit(f"qt-ui contract failed: {message}")


def main() -> int:
    cmake = CMAKE.read_text(encoding="utf-8")
    source = SOURCE.read_text(encoding="utf-8")
    if not re.search(r"option\(\s*AUTO_REFIRST_BUILD_QT_UI[^\n]*\sOFF\s*\)", cmake):
        fail("AUTO_REFIRST_BUILD_QT_UI must default OFF")
    for needle in (
        "find_package(Qt6 COMPONENTS Widgets QUIET)",
        "find_package(Qt5 COMPONENTS Widgets QUIET)",
        "add_executable(auto_refirst_gui tools/qt_gui/main.cpp)",
        'OUTPUT_NAME "auto-refirst-gui"',
        "target_link_libraries(auto_refirst_gui",
    ):
        if needle not in cmake:
            fail(f"missing CMake integration marker: {needle}")
    for needle in (
        "setAcceptDrops(true)",
        "dragEnterEvent",
        "dropEvent",
        "QProcess",
        "--json",
        "--json-envelope",
        "--json-errors",
        "QTimer",
        "processTimedOut",
        "cancelAnalysis",
        "kUiOutputCap",
        "LIMITATIONS / LOW CONFIDENCE",
        "QDesktopServices::openUrl",
    ):
        if needle not in source:
            fail(f"missing UI behavior marker: {needle}")
    if "--run" in source or "--apply" in source:
        # The words are allowed in explanatory UI text, but the GUI must not
        # pass either authorization flag to the child process.
        if re.search(r"args\s*<<[^;]*(--run|--apply)", source):
            fail("GUI must not authorize runtime execution or replacement")
    print("[PASS] optional Qt UI contract (offline)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
