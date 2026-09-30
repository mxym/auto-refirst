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
        "add_executable(auto_refirst_gui WIN32",
        "windeployqt",
        "POST_BUILD",
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
        "kUiRelationshipCap",
        "kUiRuntimeCap",
        "LIMITS",
        "m_language",
        "m_recursive",
        "m_run",
        "m_apply",
        "m_runtime_mode",
        "QStackedWidget",
        "m_nav_workspace",
        "m_nav_settings",
        "m_navigation_title",
        "showPage",
        "m_metric_findings",
        "m_metric_confirmed",
        "m_metric_review",
        "m_search_edit",
        "m_artifact_root_edit",
        "--report-lang=",
        "--timeout=",
        "--max-depth=",
        "--max-runtime-targets=",
        "--total-runtime-budget=",
        "--run-all",
        "--artifact-depth=",
        "--artifact-nodes=",
        "--artifact-bytes=",
        "--artifact-root=",
        "--search=",
        "--search-ignore-case",
        "--wxid=",
        "setCreateProcessArgumentsModifier",
        "CREATE_NO_WINDOW",
        "familyMatch",
        "artifact_relationships",
        "RELATIONSHIPS",
        "runtime_plan",
        "runtime_eligibility_reason",
        "runtimeStateLabel",
        "runtime_steps",
        "selected",
        "RUNTIME",
        "AUTO_REFIRST_GUI_LANGUAGE",
        "AUTO_REFIRST_GUI_PAGE",
        "AUTO_REFIRST_GUI_SEARCH",
        "QDesktopServices::openUrl",
    ):
        if needle not in source:
            fail(f"missing UI behavior marker: {needle}")
    for flag in ("--run", "--apply"):
        if flag in source and f"if (m_{'run' if flag == '--run' else 'apply'}->isChecked())" not in source:
            fail(f"{flag} must be explicitly gated by its checkbox")
    print("[PASS] optional Qt UI contract (offline)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
