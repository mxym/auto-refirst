#!/usr/bin/env python3
"""Public static-only oracle for the tracked project-owned APK/JNI fixture."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/corpus/apk-jni/jni-relation-x86_64.apk"
EXPECTED_MEMBERS = [
    "AndroidManifest.xml",
    "classes.dex",
    "lib/x86_64/libjni_relation.so",
]
EXPECTED_LEVELS = {
    "J0_PACKAGED",
    "J1_STATIC_LOAD_REFERENCE",
    "J2_DEX_NATIVE_DECLARATION",
    "J3_JNI_MANGLED_EXPORT",
    "J4_REGISTERNATIVES_TABLE_FDE",
}


def main() -> int:
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build/auto-refirst"
    assert binary.is_file(), binary
    assert FIXTURE.is_file(), FIXTURE
    with ZipFile(FIXTURE) as archive:
        assert archive.namelist() == EXPECTED_MEMBERS, archive.namelist()
        assert len(set(archive.namelist())) == len(EXPECTED_MEMBERS)
        assert archive.testzip() is None

    completed = subprocess.run(
        [str(binary), str(FIXTURE), "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    stdout = completed.stdout.decode("utf-8", errors="strict")
    stderr = completed.stderr.decode("utf-8", errors="strict")
    assert completed.returncode == 0, (completed.returncode, stdout[-2000:], stderr[-2000:])
    report = json.loads(stdout)
    apk = report["apk"]
    assert apk["valid"] and apk["jni_relations_state"] == "RESOLVED", apk
    counts = tuple(
        apk[key] for key in (
            "jni_packaged_count",
            "jni_referenced_count",
            "jni_declared_count",
            "jni_exported_count",
            "jni_registration_confirmed_count",
        )
    )
    assert counts == (1, 1, 1, 1, 1), counts
    levels = {item["evidence_level"]: item for item in apk["jni_relations"]}
    assert set(levels) == EXPECTED_LEVELS, set(levels)
    assert levels["J1_STATIC_LOAD_REFERENCE"]["library_name"] == "jni_relation"
    for level in (
        "J2_DEX_NATIVE_DECLARATION",
        "J3_JNI_MANGLED_EXPORT",
        "J4_REGISTERNATIVES_TABLE_FDE",
    ):
        relation = levels[level]
        assert relation["class_descriptor"] == "Lcom/example/JniRelationFixture;"
        assert relation["method_name"] == "nativeAdd"
        assert relation["method_descriptor"] == "(I)I"
    assert levels["J3_JNI_MANGLED_EXPORT"]["fde_boundary_confirmed"]
    registration = levels["J4_REGISTERNATIVES_TABLE_FDE"]
    assert registration["registration_confirmed"] and registration["fde_boundary_confirmed"]
    assert apk["native_relocation_count"] >= 3 and apk["native_fde_count"] >= 3
    deep = apk["native_deep_entries"]
    assert len(deep) == 1
    assert deep[0]["native_dynamic_state"] == "RESOLVED"
    assert deep[0]["native_unwind_state"] == "RESOLVED"
    assert not deep[0]["native_jni_evidence_limited"]
    finding = next(
        item for item in report["findings"]
        if item["family"] == "Android APK" and item["state"] == "CONFIRMED"
    )
    assert finding["fields"]["jni_static_only"] == "true"
    assert any("invocation was not observed" in item for item in finding["evidence"])
    assert report["runtime"]["requested"] is False
    print("[PASS] project-owned APK/JNI J0-J4 structural relation fixture; static only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
