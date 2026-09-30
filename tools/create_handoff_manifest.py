#!/usr/bin/env python3
"""Create a deterministic, static-only handoff manifest from auto-refirst JSON.

The manifest is a transport contract for a downstream human/tool.  It never
executes, installs, writes back, or follows paths named by the input report.
All artifact and runtime observations remain explicitly untrusted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any, Iterable

TOOL_VERSION = "1.0"
DEFAULT_MAX_ENTRIES = 4096
DEFAULT_MAX_FINDINGS = 4096
DEFAULT_MAX_RELATIONSHIPS = 8192


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _bool(value: Any) -> bool:
    return value if isinstance(value, bool) else False


def _num(value: Any) -> int | float:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _sorted_strings(values: Iterable[Any]) -> list[str]:
    return sorted({_str(x) for x in values if isinstance(x, str) and x})


def _bounded_strings(value: Any, limit: int = 32) -> list[str]:
    return _sorted_strings(_list(value))[:limit]


def _load(path: pathlib.Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    try:
        return json.loads(raw.decode("utf-8")), raw
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"report is not valid UTF-8 JSON: {exc}") from exc


def _reports(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict) and isinstance(value.get("reports"), list):
        return [x for x in value["reports"] if isinstance(x, dict)]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _source(report: dict[str, Any]) -> dict[str, Any]:
    # The CLI report carries the source snapshot at the report root. There is
    # no input_snapshot object (and no exists bit) in the public JSON schema;
    # do not synthesize one or claim that a path was observed to exist.
    return {
        "path": _str(report.get("input")),
        "sha256": _str(report.get("sha256")),
        "size": _num(report.get("size")),
        "offset_space": "current_input_file",
    }


def _entry(record: dict[str, Any], *, source_report: int, runtime: bool = False) -> dict[str, Any]:
    # Copy only contract fields.  Arbitrary report fields are intentionally not
    # propagated into the handoff surface.
    item = {
        "source_report": source_report,
        "path": _str(record.get("path")),
        "kind": _str(record.get("kind")),
        "role": _str(record.get("role")),
        "source": _str(record.get("source")),
        "state": _str(record.get("state")),
        "relation": _str(record.get("relation")),
        "priority": _str(record.get("priority")),
        "parent": _str(record.get("parent")),
        "size": _num(record.get("size")),
        "sha256": _str(record.get("sha256")),
        "normalized": _bool(record.get("normalized")),
        "runtime_confirmed": _bool(record.get("runtime_confirmed")),
        "trust_state": "RUNTIME_OBSERVED_UNTRUSTED" if runtime else "STATIC_ARTIFACT_UNTRUSTED",
        "execution_allowed": False,
    }
    return item


def _finding(record: dict[str, Any], *, source_report: int) -> dict[str, Any]:
    return {
        "source_report": source_report,
        "kind": _str(record.get("kind")),
        "family": _str(record.get("family")),
        "variant": _str(record.get("variant")),
        "state": _str(record.get("state")),
        "confidence": record.get("confidence") if isinstance(record.get("confidence"), (int, float)) else 0,
        "evidence": _bounded_strings(record.get("evidence")),
        "negative_evidence": _bounded_strings(record.get("negative_evidence")),
        "suggested_actions": _bounded_strings(record.get("suggested_actions")),
        "fields": {str(k): str(v) for k, v in sorted(_obj(record.get("fields")).items()) if isinstance(k, str)},
        "execution_allowed": False,
    }


def _relationship(record: dict[str, Any], *, source_report: int) -> dict[str, Any]:
    keep = ("kind", "state", "first", "second", "first_role", "second_role",
            "first_relation_role", "second_relation_role", "evidence_level",
            "evidence_basis", "evidence_source", "source_coordinate",
            "target_coordinate", "provenance_scope", "ambiguity", "semantic_relevance",
            "reason")
    out = {"source_report": source_report}
    for key in keep:
        value = record.get(key)
        if isinstance(value, str):
            out[key] = value
    out["execution_allowed"] = False
    return out


def build(value: Any, raw: bytes, *, max_entries: int, max_findings: int,
          max_relationships: int) -> dict[str, Any]:
    reports = _reports(value)
    if not reports:
        raise ValueError("report must be an object, array, or reports[] envelope")
    source_hash = hashlib.sha256(raw).hexdigest()
    report_schema = value.get("report_schema_version") if isinstance(value, dict) else None
    entries: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    next_actions: set[str] = set()
    sources: list[dict[str, Any]] = []
    for index, report in enumerate(reports):
        sources.append({"report_index": index, **_source(report)})
        for rec in _list(report.get("artifacts")):
            if isinstance(rec, dict):
                entries.append(_entry(rec, source_report=index))
        runtime = _obj(report.get("runtime"))
        for rec in _list(runtime.get("artifacts")):
            if isinstance(rec, dict):
                entries.append(_entry(rec, source_report=index, runtime=True))
        for rec in _list(report.get("findings")):
            if isinstance(rec, dict):
                f = _finding(rec, source_report=index)
                findings.append(f)
                next_actions.update(f["suggested_actions"])
        for rec in _list(report.get("artifact_relationships")):
            if isinstance(rec, dict):
                relationships.append(_relationship(rec, source_report=index))
        guidance = _obj(report.get("analysis_guidance"))
        next_actions.update(_bounded_strings(guidance.get("priority_guidance")))
        # Runtime guidance is nested in the CLI contract.  Keep the legacy
        # report-level list above for compatibility, but read the real path.
        modality = _obj(guidance.get("runtime_modality"))
        next_actions.update(_bounded_strings(modality.get("priority_guidance")))

    # Directory --json reports keep the aggregate runtime guidance beside
    # reports[], under directory_summary.runtime_modality.  It is still
    # declared evidence from the report and should not be silently dropped.
    if isinstance(value, dict):
        summary = _obj(value.get("directory_summary"))
        summary_modality = _obj(summary.get("runtime_modality"))
        next_actions.update(_bounded_strings(summary_modality.get("priority_guidance")))

    entries.sort(key=lambda x: (x["source_report"], x["path"], x["kind"], x["role"], x["sha256"], x["state"]))
    findings.sort(key=lambda x: (x["source_report"], x["family"], x["kind"], x["variant"], x["state"]))
    relationships.sort(key=lambda x: (x.get("source_report", 0), x.get("kind", ""), x.get("first", ""), x.get("second", ""), x.get("state", "")))
    truncation = {
        "entries_total": len(entries),
        "findings_total": len(findings),
        "relationships_total": len(relationships),
        "entries_omitted": max(0, len(entries) - max_entries),
        "findings_omitted": max(0, len(findings) - max_findings),
        "relationships_omitted": max(0, len(relationships) - max_relationships),
    }
    manifest = {
        "manifest_schema_version": "1.0",
        "kind": "auto-refirst.static-handoff-manifest",
        "tool": {"name": "create_handoff_manifest", "version": TOOL_VERSION},
        "generated_from": {"report_sha256": source_hash, "report_schema_version": report_schema or "unknown", "report_count": len(reports)},
        "policy": {
            "static_only": True,
            "execution_authorized": False,
            "installation_authorized": False,
            "writeback_authorized": False,
            "untrusted_artifact_boundary": True,
            "path_resolution": "DECLARED_ONLY_NO_FOLLOW",
        },
        "sources": sources,
        "entries": entries[:max_entries],
        "findings": findings[:max_findings],
        "relationships": relationships[:max_relationships],
        "next_actions": sorted(next_actions),
        "truncation": truncation,
    }
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report", type=pathlib.Path, help="auto-refirst JSON report or --json-envelope")
    ap.add_argument("-o", "--output", type=pathlib.Path, help="output path; stdout when omitted")
    ap.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    ap.add_argument("--max-findings", type=int, default=DEFAULT_MAX_FINDINGS)
    ap.add_argument("--max-relationships", type=int, default=DEFAULT_MAX_RELATIONSHIPS)
    ns = ap.parse_args(argv)
    if min(ns.max_entries, ns.max_findings, ns.max_relationships) < 0:
        ap.error("manifest limits must be non-negative")
    try:
        value, raw = _load(ns.report)
        manifest = build(value, raw, max_entries=ns.max_entries, max_findings=ns.max_findings, max_relationships=ns.max_relationships)
        text = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        if ns.output:
            ns.output.parent.mkdir(parents=True, exist_ok=True)
            tmp = ns.output.with_name(ns.output.name + ".tmp")
            tmp.write_text(text, encoding="utf-8", newline="\n")
            tmp.replace(ns.output)
        else:
            sys.stdout.write(text)
        return 0
    except (OSError, ValueError) as exc:
        print(f"create_handoff_manifest: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
