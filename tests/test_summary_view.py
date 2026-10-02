#!/usr/bin/env python3
"""Check the opt-in concise report view without changing the default contract."""

import json
import pathlib
import subprocess
import sys
import tempfile


def run(binary: pathlib.Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="auto-refirst-summary-") as raw:
        sample = pathlib.Path(raw) / "sample.bin"
        sample.write_bytes(b"summary fixture\n")

        default_text = run(binary, str(sample)).stdout
        compact_text = run(binary, str(sample), "--summary").stdout
        assert "SHA256:" in default_text and "Size:" in default_text, default_text
        assert "SHA256:" not in compact_text and "Size:" not in compact_text, compact_text
        assert "Format: unknown" in compact_text, compact_text
        assert "Analysis guidance:" not in compact_text, compact_text

        compact = json.loads(run(binary, str(sample), "--summary", "--json").stdout)
        assert compact["report_schema_version"] == "1.0", compact
        assert compact["view"] == "summary", compact
        assert set(compact) == {
            "report_schema_version",
            "view",
            "input",
            "format",
            "artifacts",
            "findings",
            "runtime_artifacts",
        }, compact
        assert compact["format"]["kind"] == "unknown", compact

        envelope = json.loads(
            run(binary, str(sample), "--summary", "--json", "--json-envelope").stdout
        )
        assert envelope["report_schema_version"] == "1.0", envelope
        assert envelope["reports"][0]["view"] == "summary", envelope

    print("[PASS] opt-in concise summary text/JSON view")


if __name__ == "__main__":
    main()
