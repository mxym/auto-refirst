#!/usr/bin/env python3
"""Regression tests for the opt-in JSON diagnostics channel.

The successful report transport is intentionally tested alongside failures: JSON
errors belong on stderr so stdout remains a clean report stream for pipelines.
"""
from __future__ import annotations
import json
import os
import pathlib
import subprocess
import sys
import tempfile

AR = pathlib.Path(sys.argv[1]).resolve()


def run(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    return subprocess.run(
        [str(AR), *map(str, args)],
        stdout=stdout,
        stderr=stderr,
        timeout=90,
    )


def assert_error(cp: subprocess.CompletedProcess[bytes], code: int, kind: str):
    assert cp.returncode == code, (cp.returncode, cp.stdout, cp.stderr)
    assert cp.stdout in (b"", None), cp.stdout
    assert cp.stderr, cp.stderr
    obj = json.loads(cp.stderr)
    assert obj["error_schema_version"] == "1.0", obj
    err = obj["error"]
    assert err["code"] == code and err["kind"] == kind, err
    assert err["stage"] and err["message"], err
    return err


def main() -> None:
    assert AR.is_file(), AR
    with tempfile.TemporaryDirectory(prefix="auto-refirst-json-errors-") as raw:
        td = pathlib.Path(raw)
        sample = td / "合法-✓-input.bin"
        sample.write_bytes(b"source-generated input")

        # Unknown options are usage failures and remain isolated to stderr.
        err = assert_error(run(sample, "--json-errors", "--unknown-option"), 2, "usage")
        assert "unknown option" in err["message"], err

        # Missing input is an input failure; the UTF-8 path is escaped by the
        # CLI envelope and remains valid JSON.
        missing = td / "不存在-☃.bin"
        err = assert_error(run(missing, "--json-errors"), 3, "input")
        assert err["path"].endswith("不存在-☃.bin"), err

        # --json-errors is independent from --json. A valid report still uses
        # stdout, with no diagnostics on stderr.
        ok = run(sample, "--json-errors", "--json")
        assert ok.returncode == 0 and ok.stderr == b"", (ok.returncode, ok.stderr)
        json.loads(ok.stdout)

        # Search no-match is the documented non-error exit code 1 and has no
        # error envelope even when diagnostics are enabled.
        no_match = run(sample, "--json-errors", "--json", "--search=definitely-not-present")
        assert no_match.returncode == 1 and no_match.stdout == b"" and no_match.stderr == b"", (
            no_match.returncode,
            no_match.stdout,
            no_match.stderr,
        )

        # Force the fatal output-write path on Unix. The error envelope is on
        # stderr and must still carry the process-level code 4.
        if os.name != "nt" and pathlib.Path("/dev/full").exists():
            with pathlib.Path("/dev/full").open("wb") as sink:
                fatal = run(sample, "--json-errors", "--json", stdout=sink)
            assert_error(fatal, 4, "internal")
            # A failed diagnostics stream is itself a transport failure. The
            # process must upgrade the requested usage code to fatal code 4.
            with pathlib.Path("/dev/full").open("wb") as sink:
                stderr_failure = run(sample, "--json-errors", "--unknown-option", stderr=sink)
            assert stderr_failure.returncode == 4, stderr_failure.returncode

    print("[PASS] --json-errors stderr envelope: usage/input/internal + clean success/search transports")


if __name__ == "__main__":
    main()
