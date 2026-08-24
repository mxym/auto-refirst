#!/usr/bin/env python3
"""Fail-closed verifier for hosted-CI auto-refirst build identity."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys


FULL_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
PRODUCT_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]*")
SCHEMA_VERSION = re.compile(r"[0-9]+\.[0-9]+")
FIELDS = ("git_commit", "build_platform", "report_schema_version")


class IdentityError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise IdentityError(message)


def validate_version_output(
    output: str,
    *,
    expected_commit: str,
    expected_platform: str,
    expected_schema: str,
) -> tuple[str, dict[str, str]]:
    if FULL_SHA.fullmatch(expected_commit) is None:
        fail("expected commit must be one full lowercase Git object ID")
    if not expected_platform or "/" not in expected_platform:
        fail("expected platform must be an exact OS/architecture identity")
    if SCHEMA_VERSION.fullmatch(expected_schema) is None:
        fail("expected report schema must be major.minor")
    if "\x00" in output:
        fail("version output contains NUL")

    lines = output.splitlines()
    if len(lines) != 4 or any(not line or line != line.strip() for line in lines):
        fail("version output must be exactly four non-empty, unpadded lines")
    product_match = re.fullmatch(r"auto-refirst (.+)", lines[0])
    if product_match is None or PRODUCT_VERSION.fullmatch(product_match.group(1)) is None:
        fail("invalid product version line")

    fields: dict[str, str] = {}
    for line in lines[1:]:
        if "=" not in line:
            fail("version metadata line is not key=value")
        key, value = line.split("=", 1)
        if key not in FIELDS:
            fail(f"unexpected version metadata key: {key!r}")
        if key in fields:
            fail(f"duplicate version metadata key: {key}")
        if not value:
            fail(f"empty version metadata value: {key}")
        fields[key] = value
    if set(fields) != set(FIELDS):
        fail("version metadata field set is incomplete")
    if fields["git_commit"] != expected_commit:
        fail("embedded git commit does not equal the exact hosted event commit")
    if fields["build_platform"] != expected_platform:
        fail("embedded build platform is not the exact native platform contract")
    if fields["report_schema_version"] != expected_schema:
        fail("embedded report schema does not equal the frozen schema contract")
    return product_match.group(1), fields


def self_test() -> int:
    commit = "a" * 40
    valid = (
        "auto-refirst 0.1.0-rc.1\n"
        f"git_commit={commit}\n"
        "build_platform=Linux/x86_64\n"
        "report_schema_version=1.0\n"
    )
    validate_version_output(
        valid,
        expected_commit=commit,
        expected_platform="Linux/x86_64",
        expected_schema="1.0",
    )
    mutations = (
        valid.replace(commit, commit + "-dirty"),
        valid.replace(commit, commit + "-status-unknown"),
        valid.replace(commit, "b" * 40),
        valid.replace("Linux/x86_64", "Linux/AMD64"),
        valid.replace("1.0", "1.1"),
        valid.replace("git_commit=", "source_commit="),
        valid.replace("build_platform=Linux/x86_64\n", ""),
        valid + "extra=value\n",
        valid.replace("report_schema_version=1.0", "git_commit=" + commit),
        valid.replace("auto-refirst 0.1.0-rc.1", "auto-refirst invalid version"),
    )
    for index, candidate in enumerate(mutations, start=1):
        try:
            validate_version_output(
                candidate,
                expected_commit=commit,
                expected_platform="Linux/x86_64",
                expected_schema="1.0",
            )
        except IdentityError:
            continue
        fail(f"identity mutation {index} was incorrectly accepted")
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-platform", required=True)
    parser.add_argument("--expected-schema", required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        mutation_count = self_test() if args.self_test else 0
        if not args.binary.is_file():
            fail(f"binary is not a regular file: {args.binary}")
        try:
            completed = subprocess.run(
                [str(args.binary), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            fail(f"cannot execute binary --version: {exc}")
        if completed.returncode != 0:
            fail(f"binary --version failed with exit code {completed.returncode}")
        if completed.stderr:
            fail("binary --version emitted stderr")
        product, fields = validate_version_output(
            completed.stdout,
            expected_commit=args.expected_commit,
            expected_platform=args.expected_platform,
            expected_schema=args.expected_schema,
        )
    except IdentityError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(
        "[PASS] exact build identity: "
        f"product={product} commit={fields['git_commit']} "
        f"platform={fields['build_platform']} schema={fields['report_schema_version']} "
        f"mutations={mutation_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
