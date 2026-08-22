#!/usr/bin/env python3
"""Mutation checks for the public runner's UTF-8 subprocess contract."""

from __future__ import annotations

import os
import sys

import run_public_regression as public_runner


def emit(stdout: bytes = b"", stderr: bytes = b"") -> list[str]:
    script = (
        "import os;"
        f"os.write(1, bytes.fromhex({stdout.hex()!r}));"
        f"os.write(2, bytes.fromhex({stderr.hex()!r}))"
    )
    return [sys.executable, "-c", script]


def expect_decode_failure(command: list[str], stream: str) -> None:
    try:
        public_runner.run(command)
    except AssertionError as exc:
        expected = f"command {stream} is not valid UTF-8"
        if expected not in str(exc):
            raise AssertionError(f"wrong UTF-8 failure for {stream}: {exc}") from exc
    else:
        raise AssertionError(f"invalid UTF-8 {stream} was accepted")


def expect_toolchain_decode_failure(command: list[str], stream: str, encoding: str) -> None:
    try:
        public_runner.run_toolchain(command, encoding=encoding)
    except AssertionError as exc:
        expected = f"toolchain command {stream} is not valid {encoding}"
        if expected not in str(exc):
            raise AssertionError(f"wrong toolchain decode failure for {stream}: {exc}") from exc
    else:
        raise AssertionError(f"invalid {encoding} toolchain {stream} was accepted")


def main() -> int:
    # Deliberately request a legacy child locale. os.write() keeps the fixture
    # bytes exact, proving the parent decoder does not inherit a host code page.
    env = dict(os.environ)
    env["PYTHONUTF8"] = "0"
    env["PYTHONIOENCODING"] = "cp936"
    stdout = "公开回归 ✓\n".encode("utf-8")
    stderr = "UTF-8 stderr ✓\n".encode("utf-8")
    completed = public_runner.run(emit(stdout, stderr), env=env)
    assert completed.stdout == stdout.decode("utf-8")
    assert completed.stderr == stderr.decode("utf-8")

    legacy_stdout = "编码".encode("cp936")
    expect_decode_failure(emit(stdout=legacy_stdout), "stdout")
    expect_decode_failure(emit(stderr=b"bad:\x80"), "stderr")

    localized = "正在生成代码".encode("cp936")
    tool = public_runner.run_toolchain(emit(stdout=localized), encoding="cp936")
    assert tool.stdout == localized.decode("cp936")
    expect_toolchain_decode_failure(emit(stderr=b"bad:\x81"), "stderr", "cp936")
    print("[PASS] public runner decoding: product/helper UTF-8 strict; localized toolchain diagnostics separated and strict")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
