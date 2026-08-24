#!/usr/bin/env python3
"""Cross-platform import and fail-closed host-boundary tests."""

from __future__ import annotations

from contextlib import redirect_stdout
import builtins
import importlib.util
from io import StringIO
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent / "adapter.py"


def load_without_resource():
    spec = importlib.util.spec_from_file_location(
        "de4dotex_adapter_without_resource", ADAPTER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    real_import = builtins.__import__

    def import_without_resource(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "resource":
            raise ModuleNotFoundError("No module named 'resource'", name="resource")
        return real_import(name, globals, locals, fromlist, level)

    with mock.patch("builtins.__import__", side_effect=import_without_resource):
        spec.loader.exec_module(module)
    return module


class PortabilityTests(unittest.TestCase):
    def test_import_succeeds_when_resource_module_is_unavailable(self) -> None:
        adapter = load_without_resource()
        self.assertIsNone(adapter.resource)

    def test_help_succeeds_in_a_real_subprocess(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ADAPTER), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--manifest", completed.stdout)

    def test_help_succeeds_when_resource_module_is_unavailable(self) -> None:
        adapter = load_without_resource()
        output = StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            adapter.parse_args(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("--manifest", output.getvalue())

    def test_windows_run_is_rejected_before_any_process_spawn(self) -> None:
        adapter = load_without_resource()
        arguments = [
            "--manifest", r"C:\\analysis\\manifest.json",
            "--tool-root", r"C:\\tools\\de4dotex",
            "--bwrap", r"C:\\tools\\bwrap.exe",
            "--authorization", r"C:\\analysis\\authorization.json",
            "--input", r"C:\\analysis\\target.dll",
            "--output-dir", r"C:\\analysis\\result",
            "--mode", "detect",
        ]
        with mock.patch.object(adapter.platform, "system", return_value="Windows"), \
                mock.patch.object(adapter.platform, "machine", return_value="AMD64"), \
                mock.patch.object(adapter.subprocess, "run") as probe, \
                mock.patch.object(adapter.subprocess, "Popen") as launch:
            result = adapter.run(arguments)

        self.assertEqual(result["state"], "PARTIAL")
        self.assertEqual(result["reason_code"], "PLATFORM_MISMATCH")
        self.assertFalse(result["attempted"])
        self.assertEqual(result["mode"], "detect")
        probe.assert_not_called()
        launch.assert_not_called()

    def test_missing_resource_preexec_is_fail_closed(self) -> None:
        adapter = load_without_resource()
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter.make_preexec(1, 1, 1, 1)
        self.assertEqual(caught.exception.code, "PLATFORM_MISMATCH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
