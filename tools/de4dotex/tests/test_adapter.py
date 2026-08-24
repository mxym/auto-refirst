#!/usr/bin/env python3
"""Fault-oriented tests for the narrow Linux sidecar adapter."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import importlib.util


HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent / "adapter.py"
MOCK_SOURCE = HERE / "mock_de4dot.c"
SPEC = importlib.util.spec_from_file_location("de4dotex_adapter_under_test", ADAPTER)
assert SPEC is not None and SPEC.loader is not None
ADAPTER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER_MODULE)


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def tree_identity(root: Path) -> tuple[str, int, int]:
    rows: list[bytes] = []
    count = 0
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if not path.is_file():
            continue
        digest, size = sha256_file(path)
        rows.append(f"{digest} {size} {path.relative_to(root).as_posix()}\n".encode())
        count += 1
        total += size
    return hashlib.sha256(b"".join(rows)).hexdigest(), count, total


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise unittest.SkipTest("Linux/x86_64 sandbox test only")
        bwrap_value = os.environ.get("DE4DOTEX_TEST_BWRAP", "")
        cls.bwrap = Path(bwrap_value)
        if not cls.bwrap.is_file():
            raise unittest.SkipTest("set DE4DOTEX_TEST_BWRAP to the audited test bubblewrap")
        cls.suite_temp = tempfile.TemporaryDirectory(prefix="de4dotex-adapter-tests-")
        cls.suite_root = Path(cls.suite_temp.name)
        cls.mock_binary = cls.suite_root / "mock-de4dot"
        subprocess.run(
            ["cc", "-O2", "-Wall", "-Wextra", "-Werror", str(MOCK_SOURCE), "-o", str(cls.mock_binary)],
            check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "suite_temp"):
            cls.suite_temp.cleanup()

    def setUp(self) -> None:
        self.case_temp = tempfile.TemporaryDirectory(prefix="case-", dir=self.suite_root)
        self.root = Path(self.case_temp.name)
        self.tool_root = self.root / "tool"
        self.tool_root.mkdir()
        shutil.copy2(self.mock_binary, self.tool_root / "de4dot")
        (self.tool_root / "de4dot").chmod(0o755)
        tree_hash, tree_files, tree_bytes = tree_identity(self.tool_root)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({
            "schema_version": 1,
            "provider": "de4dotex",
            "enabled_by_default": False,
            "entrypoint": "de4dot",
            "platform": {"contract": "Linux/x86_64"},
            "release": {
                "version": "3.8.0",
                "reported_version": "3.8.0.0",
                "commit": "2b03ac6e85ca26556da694dedb01e72aad222902",
                "asset": {"sha256": "test-only"},
            },
            "installed_tree": {"sha256": tree_hash, "files": tree_files, "bytes": tree_bytes},
            "sandbox": {
                "minimum_version": "0.6.1",
                "launcher_trust": {"model": "root-owned-system-dependency", "sha256": None},
                "system_abi_ro_binds": ["/lib", "/lib64", "/usr/lib"],
                "require_cgroup_v2_hard_limits": True,
            },
            "limits": {
                "timeout_ms": 1000,
                "physical_memory_bytes": 134217728,
                "swap_bytes": 0,
                "address_space_bytes": 536870912,
                "gc_heap_hard_limit_bytes": 67108864,
                "input_bytes": 1048576,
                "output_bytes": 65536,
                "log_bytes": 8192,
                "output_files": 4,
                "processes": 256,
            },
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self.case_temp.cleanup()

    def prepare(self, mode_byte: bytes = b"Nfixture") -> tuple[Path, Path]:
        target = self.root / "target.dll"
        target.write_bytes(mode_byte)
        target_hash, target_size = sha256_file(target)
        authorization = self.root / "authorization.json"
        authorization.write_text(json.dumps({
            "schema": "auto-refirst.target-execution-authorization.v1",
            "authorization_source": "explicit --run",
            "runtime_execution_authorized": True,
            "static_evidence_only": False,
            "target_sha256": target_hash,
            "target_size": target_size,
        }), encoding="utf-8")
        return target, authorization

    def invoke(
        self,
        mode_byte: bytes = b"Nfixture",
        *,
        mode: str = "detect",
        authorization: Path | None = None,
        target: Path | None = None,
        output_name: str = "result",
        pin_manifest: bool = True,
    ) -> dict:
        if target is None or authorization is None:
            prepared_target, prepared_authorization = self.prepare(mode_byte)
            target = target or prepared_target
            authorization = authorization or prepared_authorization
        arguments = [
            "--manifest", str(self.manifest),
            "--tool-root", str(self.tool_root),
            "--bwrap", str(self.bwrap),
            "--authorization", str(authorization),
            "--input", str(target),
            "--output-dir", str(self.root / output_name),
            "--mode", mode,
        ]
        cgroup_proof = {
            "version": 2,
            "path": "/unit-test",
            "memory_max": 134217728,
            "memory_swap_max": 0,
            "pids_max": 256,
            "inherited_by_process_tree": True,
        }
        launcher_proof = {
            "version": "0.6.1",
            "sha256": sha256_file(self.bwrap)[0],
            "size": self.bwrap.stat().st_size,
            "trust_model": "test-proof",
            "digest_pinned": True,
        }
        with mock.patch.object(ADAPTER_MODULE, "validate_hard_cgroup", return_value=cgroup_proof), \
                mock.patch.object(ADAPTER_MODULE, "validate_immutable_tool_tree"), \
                mock.patch.object(
                    ADAPTER_MODULE, "validate_sandbox_launcher",
                    return_value=(self.bwrap, launcher_proof),
                ):
            if pin_manifest:
                manifest_hash = sha256_file(self.manifest)[0]
                with mock.patch.object(ADAPTER_MODULE, "PINNED_MANIFEST_SHA256", manifest_hash):
                    return ADAPTER_MODULE.run(arguments)
            return ADAPTER_MODULE.run(arguments)

    def assert_partial(self, result: dict, code: str) -> None:
        self.assertEqual(result["state"], "PARTIAL")
        self.assertEqual(result["reason_code"], code)

    def test_successful_detector_is_complete(self) -> None:
        result = self.invoke()
        self.assertEqual(result["state"], "COMPLETE")
        self.assertEqual(result["reason_code"], "DETECTION_COMPLETED")
        self.assertEqual(result["detector"]["name"], "Obfuscar")
        self.assertTrue(result["attempted"])

    def test_untrusted_manifest_is_rejected(self) -> None:
        result = self.invoke(output_name="untrusted-manifest", pin_manifest=False)
        self.assert_partial(result, "MANIFEST_UNTRUSTED")
        self.assertFalse(result["attempted"])

    def test_root_invoker_is_rejected(self) -> None:
        with mock.patch.object(ADAPTER_MODULE.os, "geteuid", return_value=0):
            result = self.invoke(output_name="root-invoker")
        self.assert_partial(result, "UNSAFE_INVOKER_IDENTITY")
        self.assertFalse(result["attempted"])

    def test_user_owned_tool_tree_is_rejected(self) -> None:
        with self.assertRaises(ADAPTER_MODULE.AdapterError) as caught:
            ADAPTER_MODULE.validate_immutable_tool_tree(self.tool_root)
        self.assertEqual(caught.exception.code, "TOOL_TREE_NOT_IMMUTABLE")

    def test_user_owned_launcher_is_rejected_before_probe(self) -> None:
        sandbox = {"minimum_version": "0.6.1", "launcher_trust": {
            "model": "root-owned-system-dependency", "sha256": None,
        }}
        with mock.patch.object(ADAPTER_MODULE.subprocess, "run") as probe:
            with self.assertRaises(ADAPTER_MODULE.AdapterError) as caught:
                ADAPTER_MODULE.validate_sandbox_launcher(self.bwrap, sandbox)
        self.assertEqual(caught.exception.code, "SANDBOX_UNAVAILABLE")
        probe.assert_not_called()

    def test_unbounded_cgroup_is_rejected(self) -> None:
        fake_root = self.root / "fake-cgroup"
        fake_group = fake_root / "unit"
        fake_group.mkdir(parents=True)
        (fake_group / "memory.max").write_text("max\n", encoding="ascii")
        (fake_group / "memory.swap.max").write_text("0\n", encoding="ascii")
        (fake_group / "pids.max").write_text("256\n", encoding="ascii")
        membership = self.root / "cgroup-membership"
        membership.write_text("0::/unit\n", encoding="ascii")
        with mock.patch.object(ADAPTER_MODULE, "CGROUP_ROOT", fake_root), mock.patch.object(
            ADAPTER_MODULE, "PROC_SELF_CGROUP", membership
        ):
            with self.assertRaises(ADAPTER_MODULE.AdapterError) as caught:
                ADAPTER_MODULE.validate_hard_cgroup(134217728, 0, 256)
        self.assertEqual(caught.exception.code, "HARD_RESOURCE_SANDBOX_UNAVAILABLE")

    def test_bounded_cgroup_is_accepted(self) -> None:
        fake_root = self.root / "fake-cgroup"
        fake_group = fake_root / "unit"
        fake_group.mkdir(parents=True)
        (fake_group / "memory.max").write_text("134217728\n", encoding="ascii")
        (fake_group / "memory.swap.max").write_text("0\n", encoding="ascii")
        (fake_group / "pids.max").write_text("128\n", encoding="ascii")
        membership = self.root / "cgroup-membership"
        membership.write_text("0::/unit\n", encoding="ascii")
        with mock.patch.object(ADAPTER_MODULE, "CGROUP_ROOT", fake_root), mock.patch.object(
            ADAPTER_MODULE, "PROC_SELF_CGROUP", membership
        ):
            proof = ADAPTER_MODULE.validate_hard_cgroup(134217728, 0, 256)
        self.assertEqual(proof["memory_max"], 134217728)
        self.assertEqual(proof["memory_swap_max"], 0)
        self.assertEqual(proof["pids_max"], 128)

    def test_unbounded_swap_is_rejected(self) -> None:
        fake_root = self.root / "fake-cgroup"
        fake_group = fake_root / "unit"
        fake_group.mkdir(parents=True)
        (fake_group / "memory.max").write_text("134217728\n", encoding="ascii")
        (fake_group / "memory.swap.max").write_text("max\n", encoding="ascii")
        (fake_group / "pids.max").write_text("128\n", encoding="ascii")
        membership = self.root / "cgroup-membership"
        membership.write_text("0::/unit\n", encoding="ascii")
        with mock.patch.object(ADAPTER_MODULE, "CGROUP_ROOT", fake_root), mock.patch.object(
            ADAPTER_MODULE, "PROC_SELF_CGROUP", membership
        ):
            with self.assertRaises(ADAPTER_MODULE.AdapterError) as caught:
                ADAPTER_MODULE.validate_hard_cgroup(134217728, 0, 256)
        self.assertEqual(caught.exception.code, "HARD_RESOURCE_SANDBOX_UNAVAILABLE")

    def test_deobfuscation_output_requires_core_reparse(self) -> None:
        result = self.invoke(mode="deobfuscate")
        self.assert_partial(result, "PENDING_CORE_REPARSE")
        self.assertTrue(result["requires_core_reparse"])
        self.assertEqual(result["artifacts"][0]["relative_path"], "cleaned.dll")

    def test_missing_tool_is_partial(self) -> None:
        target, authorization = self.prepare()
        shutil.rmtree(self.tool_root)
        result = self.invoke(target=target, authorization=authorization, output_name="missing-tool")
        self.assert_partial(result, "TOOL_MISSING")
        self.assertFalse(result["attempted"])

    def test_tool_tree_hash_mismatch_is_partial(self) -> None:
        (self.tool_root / "unexpected").write_text("changed", encoding="utf-8")
        self.assert_partial(self.invoke(output_name="tree-mismatch"), "TOOL_TREE_MISMATCH")

    def test_missing_authorization_is_partial(self) -> None:
        missing = self.root / "does-not-exist.json"
        self.assert_partial(self.invoke(authorization=missing, output_name="missing-auth"), "AUTHORIZATION_INVALID")

    def test_execution_authorization_is_required(self) -> None:
        target, authorization = self.prepare()
        value = json.loads(authorization.read_text(encoding="utf-8"))
        value["runtime_execution_authorized"] = False
        authorization.write_text(json.dumps(value), encoding="utf-8")
        result = self.invoke(target=target, authorization=authorization, output_name="denied")
        self.assert_partial(result, "RUNTIME_EXECUTION_NOT_AUTHORIZED")

    def test_authorization_target_hash_must_match(self) -> None:
        target, authorization = self.prepare()
        value = json.loads(authorization.read_text(encoding="utf-8"))
        value["target_sha256"] = "0" * 64
        authorization.write_text(json.dumps(value), encoding="utf-8")
        result = self.invoke(target=target, authorization=authorization, output_name="hash-mismatch")
        self.assert_partial(result, "AUTHORIZATION_TARGET_MISMATCH")

    def test_authorization_unknown_field_is_rejected(self) -> None:
        target, authorization = self.prepare()
        value = json.loads(authorization.read_text(encoding="utf-8"))
        value["future_semantics"] = True
        authorization.write_text(json.dumps(value), encoding="utf-8")
        result = self.invoke(target=target, authorization=authorization, output_name="unknown-auth-field")
        self.assert_partial(result, "AUTHORIZATION_INVALID")

    def test_timeout_is_partial(self) -> None:
        self.assert_partial(self.invoke(b"Tfixture", output_name="timeout"), "TIMEOUT")

    def test_crash_is_partial(self) -> None:
        self.assert_partial(self.invoke(b"Cfixture", output_name="crash"), "TOOL_CRASH")

    def test_monitor_exception_is_partial_after_attempt(self) -> None:
        with mock.patch.object(ADAPTER_MODULE, "output_usage", side_effect=RuntimeError("monitor fault")):
            result = self.invoke(b"Tfixture", output_name="monitor-fault")
        self.assert_partial(result, "ADAPTER_INTERNAL_ERROR")
        self.assertTrue(result["attempted"])

    def test_oversized_log_is_partial(self) -> None:
        self.assert_partial(self.invoke(b"Ofixture", output_name="oversize"), "OVERSIZED_OUTPUT")

    def test_malformed_output_is_partial(self) -> None:
        self.assert_partial(self.invoke(b"Mfixture", output_name="malformed"), "MALFORMED_OUTPUT")

    def test_runtime_version_mismatch_is_partial(self) -> None:
        self.assert_partial(self.invoke(b"Vfixture", output_name="version-mismatch"), "TOOL_VERSION_MISMATCH")

    def test_symlink_output_is_partial(self) -> None:
        self.assert_partial(self.invoke(b"Sfixture", mode="deobfuscate", output_name="symlink"), "UNSAFE_OUTPUT")


if __name__ == "__main__":
    unittest.main(verbosity=2)
