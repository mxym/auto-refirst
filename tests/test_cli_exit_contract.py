#!/usr/bin/env python3
import contextlib
import ctypes
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

AR = pathlib.Path(sys.argv[1]).resolve()


def run(*args):
    return subprocess.run(
        [str(AR), *map(str, args)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
    )


@contextlib.contextmanager
def deny_read(path):
    """Keep metadata visible while denying the analyzer's data-open request."""
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        handle = create_file(str(path), 0x80000000, 0, None, 3, 0x80, None)
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            raise OSError(ctypes.get_last_error(), "CreateFileW share-denial fixture failed")
        try:
            yield
        finally:
            if not close_handle(handle):
                raise OSError(ctypes.get_last_error(), "CloseHandle failed")
        return

    old_mode = stat.S_IMODE(path.stat().st_mode)
    path.chmod(0)
    try:
        try:
            with path.open("rb"):
                pass
        except PermissionError:
            pass
        else:
            raise AssertionError("chmod(000) did not deny reads for this test identity")
        yield
    finally:
        path.chmod(old_mode)


def assert_input_failure(path):
    cp = run(path, "--json")
    assert cp.returncode == 3, (path, cp.returncode, cp.stdout[-1000:], cp.stderr[-1000:])


def main():
    assert AR.is_file(), AR
    with tempfile.TemporaryDirectory(prefix="auto-refirst-exit-contract-") as raw:
        td = pathlib.Path(raw)

        empty = td / "empty.bin"
        empty.write_bytes(b"")
        cp = run(empty, "--json")
        assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
        empty_report = json.loads(cp.stdout)
        assert empty_report["size"] == 0 and empty_report["sha256"]

        malformed = td / "malformed.asar"
        malformed.write_bytes(b"not an asar container")
        cp = run(malformed, "--json")
        assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
        report = json.loads(cp.stdout)
        failures = [
            f for f in report["findings"]
            if f["family"] == "Electron ASAR" and f["state"] == "FAILED"
        ]
        assert len(failures) == 1, failures

        blocked_root = td / "blocked-root.bin"
        blocked_root.write_bytes(b"source-generated blocked root")
        with deny_read(blocked_root):
            assert_input_failure(blocked_root)

        mixed = td / "mixed"
        mixed.mkdir()
        (mixed / "good.bin").write_bytes(b"source-generated readable child")
        blocked_child = mixed / "blocked.bin"
        blocked_child.write_bytes(b"source-generated blocked child")
        with deny_read(blocked_child):
            cp = run(mixed, "--json")
            assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
            directory = json.loads(cp.stdout)
            summary = directory["directory_summary"]
            assert summary["total_files"] == 2, summary
            assert summary["analyzed_files"] == 1 and summary["skipped_files"] == 1, summary

            only_blocked = td / "only-blocked"
            only_blocked.mkdir()
            second_blocked = only_blocked / "blocked.bin"
            second_blocked.write_bytes(b"source-generated blocked child")
            with deny_read(second_blocked):
                assert_input_failure(only_blocked)

    print("[PASS] CLI exit taxonomy: empty/suspicious success + root/open failure + mixed directory")


if __name__ == "__main__":
    main()
