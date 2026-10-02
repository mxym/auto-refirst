#!/usr/bin/env python3
"""Regression for fd-to-fd runtime payload transports.

The Linux runtime tracer must attribute the destination descriptor for
sendfile(2), splice(2), and vmsplice(2).  splice's output descriptor is the
third argument; treating every transport as args[0] silently loses the
runtime backing provenance and can make the subsequent executable mapping
look like an ordinary pre-existing file.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SOURCE = r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int make_destination(const char *path) {
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0700);
    if (fd < 0 || ftruncate(fd, 7) != 0) return -1;
    return fd;
}

static int run_payload(int fd) {
    void *rx = mmap(NULL, 7, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (rx == MAP_FAILED) return -1;
    close(fd);
    int value = ((int (*)(void))rx)();
    munmap(rx, 7);
    return value;
}

int main(void) {
    char source_path[] = "/tmp/auto-refirst-transport-source-XXXXXX";
    int source = mkstemp(source_path);
    if (source < 0) return 10;
    const unsigned char code[] = {0xb8, 43, 0, 0, 0, 0xc3, 0};
    if (write(source, code, sizeof(code)) != (ssize_t)sizeof(code)) return 11;
    if (lseek(source, 0, SEEK_SET) != 0) return 12;

    char sendfile_path[] = "/tmp/auto-refirst-transport-sendfile-XXXXXX";
    int sendfile_dst = mkstemp(sendfile_path);
    if (sendfile_dst < 0 || ftruncate(sendfile_dst, 7) != 0) return 13;
    /* Recreate the strict runtime-created backing after mkstemp's open. */
    close(sendfile_dst);
    unlink(sendfile_path);
    sendfile_dst = make_destination(sendfile_path);
    if (sendfile_dst < 0) return 14;
    off_t sendfile_offset = 0;
    if (syscall(SYS_sendfile, sendfile_dst, source, &sendfile_offset, 7) != 7) return 15;

    char splice_path[] = "/tmp/auto-refirst-transport-splice-XXXXXX";
    int splice_dst = mkstemp(splice_path);
    if (splice_dst < 0 || ftruncate(splice_dst, 7) != 0) return 16;
    close(splice_dst);
    unlink(splice_path);
    splice_dst = make_destination(splice_path);
    if (splice_dst < 0) return 17;
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0 || lseek(source, 0, SEEK_SET) != 0) return 18;
    off_t splice_in = 0;
    if (syscall(SYS_splice, source, &splice_in, pipe_fds[1], NULL, 7, 0) != 7) return 19;
    if (syscall(SYS_splice, pipe_fds[0], NULL, splice_dst, NULL, 7, 0) != 7) return 20;
    close(pipe_fds[0]);
    close(pipe_fds[1]);

    char vmsplice_path[] = "/tmp/auto-refirst-transport-vmsplice-XXXXXX";
    int vmsplice_dst = mkstemp(vmsplice_path);
    if (vmsplice_dst < 0 || ftruncate(vmsplice_dst, 7) != 0) return 21;
    close(vmsplice_dst);
    unlink(vmsplice_path);
    vmsplice_dst = make_destination(vmsplice_path);
    if (vmsplice_dst < 0 || pipe(pipe_fds) != 0) return 22;
    unsigned char first[] = {0xb8, 43, 0};
    unsigned char second[] = {0, 0, 0, 0xc3};
    struct iovec vectors[] = {{first, sizeof(first)}, {second, sizeof(second)}};
    if (syscall(SYS_vmsplice, pipe_fds[1], vectors, 2, 0) != 7) return 23;
    if (syscall(SYS_splice, pipe_fds[0], NULL, vmsplice_dst, NULL, 7, 0) != 7) return 24;
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(source);
    unlink(source_path);

    int result = run_payload(sendfile_dst);
    if (result != 43) return 25;
    result = run_payload(splice_dst);
    if (result != 43) return 26;
    result = run_payload(vmsplice_dst);
    if (result != 43) return 27;
    unlink(sendfile_path);
    unlink(splice_path);
    unlink(vmsplice_path);
    return 0;
}
'''


def main() -> int:
    if sys.platform != "linux":
        print("[SKIP] Linux runtime backend")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_runtime_transport_backing.py AUTO_REFIRST")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        print("[SKIP] no C compiler")
        return 0
    with tempfile.TemporaryDirectory(prefix="auto-refirst-runtime-transport-") as td:
        root = Path(td)
        source, fixture = root / "transport.c", root / "transport"
        source.write_text(SOURCE)
        cp = subprocess.run([cc, "-O2", "-Wall", str(source), "-o", str(fixture)],
                            capture_output=True, text=True)
        if cp.returncode:
            raise AssertionError(cp.stderr)
        cp = subprocess.run(
            [sys.argv[1], str(fixture), "--run", "--timeout=5000",
             f"--artifact-root={root/'run'/'artifacts'}", "--json"],
            capture_output=True, text=True, timeout=30,
        )
        if cp.returncode:
            raise AssertionError(cp.stderr or cp.stdout)
        report = json.loads(cp.stdout)
        events = report["runtime"]["timeline"]
        writes = {
            e.get("fields", {}).get("source"): e
            for e in events
            if e.get("kind") == "file_write"
            and e.get("fields", {}).get("source") == "sendfile"
        }
        splice_events = [
            e for e in events
            if e.get("kind") == "file_write"
            and e.get("fields", {}).get("source") == "splice"
        ]
        assert writes.keys() == {"sendfile"}, events
        assert len(splice_events) >= 2, events
        sendfile = writes["sendfile"]["fields"]
        assert sendfile.get("source_fd") is not None
        assert sendfile.get("transfer_bytes_requested") == "7", sendfile
        plain_splices = [
            e["fields"] for e in splice_events
            if "upstream_transport" not in e.get("fields", {})
        ]
        assert plain_splices, splice_events
        splice = plain_splices[0]
        assert splice.get("source_fd") is not None
        assert splice.get("transfer_bytes_requested") == "7", splice
        assert splice.get("splice_flags") == "0x0", splice
        # vmsplice writes the pipe, not the tracked file.  Its provenance is
        # carried through the pipe inode and appears on the subsequent splice.
        vmsplice_splices = [
            e["fields"] for e in splice_events
            if e.get("fields", {}).get("upstream_transport") == "vmsplice"
        ]
        assert vmsplice_splices, splice_events
        vmsplice = vmsplice_splices[0]
        assert vmsplice.get("upstream_written_bytes") == "7", vmsplice
        assert vmsplice.get("upstream_iov_count") == "2", vmsplice
        assert vmsplice.get("upstream_pipe_inode"), vmsplice
        backing_maps = [
            e for e in events
            if e.get("kind") == "memory_allocate"
            and e.get("fields", {}).get("backing_kind") == "runtime_released_file"
            and e.get("fields", {}).get("requested_prot") == "0x5"
        ]
        assert len(backing_maps) >= 3, events
    print("[PASS] sendfile/splice/vmsplice destination backing provenance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
