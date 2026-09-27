#!/usr/bin/env python3
"""Bounded parent-PE to exact embedded-PE loader-route checks."""

import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe, put16, put32


def parent(*, bridge: bool) -> bytes:
    data = bytearray(minimal_pe())
    optional = 0x98
    raw = lambda rva: 0x200 + (rva - 0x1000)
    data.extend(b"\0" * 0x400)
    section = optional + 224
    put32(data, section + 8, 0x800)
    put32(data, section + 16, 0x800)
    put32(data, optional + 96 + 16, 0x1300)  # IMAGE_DIRECTORY_ENTRY_RESOURCE
    put32(data, optional + 96 + 20, 0x40)

    names = ["FindResourceW", "LoadResource", "LockResource"]
    if bridge:
        names += ["CreateProcessW", "WriteFile"]
    descriptor = raw(0x1180)
    int_rva, iat_rva = 0x11C0, 0x11F0
    put32(data, optional + 96 + 8, 0x1180)  # IMAGE_DIRECTORY_ENTRY_IMPORT
    put32(data, optional + 96 + 12, 0x80)
    put32(data, descriptor + 0, int_rva)
    put32(data, descriptor + 12, 0x11E0)
    put32(data, descriptor + 16, iat_rva)
    data[raw(0x11E0):raw(0x11E0) + 13] = b"kernel32.dll\0"
    name_rva = 0x1230
    for index, name in enumerate(names):
        hint_name = raw(name_rva)
        put16(data, hint_name, 0)
        data[hint_name + 2:hint_name + 2 + len(name) + 1] = name.encode() + b"\0"
        put32(data, raw(int_rva) + index * 4, name_rva)
        put32(data, raw(iat_rva) + index * 4, name_rva)
        name_rva += 2 + len(name) + 1
    child = minimal_pe()
    child_offset = 0xA00
    if len(data) < child_offset:
        data.extend(b"\0" * (child_offset - len(data)))
    data[child_offset:child_offset + len(child)] = child
    return bytes(data[:child_offset + len(child)])


def report(binary: pathlib.Path, payload: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-nested-route-") as raw:
        path = pathlib.Path(raw) / "loader.exe"
        path.write_bytes(payload)
        completed = subprocess.run(
            [str(binary), str(path), "--json"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return json.loads(completed.stdout.decode("utf-8"))


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    positive = report(binary, parent(bridge=True))
    routes = [x for x in positive["artifact_relationships"] if x["kind"] == "pe_embedded_loader_route"]
    assert len(routes) == 1, routes
    route = routes[0]
    assert route["state"] == "ROUTE_HINT", route
    assert route["evidence_level"] == "R1_ROUTING_HINT", route
    assert route["priority_eligible"] is False, route
    assert "CreateProcessW" in route["source_coordinate"], route
    finding = next(x for x in positive["findings"] if x["family"] == "Embedded executable loader route")
    assert finding["state"] == "ROUTE_HINT", finding
    assert finding["fields"]["resource_identity"] == "UNRESOLVED", finding
    assert finding["fields"]["argument_flow"] == "UNRESOLVED", finding
    assert any(x.get("relation") == "embedded_executable" for x in positive["artifacts"]), positive["artifacts"]

    negative = report(binary, parent(bridge=False))
    assert not any(x["kind"] == "pe_embedded_loader_route" for x in negative["artifact_relationships"]), negative
    assert not any(x["family"] == "Embedded executable loader route" for x in negative["findings"]), negative
    print("[PASS] bounded PE resource/bridge to exact embedded-PE route hint and negative boundary")


if __name__ == "__main__":
    main()
