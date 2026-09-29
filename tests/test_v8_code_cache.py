#!/usr/bin/env python3
"""Exercise V8 code-cache routing through the product binary."""
import json
import pathlib
import struct
import subprocess
import sys
import tempfile


def cache_bytes() -> bytes:
    out = bytearray(32 + 64)
    for offset, value in (
        (0, 0xC0DE0688),
        (4, 0xDC338CFA),
        (8, 17 | (1 << 29)),
        (12, 0x5FB11F89),
        (16, 0x5CFB0532),
        (20, 64),
        (24, 0),
    ):
        struct.pack_into("<I", out, offset, value)
    return bytes(out)


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="ar-v8-cache-") as temp:
        path = pathlib.Path(temp) / "renamed.data"
        path.write_bytes(cache_bytes())
        report = subprocess.run([str(binary), str(path), "--json"], capture_output=True, check=True, timeout=30)
        obj = json.loads(report.stdout.decode("utf-8"))
        assert obj["format"]["kind"] == "V8 JavaScript code cache", obj["format"]
        assert obj["v8_code_cache"]["valid"] is True, obj["v8_code_cache"]
        finding = next(x for x in obj["findings"] if x["family"] == "V8 JavaScript code cache")
        assert finding["state"] == "LIKELY", finding
        assert finding["fields"]["payload_offset"] == "32", finding
        text = subprocess.run([str(binary), str(path)], capture_output=True, check=True, timeout=30).stdout.decode("utf-8")
        assert "Format: V8 JavaScript code cache" in text, text
        assert "serialized payload remains opaque" in text, text
    print("[PASS] V8 code-cache header routing, JSON, text, and opaque-payload contract")


if __name__ == "__main__":
    main()
