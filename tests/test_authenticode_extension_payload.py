#!/usr/bin/env python3
"""Focused contract test for the bounded PE certificate-extension triage.

The fixture is synthetic and does not contain a real signer.  It only checks
that a private-enterprise DER extension carrying opaque bytes is surfaced as a
low-confidence file-offset hint, while short/malformed/similar inputs remain
quiet and the output is capped when many candidates are present.
"""
import json
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import minimal_pe


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + der_len(len(payload)) + payload


def extension(payload: bytes, *, oid: bytes = bytes.fromhex("2b060104018a3901")) -> bytes:
    return der(0x30, der(0x06, oid) + der(0x04, payload))


def certificate_carrier(entries: list[bytes]) -> bytes:
    """Attach one or more synthetic WIN_CERTIFICATE entries to minimal_pe."""
    image = bytearray(minimal_pe())
    cert_offset = (len(image) + 7) & ~7
    table = bytearray()
    for blob in entries:
        record = struct.pack("<IHH", 8 + len(blob), 0x0200, 2) + blob
        table.extend(record)
        table.extend(b"\0" * ((-len(record)) & 7))
    image.extend(b"\0" * (cert_offset - len(image)))
    image.extend(table)
    directory = 0x98 + 96 + 4 * 8
    struct.pack_into("<II", image, directory, cert_offset, len(table))
    return bytes(image)


def run(binary: pathlib.Path, sample: bytes, root: pathlib.Path, name: str) -> dict:
    path = root / name
    path.write_bytes(sample)
    cp = subprocess.run([str(binary), str(path), "--json"], check=True,
                        capture_output=True, timeout=30)
    return json.loads(cp.stdout.decode("utf-8"))


def payload_finding(report: dict) -> dict | None:
    return next((f for f in report["findings"]
                 if f["family"] == "PE Authenticode extension payload"), None)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_authenticode_extension_payload.py <auto-refirst>")
    binary = pathlib.Path(sys.argv[1]).resolve()
    # A DER sequence makes the positive payload look like a nested container,
    # but no challenge-specific OID or module bytes are embedded in the test.
    nested = der(0x30, der(0x02, b"\x01") + der(0x04, b"A" * 320))
    positive = run(binary, certificate_carrier([extension(nested)]),
                   pathlib.Path(tempfile.mkdtemp(prefix="ar-cert-ext-")), "positive.bin")
    finding = payload_finding(positive)
    assert finding is not None, positive["findings"]
    assert finding["state"] == "SUSPECTED" and finding["confidence"] < 0.5
    assert finding["fields"]["candidate_count"] == "1"
    assert finding["ranges"][0]["coordinate_space"] == "FILE_OFFSET"
    assert finding["ranges"][0]["basis"] == "CURRENT_INPUT_FILE"
    assert int(finding["fields"]["payload_bytes"]) >= 320
    extraction = positive["authenticode"]["extraction"]
    assert extraction["success"] and extraction["written_count"] == 1, extraction
    assert (pathlib.Path(extraction["output_dir"]) / "extension-0.der").read_bytes() == nested

    # A valid private OID with only a short value is common metadata, not a
    # payload candidate.  A truncated DER carrier must also fail closed.
    short = run(binary, certificate_carrier([extension(b"B" * 255)]),
                pathlib.Path(tempfile.mkdtemp(prefix="ar-cert-short-")), "short.bin")
    assert payload_finding(short) is None, short["findings"]
    public_oid = run(binary, certificate_carrier([extension(b"P" * 320, oid=bytes.fromhex("551d13"))]),
                      pathlib.Path(tempfile.mkdtemp(prefix="ar-cert-public-")), "public.bin")
    assert payload_finding(public_oid) is None, public_oid["findings"]
    malformed = certificate_carrier([b"\x30\x82\xff"])
    bad = run(binary, malformed, pathlib.Path(tempfile.mkdtemp(prefix="ar-cert-bad-")), "bad.bin")
    assert payload_finding(bad) is None, bad["findings"]

    # Candidate output is bounded even when the certificate carries many
    # independently valid extension records.
    capped = run(binary, certificate_carrier([extension(b"C" * 256) for _ in range(40)]),
                 pathlib.Path(tempfile.mkdtemp(prefix="ar-cert-cap-")), "cap.bin")
    cap_finding = payload_finding(capped)
    assert cap_finding is not None
    assert cap_finding["fields"]["candidate_count"] == "32"
    assert len(cap_finding["ranges"]) == 32
    assert int(cap_finding["fields"]["der_node_budget"]) == 4096
    assert int(cap_finding["fields"]["der_scan_bytes_cap"]) == 16 * 1024 * 1024
    print("[PASS] bounded Authenticode extension payload hint: positive, short/malformed negatives, 32-candidate cap")


if __name__ == "__main__":
    main()
