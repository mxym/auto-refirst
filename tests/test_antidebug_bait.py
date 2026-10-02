#!/usr/bin/env python3
"""Small PE64 anti-debug contract and marker-bait regression.

The fixture intentionally uses a valid exception directory and a real x64
RUNTIME_FUNCTION so the detector has a function boundary.  It is never
executed.  In particular, an imported anti-debug name (or an embedded PDB
marker) must not be promoted to a finding until a call/instruction is
localized.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def p16(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<H", buf, off, value)


def p32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value)


def p64(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<Q", buf, off, value)


def pe64(*, code: bytes, imports: tuple[str, ...] = (), pdb_marker: bool = False,
         tls_callback: bool = False, context_flags: int = 0) -> bytes:
    """Build one bounded PE64 image containing code/imports/.pdata.

    All RVA-bearing structures live in one raw section.  This keeps the
    fixture readable while still exercising the production parser's import,
    exception and instruction-coordinate paths.
    """

    image = bytearray(0x3200)
    image[:2] = b"MZ"
    p32(image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    p16(image, 0x84, 0x8664)  # AMD64
    p16(image, 0x86, 1)
    p16(image, 0x94, 240)
    p16(image, 0x96, 0x2022)

    opt = 0x98
    p16(image, opt, 0x20B)
    p32(image, opt + 4, 0x3000)
    p32(image, opt + 16, 0x1000)
    p32(image, opt + 20, 0x1000)
    p64(image, opt + 24, 0x140000000)
    p32(image, opt + 32, 0x1000)
    p32(image, opt + 36, 0x200)
    p32(image, opt + 56, 0x4000)
    p32(image, opt + 60, 0x200)
    p16(image, opt + 68, 3)
    p32(image, opt + 72, 0x100000)
    p32(image, opt + 76, 0x1000)
    p32(image, opt + 80, 0x100000)
    p32(image, opt + 84, 0x1000)
    p32(image, opt + 108, 16)

    # Section: executable and readable; raw offset 0x200 maps RVA 0x1000.
    section = opt + 240
    image[section:section + 8] = b".all\0\0\0\0"
    p32(image, section + 8, 0x3000)
    p32(image, section + 12, 0x1000)
    p32(image, section + 16, 0x3000)
    p32(image, section + 20, 0x200)
    p32(image, section + 36, 0x60000020)

    raw = lambda rva: 0x200 + (rva - 0x1000)
    image[raw(0x1000):raw(0x1000) + len(code)] = code

    # Exception directory: one RUNTIME_FUNCTION [0x1000, 0x1100), followed by
    # a minimal version-1 unwind record.  The detector will decode only the
    # file-backed function bytes.
    p32(image, opt + 112 + 3 * 8, 0x3000)
    p32(image, opt + 112 + 3 * 8 + 4, 12)
    p32(image, raw(0x3000) + 0, 0x1000)
    p32(image, raw(0x3000) + 4, 0x1100)
    p32(image, raw(0x3000) + 8, 0x3100)
    image[raw(0x3100):raw(0x3100) + 4] = b"\x01\x00\x00\x00"

    if tls_callback:
        # IMAGE_TLS_DIRECTORY64 and a null-terminated callback VA array.
        # The callback points at the same bounded code function; the fixture
        # is static-only and does not claim that this callback is benign.
        p32(image, opt + 112 + 9 * 8, 0x2400)
        p32(image, opt + 112 + 9 * 8 + 4, 40)
        p64(image, raw(0x2400) + 0, 0x140001000)
        p64(image, raw(0x2400) + 8, 0x140001000)
        p64(image, raw(0x2400) + 16, 0x140002480)
        p64(image, raw(0x2400) + 24, 0x140002500)
        p32(image, raw(0x2400) + 32, 0)
        p32(image, raw(0x2400) + 36, 0)
        p64(image, raw(0x2500), 0x140001000)
        p64(image, raw(0x2500) + 8, 0)

    if imports:
        # One kernel32 descriptor and 8-byte PE64 INT/IAT entries.
        p32(image, opt + 112 + 1 * 8, 0x2000)
        p32(image, opt + 112 + 1 * 8 + 4, 0x80)
        desc = raw(0x2000)
        p32(image, desc + 0, 0x2040)
        p32(image, desc + 12, 0x2060)
        p32(image, desc + 16, 0x2050)
        image[raw(0x2060):raw(0x2060) + 13] = b"kernel32.dll\0"
        for i, name in enumerate(imports):
            hint_name_rva = 0x2080 + i * 0x40
            p64(image, raw(0x2040) + i * 8, hint_name_rva)
            p64(image, raw(0x2050) + i * 8, hint_name_rva)
            p16(image, raw(hint_name_rva), 0)
            encoded = name.encode("ascii") + b"\0"
            image[raw(hint_name_rva) + 2:raw(hint_name_rva) + 2 + len(encoded)] = encoded
        # Explicit terminators for INT and IAT.
        p64(image, raw(0x2040) + len(imports) * 8, 0)
        p64(image, raw(0x2050) + len(imports) * 8, 0)

    if pdb_marker:
        marker = b"C:\\build\\release\\sample.pdb\0"
        image[raw(0x2200):raw(0x2200) + len(marker)] = marker

    if context_flags:
        # A file-backed CONTEXT object lets the anti-debug fixture exercise
        # SetThreadContext-family argument localization without executing the
        # sample.  ContextFlags is the first DWORD in the structure.
        p32(image, raw(0x2300), context_flags)

    return bytes(image)


def call_iat(iat_rva: int, *, branch: bool = True) -> bytes:
    # call qword ptr [rip + (IAT - next_ip)]; test eax,eax; jne +1; ret
    disp = iat_rva - (0x1000 + 6)
    code = b"\xff\x15" + struct.pack("<i", disp) + b"\x85\xc0"
    if branch:
        code += b"\x75\x01"
    return code + b"\xc3"


def timing_pair(iat_rva: int) -> bytes:
    """Two direct timing API calls in one bounded function."""
    def one(call_rva: int) -> bytes:
        disp = iat_rva - (call_rva + 6)
        return b"\xff\x15" + struct.pack("<i", disp)

    return one(0x1000) + one(0x1006) + b"\xc3"


def rtl_veh_trap() -> bytes:
    """Register an executable VEH callback through ntdll's native alias.

    RtlAddVectoredExceptionHandler takes the callback in RDX (the second
    argument).  The conditional branch deliberately leaves one edge at the
    INT3 and one edge at the return, which gives the static CFG correlator a
    concrete registration-to-trap relation.
    """
    handler_va = 0x140001080
    call_rva = 0x1000 + 15
    disp = 0x2050 - (call_rva + 6)
    code = (
        b"\x48\xba" + struct.pack("<Q", handler_va)  # mov rdx, callback
        + b"\xb9\x01\x00\x00\x00"                    # mov ecx, 1
        + b"\xff\x15" + struct.pack("<i", disp)       # call [Rtl... IAT]
        + b"\x85\xc0\x74\x01\xcc\xc3"
    )
    body = bytearray(b"\x90" * 0x100)
    body[:len(code)] = code
    body[0x80] = 0xC3
    return bytes(body)


def peb_being_debugged() -> bytes:
    # mov rax, gs:[0x60]; movzx eax, byte ptr [rax+2]; ret
    return b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x0f\xb6\x40\x02\xc3"


def peb_process_heap_flags() -> bytes:
    # mov rax, gs:[0x60]; mov rcx, [rax+0x30] (ProcessHeap);
    # mov edx, [rcx+0x70] (HEAP.Flags); test edx, 0x70; ret.
    return bytes.fromhex(
        "65488b042560000000488b48308b517048f7c270000000c3"
    )


def peb_process_heap_pointer_only() -> bytes:
    # The same ProcessHeap derivation without reading or testing Flags.
    return bytes.fromhex("65488b042560000000488b4830c3")


def set_thread_context_debug_registers() -> bytes:
    # lea rdx,[rip+0x2300] (the CONTEXT pointer, second argument), then call
    # SetThreadContext through the first IAT slot.
    context_disp = 0x2300 - (0x1000 + 7)
    call_disp = 0x2050 - (0x1000 + 7 + 6)
    return b"\x48\x8d\x15" + struct.pack("<i", context_disp) + b"\xff\x15" + struct.pack("<i", call_disp) + b"\xc3"


def set_thread_context_debug_registers_stack() -> bytes:
    # sub rsp,28h; mov dword ptr [rsp+20h],100010h; lea rdx,[rsp+20h];
    # call SetThreadContext through the first IAT slot.
    code = bytearray(bytes.fromhex("4883ec28c744242010001000488d542420"))
    call_rva = 0x1000 + len(code)
    code += b"\xff\x15" + struct.pack("<i", 0x2050 - (call_rva + 6))
    code += bytes.fromhex("4883c428c3")
    return bytes(code)


def run(binary: Path, payload: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-antidebug-bait-") as raw:
        sample = Path(raw) / "sample.exe"
        sample.write_bytes(payload)
        cp = subprocess.run([str(binary), str(sample), "--json"], check=True,
                            capture_output=True, timeout=30)
        return json.loads(cp.stdout.decode("utf-8"))


def exceptional_flow_csv(binary: Path, payload: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="ar-antidebug-extract-") as raw:
        sample = Path(raw) / "sample.exe"
        sample.write_bytes(payload)
        cp = subprocess.run([str(binary), str(sample), "--extract", "--json"],
                            check=True, capture_output=True, timeout=30)
        report = json.loads(cp.stdout.decode("utf-8"))
        for artifact in report.get("artifacts", []):
            if artifact.get("kind") != "exceptional_flow_map":
                continue
            path = Path(artifact.get("path", ""))
            if path.exists():
                return path.read_text(encoding="utf-8")
    return ""


def run_summary(binary: Path, payload: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="ar-antidebug-summary-") as raw:
        sample = Path(raw) / "sample.exe"
        sample.write_bytes(payload)
        cp = subprocess.run([str(binary), str(sample), "--summary", "--json"],
                            check=True, capture_output=True, timeout=30)
        return json.loads(cp.stdout.decode("utf-8"))


def anti(report: dict) -> list[dict]:
    return [f for f in report.get("findings", []) if f.get("family") == "Anti-debug"]


def main() -> None:
    binary = Path(sys.argv[1]).resolve()

    # Import and strings alone are bait.  This is intentionally the same
    # anti-debug API plus a PDB path, with no callsite or GS:[0x60] access.
    bait = run(binary, pe64(code=b"\xc3", imports=("IsDebuggerPresent",), pdb_marker=True))
    assert not anti(bait), bait.get("findings", [])

    # A real callsite is confirmed and localized to the current image.  The
    # branch is useful evidence but not required to recognize the API call.
    real = run(binary, pe64(code=call_iat(0x2050), imports=("IsDebuggerPresent",)))
    findings = anti(real)
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding["variant"] == "IsDebuggerPresent"
    assert finding["state"] == "CONFIRMED"
    assert finding["fields"]["callsite_rva"] == "0x1000"
    assert finding["fields"]["result_controls_branch"] == "true"
    # The summary field is the stable RVA contract.  The legacy anti-debug
    # range serializer is file-offset based (0x200 is RVA 0x1000 here).
    assert finding["ranges"] and finding["ranges"][0]["offset"] == 0x200
    # The concise JSON view must retain the typed coordinate provenance used
    # by the full report; dropping it makes an address ambiguous after a
    # runtime or child-process finding is folded into the summary.
    compact = run_summary(binary, pe64(code=call_iat(0x2050),
                                       imports=("IsDebuggerPresent",)))
    compact_range = next(f for f in compact["findings"]
                         if f["variant"] == "IsDebuggerPresent")["ranges"][0]
    assert {"coordinate_space", "basis", "artifact_identity", "label"} <= set(compact_range), compact_range

    # TLS is an execution-before-entry surface.  Its presence is retained in
    # the format facts while the anti-debug result remains tied to the actual
    # callsite; a TLS marker alone must not manufacture an anti-debug finding.
    tls = run(binary, pe64(code=call_iat(0x2050),
                           imports=("IsDebuggerPresent",), tls_callback=True))
    assert tls["pe"]["tls"]["present"] is True
    assert tls["pe"]["tls"]["callback_count"] == 1
    assert any(x["variant"] == "IsDebuggerPresent" for x in anti(tls)), anti(tls)

    # Direct PEB access is recognized without an import.  This catches a
    # common custom-loader/hand-written anti-debug shape.
    peb = run(binary, pe64(code=peb_being_debugged()))
    findings = anti(peb)
    assert any(x["variant"] == "PEB.BeingDebugged" and x["state"] == "CONFIRMED"
               for x in findings), findings

    # The heap metadata route is accepted only when ProcessHeap is derived
    # from the PEB and the Flags field is actually tested.  A bare PEB heap
    # pointer therefore remains a non-finding; this fixture closes the full
    # access-and-test shape and checks the newly localized result.
    heap = run(binary, pe64(code=peb_process_heap_flags()))
    findings = anti(heap)
    assert any(x["variant"] == "PEB.ProcessHeap/Flags" and x["state"] == "LIKELY"
               for x in findings), findings
    heap_bait = run(binary, pe64(code=peb_process_heap_pointer_only()))
    assert not any(x["variant"].startswith("PEB.ProcessHeap/") for x in anti(heap_bait)), anti(heap_bait)

    # SetThreadContext is also used by malware to clear or install hardware
    # breakpoints.  An imported name alone remains bait; a call whose second
    # argument resolves to a file-backed CONTEXT with CONTEXT_DEBUG_REGISTERS
    # is localized and reported with the ContextFlags range.
    context_bait = run(binary, pe64(code=b"\xc3", imports=("SetThreadContext",),
                                    context_flags=0x00100010))
    assert not anti(context_bait), context_bait
    context_arch_bait = run(binary, pe64(code=set_thread_context_debug_registers(),
                                         imports=("SetThreadContext",), context_flags=0x10))
    assert not any(x["variant"] == "SetThreadContext/DebugRegisters" for x in anti(context_arch_bait)), context_arch_bait
    context = run(binary, pe64(code=set_thread_context_debug_registers(),
                               imports=("SetThreadContext",),
                               context_flags=0x00100010))
    findings = anti(context)
    context_findings = [x for x in findings
                        if x["variant"] == "SetThreadContext/DebugRegisters"]
    assert context_findings and context_findings[0]["state"] == "CONFIRMED", findings
    assert context_findings[0]["fields"]["context_flags"] == "0x100010", findings
    context_stack = run(binary, pe64(code=set_thread_context_debug_registers_stack(),
                                     imports=("SetThreadContext",)))
    stack_findings = [x for x in anti(context_stack)
                      if x["variant"] == "SetThreadContext/DebugRegisters"]
    assert stack_findings and stack_findings[0]["fields"]["context_storage"] == "STACK_LOCAL", stack_findings

    # Native ntdll exports the same VEH registration primitive under the Rtl
    # prefix.  It must receive the same trap/callback correlation as the
    # kernel32-facing AddVectoredExceptionHandler spelling.
    rtl = run(binary, pe64(code=rtl_veh_trap(), imports=("RtlAddVectoredExceptionHandler",)))
    findings = anti(rtl)
    relation = [x for x in findings if x["variant"] == "exception/trap probe"]
    assert relation and relation[0]["state"] == "LIKELY", findings
    assert relation[0]["fields"]["handler_registration_api"] == "RtlAddVectoredExceptionHandler", findings
    assert relation[0]["fields"]["registration_trap_relation"] == "SAME_FUNCTION_CFG_DOMINANCE_REACHABILITY", findings
    flow = exceptional_flow_csv(binary, pe64(code=rtl_veh_trap(),
                                              imports=("RtlAddVectoredExceptionHandler",)))
    assert "RtlAddVectoredExceptionHandler" in flow, flow
    assert "TRIGGER_HANDLER_CORRELATED" in flow, flow

    # Ordinary timing/diagnostic imports and a PDB marker remain below the
    # anti-debug contract when no callsite or data-flow is present.
    diagnostic = run(binary, pe64(code=b"\xc3", imports=("QueryPerformanceCounter",),
                                  pdb_marker=True))
    assert not anti(diagnostic), diagnostic.get("findings", [])

    # A repeated timing source remains a weak clue, but its two concrete
    # callsites must still be directly inspectable in the report.
    timed = run(binary, pe64(code=timing_pair(0x2050),
                             imports=("QueryPerformanceCounter",)))
    timing = [x for x in anti(timed)
              if x["variant"] == "QueryPerformanceCounter timing pair"]
    assert len(timing) == 1, timing
    assert timing[0]["fields"]["sample_callsites"] == "0x1000,0x1006", timing
    assert [x["offset"] for x in timing[0]["ranges"]] == [0x200, 0x206], timing
    print("[PASS] anti-debug marker bait stays silent; real call and PEB access are localized")


if __name__ == "__main__":
    main()
