#!/usr/bin/env python3
"""Self-contained public regression gate.

P0/P1 are static-only with respect to analyzed inputs, need no private corpus,
and never invoke auto-refirst --run on an analyzed target.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import hashlib
import re
import struct
import subprocess
import sys
import tempfile
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROVENANCE = ROOT / "tests" / "corpus" / "PROVENANCE.csv"
PUBLIC_FIXTURES = (
    "tests/corpus/jvm/LambdaSample.class",
    "tests/corpus/android/LambdaSample.dex",
    "tests/corpus/wasm/check_flag.o",
    "tests/corpus/lua/sample-5.4.8.luac",
)


def log(msg: str) -> None:
    print(msg, flush=True)


def run(cmd: Iterable[object], *, timeout: int = 90, check: bool = True, env=None) -> subprocess.CompletedProcess[str]:
    argv = [str(x) for x in cmd]
    cp = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=timeout, env=env)
    if check and cp.returncode != 0:
        raise AssertionError(f"command failed rc={cp.returncode}: {' '.join(argv)}\nstdout:\n{cp.stdout[-5000:]}\nstderr:\n{cp.stderr[-5000:]}")
    return cp


def analyze(binary: pathlib.Path, path: pathlib.Path, *args: str):
    cp = run([binary, path, *args, "--json"])
    return json.loads(cp.stdout)


def put16(b: bytearray, o: int, v: int) -> None: struct.pack_into("<H", b, o, v)
def put32(b: bytearray, o: int, v: int) -> None: struct.pack_into("<I", b, o, v)


def minimal_pe() -> bytes:
    b = bytearray(0x400); b[:2] = b"MZ"; put32(b, 0x3C, 0x80); b[0x80:0x84] = b"PE\0\0"
    put16(b,0x84,0x14C); put16(b,0x86,1); put16(b,0x94,224); put16(b,0x96,0x0102)
    o=0x98; put16(b,o,0x10B); put32(b,o+4,0x200); put32(b,o+16,0x1000); put32(b,o+20,0x1000); put32(b,o+24,0x2000)
    put32(b,o+28,0x400000); put32(b,o+32,0x1000); put32(b,o+36,0x200); put16(b,o+40,6); put16(b,o+48,6)
    put32(b,o+56,0x2000); put32(b,o+60,0x200); put16(b,o+68,3); put32(b,o+72,0x100000); put32(b,o+76,0x1000)
    put32(b,o+80,0x100000); put32(b,o+84,0x1000); put32(b,o+92,16)
    sh=o+224; b[sh:sh+8]=b".text\0\0\0"; put32(b,sh+8,0x100); put32(b,sh+12,0x1000); put32(b,sh+16,0x200); put32(b,sh+20,0x200); put32(b,sh+36,0x60000020)
    b[0x200] = 0xC3
    return bytes(b)


def minimal_elf() -> bytes:
    b=bytearray(0x200); b[:16]=b"\x7fELF"+bytes([2,1,1,0])+bytes(8)
    struct.pack_into("<HHIQQQIHHHHHH", b, 16, 2, 62, 1, 0x400080, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", b, 64, 1, 5, 0, 0x400000, 0x400000, 0x200, 0x200, 0x1000)
    b[0x80] = 0xC3
    return bytes(b)


def lua53_long_string_chunk() -> bytes:
    """Minimal valid Lua 5.3 chunk with strings that require the 0xff + size_t form."""
    payload = b"L" * 300

    def count(v: int) -> bytes:
        return struct.pack("<I", v)

    def long_string(raw: bytes) -> bytes:
        # Lua 5.3 stores size including the terminating byte in the length field,
        # while the serialized payload omits that terminator.
        return b"\xff" + struct.pack("<Q", len(raw) + 1) + raw

    header = (
        b"\x1bLua" + bytes([0x53, 0]) + b"\x19\x93\r\n\x1a\n" +
        bytes([4, 8, 4, 8, 8]) + struct.pack("<Q", 0x5678) + struct.pack("<d", 370.5)
    )
    proto = (
        long_string(payload) + count(0) + count(0) + bytes([0, 0, 2]) +
        count(0) +                     # code
        count(1) + bytes([4]) + long_string(payload) +  # constants
        count(0) +                     # upvalues
        count(0) +                     # child protos
        count(0) + count(0) + count(0) # lineinfo, locals, upvalue names
    )
    return header + bytes([0]) + proto


def pyc310() -> bytes:
    def i32(v): return struct.pack("<i", v)
    def u32(v): return struct.pack("<I", v)
    def bobj(v): return b"s" + i32(len(v)) + v
    def text(v):
        raw=v.encode(); assert len(raw)<256; return b"z" + bytes([len(raw)]) + raw
    def tup(xs): return b")" + bytes([len(xs)]) + b"".join(xs)
    body=(b"c"+i32(0)+i32(0)+i32(0)+i32(0)+i32(1)+i32(0)+bobj(b"d\x00S\x00")+
          tup([b"N",text("public-ci")])+tup([text("alpha")])+tup([])+tup([])+tup([])+
          text("public.py")+text("<module>")+i32(1)+bobj(b""))
    return struct.pack("<H",3439)+b"\r\n"+u32(0)+u32(0x66010203)+u32(1)+body


def provenance_gate() -> None:
    assert PROVENANCE.is_file(), PROVENANCE
    with PROVENANCE.open(newline="", encoding="utf-8") as f:
        rows = {r["path"]: r for r in csv.DictReader(f)}
    assert len(rows) == 9, f"expected exactly nine public fixture rows, got {len(rows)}"
    for path,r in rows.items():
        src=ROOT/path
        assert src.is_file(), f"missing public fixture: {path}"
        assert r["redistributable"].lower()=="true", (path,r)
        assert r["license"].strip() and r["sha256"].strip(), (path,r)
        actual=hashlib.sha256(src.read_bytes()).hexdigest()
        assert actual==r["sha256"], (path,actual,r["sha256"])
    for path in PUBLIC_FIXTURES:
        assert path in rows, f"missing P0 provenance row: {path}"
        assert rows[path]["public_ci_allowed"].lower()=="true", (path,rows[path])
    log("[PASS P0] public fixture provenance: 9 source-backed rows + SHA-256")

def p0_formats(binary: pathlib.Path, td: pathlib.Path) -> None:
    pe=td/"minimal-pe.bin"; pe.write_bytes(minimal_pe())
    elf=td/"minimal-elf.bin"; elf.write_bytes(minimal_elf())
    jp=analyze(binary,pe); je=analyze(binary,elf)
    assert jp["format"]["kind"]=="PE" and jp["runtime"]["requested"] is False
    assert je["format"]["kind"]=="ELF" and je["runtime"]["requested"] is False
    cases=[
        (PUBLIC_FIXTURES[0], "jvm_class"),
        (PUBLIC_FIXTURES[1], "dex"),
        (PUBLIC_FIXTURES[2], "wasm"),
    ]
    for rel,key in cases:
        src=ROOT/rel; p=td/src.name; p.write_bytes(src.read_bytes())
        j=analyze(binary,p); assert j[key]["valid"] and not j["runtime"]["requested"], (p,key)
    lua_src=ROOT/PUBLIC_FIXTURES[3]; lua_path=td/lua_src.name; lua_path.write_bytes(lua_src.read_bytes())
    lua=analyze(binary,lua_path);
    assert any(f["family"]=="Lua bytecode" and f["state"]=="CONFIRMED" for f in lua["findings"])
    assert not lua["runtime"]["requested"]
    lua53_path=td/"lua53-long-string.luac"; lua53_path.write_bytes(lua53_long_string_chunk())
    lua53=analyze(binary,lua53_path)
    findings=[f for f in lua53["findings"] if f["family"]=="Lua bytecode"]
    assert len(findings)==1 and findings[0]["state"]=="CONFIRMED", findings
    assert findings[0]["variant"]=="5.3" and findings[0]["fields"]["prototypes"]=="1" and findings[0]["fields"]["constants"]=="1", findings[0]
    assert not lua53["runtime"]["requested"]
    log("[PASS P0] PE/ELF/JVM/DEX/Wasm/Lua static format smoke + Lua 5.3 long-string size_t form")


def p0_relationship_guidance(binary: pathlib.Path, td: pathlib.Path) -> None:
    d=td/"relationship"; d.mkdir(); (d/"driver.py").write_text('obj=open("payload.dat","rb").read()\n',encoding="utf-8"); (d/"payload.dat").write_bytes(b"payload")
    j=analyze(binary,d); rel=[x for x in j["directory_plan"]["relationships"] if x["kind"]=="script_literal_data_dependency"]
    assert len(rel)==1 and pathlib.Path(rel[0]["second"]).name=="payload.dat" and rel[0]["state"]=="BOUNDED"
    assert not j["directory_plan"]["runtime_selected"]
    log("[PASS P0] relationship evidence + directory guidance")


def p0_interpreter_and_runtime_modality(binary: pathlib.Path, td: pathlib.Path) -> None:
    vm=td/"vm.py"; vm.write_text('''class VM:\n def __init__(self):\n  self.pc=0; self.registers=[0]*4; self.stack=[0]*8; self.instructions={"ADD":self.add,"SUB":self.add,"XOR":self.add,"MOV":self.add,"LOAD":self.add,"STORE":self.add,"JMP":self.add,"HALT":self.add}\n def add(self,*a): self.registers[0]+=1\n def run(self,program):\n  while self.pc < len(program):\n   opcode=program[self.pc]; self.pc+=1; self.instructions[opcode]()\n''',encoding="utf-8")
    j=analyze(binary,vm); aw=[f for f in j["findings"] if f["family"]=="Interpreter / bytecode boundary"]
    assert len(aw)==1 and aw[0]["state"]=="CONFIRMED" and aw[0]["fields"]["exact_program_target_bound"]=="false"
    mod=j["analysis_guidance"]["runtime_modality"]; assert not mod["runtime_execution_authorized"]
    plain=td/"plain-elf"; plain.write_bytes(minimal_elf()); j=analyze(binary,plain)
    mod=j["analysis_guidance"]["runtime_modality"]; assert not mod["runtime_execution_authorized"] and not j["runtime"]["requested"]
    log("[PASS P0] interpreter boundary synthetic + runtime-modality static authorization gate")


def p0_nested_and_graph(binary: pathlib.Path, td: pathlib.Path) -> None:
    parent=td/"nested.bin"; pe=minimal_pe(); parent.write_bytes(b"parent-prefix\0"+pe+b"parent-tail")
    j=analyze(binary,parent); nested=[a for a in j["artifacts"] if a.get("relation")=="embedded_executable"]
    assert len(nested)==1 and nested[0]["state"]=="VALIDATED_EXACT" and nested[0]["size"]==len(pe)
    assert not j["runtime"]["requested"]
    env=dict(os.environ); env["PYTHONDONTWRITEBYTECODE"]="1"
    cp=run([sys.executable,ROOT/"tests/test_artifact_graph.py",binary],env=env,timeout=120)
    assert "[PASS]" in cp.stdout, cp.stdout
    log("[PASS P0] nested executable + recursive artifact graph")


def cmake_context(binary: pathlib.Path):
    p=binary.resolve(); parent=p.parent; config=None
    if parent.name in {"Release","Debug","RelWithDebInfo","MinSizeRel"}:
        config=parent.name; build=parent.parent
    else: build=parent
    assert (build/"CMakeCache.txt").is_file(), f"cannot infer configured CMake build dir from {binary}"
    return build,config


def cmake_build(binary: pathlib.Path, targets: list[str]) -> tuple[pathlib.Path,str|None]:
    build,config=cmake_context(binary); cmd=["cmake","--build",build]
    if config: cmd += ["--config",config]
    cmd += ["--target",*targets]
    run(cmd,timeout=180)
    return build,config


def target_path(build:pathlib.Path,config:str|None,name:str) -> pathlib.Path:
    ext=".exe" if os.name=="nt" else ""
    p=(build/config/name if config else build/name).with_name(name+ext)
    assert p.is_file(), p
    return p


def p0_model_and_pyc(binary:pathlib.Path,td:pathlib.Path) -> None:
    targets=["auto_refirst_public_model_trust_unit","auto_refirst_public_python_bytecode_unit"]
    build,config=cmake_build(binary,targets)
    model=target_path(build,config,targets[0]); assert run([model]).stdout.strip()=="PASS"
    pyunit=target_path(build,config,targets[1]); p=td/"public.pyc"; p.write_bytes(pyc310())
    out=run([pyunit,"inspect",p,"1"]).stdout.strip().split("\t",7)
    assert out[0:4]==["1","1","3.10","TIMESTAMP"],out
    bad=td/"bad.pyc"; bad.write_bytes(p.read_bytes()[:10]); out=run([pyunit,"inspect",bad,"1"]).stdout
    assert out.startswith("1\t0\t"),out
    log("[PASS P0] model-trust synthetic unit + direct CPython pyc trust ingress")


def p0_windows_reparse(binary:pathlib.Path) -> None:
    if os.name != "nt": return
    cp=run([sys.executable,ROOT/"tests/test_windows_reparse_directory_output.py",binary],timeout=120)
    assert "[PASS]" in cp.stdout,cp.stdout
    log("[PASS P0] Windows directory/artifact-root junction reparse refusal")


def p0_report_json(binary:pathlib.Path,td:pathlib.Path) -> None:
    p=td/"report-elf"; p.write_bytes(minimal_elf())
    en=run([binary,p]).stdout; obj=json.loads(run([binary,p,"--json"]).stdout)
    assert "auto-refirst Analysis" in en and obj["format"]["kind"]=="ELF"
    bad=run([binary,p,"--report-lang=xx"],check=False); assert bad.returncode==2
    version=run([binary,"--version"]).stdout.strip(); assert version.startswith("auto-refirst ")
    log("[PASS P0] text report / JSON / --version contract")


def p1_generated(binary:pathlib.Path,td:pathlib.Path) -> None:
    targets=["auto_refirst_public_fixture_ordinary","auto_refirst_public_fixture_crypto","auto_refirst_public_fixture_runtime_child","auto_refirst_public_fixture_runtime_parent"]
    build,config=cmake_build(binary,targets)
    fmt="PE" if os.name=="nt" else "ELF"
    for target in targets:
        p=target_path(build,config,target); j=analyze(binary,p)
        assert j["format"]["kind"]==fmt,(target,j["format"])
        assert not j["runtime"]["requested"], (target,j["runtime"])
        modality=j.get("analysis_guidance",{}).get("runtime_modality")
        if modality is not None:
            assert not modality["runtime_execution_authorized"], (target,modality)
    # P1 bytecode fixture is generated byte-for-byte by this runner, not by the host Python compiler.
    p=td/"p1-generated.pyc"; p.write_bytes(pyc310()); assert p.stat().st_size>32
    log(f"[PASS P1] source-generated {fmt} ordinary/crypto/runtime-child/runtime-parent + deterministic pyc fixture (static analysis only)")


def write_build_manifest(binary:pathlib.Path) -> pathlib.Path:
    build,config=cmake_context(binary)
    cache=(build/"CMakeCache.txt").read_text(errors="replace")
    def cache_value(name:str) -> str:
        m=re.search(rf"^{re.escape(name)}(?::[^=]+)?=(.*)$",cache,re.M)
        return m.group(1).strip() if m else ""
    compiler_meta={}
    cmake_files=build/"CMakeFiles"
    for lang in ("C","CXX"):
        candidates=list(cmake_files.glob(f"*/CMake{lang}Compiler.cmake"))
        text=candidates[0].read_text(errors="replace") if candidates else ""
        def cmake_set(key:str) -> str:
            m=re.search(rf'set\({re.escape(key)} "([^"]*)"\)',text)
            return m.group(1) if m else ""
        compiler_meta[lang.lower()]={
            "id":cmake_set(f"CMAKE_{lang}_COMPILER_ID"),
            "version":cmake_set(f"CMAKE_{lang}_COMPILER_VERSION"),
            "target":cmake_set(f"CMAKE_{lang}_COMPILER_TARGET"),
        }
    git_commit=run(["git","-C",ROOT,"rev-parse","HEAD"],check=False)
    commit=git_commit.stdout.strip() if git_commit.returncode==0 else os.environ.get("AUTO_REFIRST_SOURCE_COMMIT","archive-or-unknown")
    version=run([binary,"--version"]).stdout.strip()
    data={
      "contract":"SEMANTICALLY_REPRODUCIBLE",
      "source_commit":commit,
      "product_version":version,
      "binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
      "cmake_version":run(["cmake","--version"]).stdout.splitlines()[0],
      "generator":cache_value("CMAKE_GENERATOR"),
      "configuration":config or cache_value("CMAKE_BUILD_TYPE") or "unspecified",
      "compiler":compiler_meta,
      "flags":{
        "c":cache_value("CMAKE_C_FLAGS"),"c_release":cache_value("CMAKE_C_FLAGS_RELEASE"),
        "cxx":cache_value("CMAKE_CXX_FLAGS"),"cxx_release":cache_value("CMAKE_CXX_FLAGS_RELEASE"),
        "exe_linker":cache_value("CMAKE_EXE_LINKER_FLAGS"),"exe_linker_release":cache_value("CMAKE_EXE_LINKER_FLAGS_RELEASE"),
      },
      "bit_reproducible_claim":False,
      "notes":"Public build manifest records source identity and toolchain/flags. Compiler timestamps, PE/PDB paths and runner image updates can change bytes; semantic assertions are the release gate."
    }
    out=build/"public-build-manifest.json";out.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8")
    log(f"[PASS META] release build manifest: {out}")
    return out


def sanitizer_smoke(harness:pathlib.Path,td:pathlib.Path) -> None:
    malformed={
      "tiny.bin":b"\x00",
      "truncated-pe.exe":b"MZ"+b"\0"*61,
      "truncated-elf":b"\x7fELF\x02\x01\x01"+b"\0"*17,
      "bad-wasm.wasm":b"\0asm\x01\0\0\0\x01\x80\x80\x80\x80\x80\x00",
      "bad-class.class":b"\xca\xfe\xba\xbe\0\0\0\x37\0\x02",
      "bad.dex":b"dex\n038\0"+b"\0"*24,
      "bad.luac":b"\x1bLua\x54\0",
    }
    for name,data in malformed.items():
        p=td/name; p.write_bytes(data); cp=run([harness,p],check=False,timeout=30)
        assert cp.returncode == 0, (name,cp.returncode,cp.stderr)
        stderr=cp.stderr.lower(); assert "addresssanitizer" not in stderr and "runtime error:" not in stderr,(name,cp.stderr)
    log("[PASS SAN] ASan+UBSan parser harness: PE/ELF/JVM/DEX/Wasm/Lua malformed corpus; static only")



def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--binary",type=pathlib.Path,default=ROOT/"build"/("auto-refirst.exe" if os.name=="nt" else "auto-refirst"))
    ap.add_argument("--tier",choices=("P0","P1","all"),default="all")
    ap.add_argument("--sanitizer-smoke",action="store_true")
    args=ap.parse_args(); binary=args.binary.resolve(); assert binary.is_file(),binary
    with tempfile.TemporaryDirectory(prefix="auto-refirst-public-") as raw:
        td=pathlib.Path(raw)
        if args.sanitizer_smoke:
            sanitizer_smoke(binary,td); return 0
        if args.tier in ("P0","all"):
            provenance_gate(); p0_formats(binary,td); p0_relationship_guidance(binary,td); p0_interpreter_and_runtime_modality(binary,td)
            p0_nested_and_graph(binary,td); p0_model_and_pyc(binary,td); p0_report_json(binary,td); p0_windows_reparse(binary)
        if args.tier in ("P1","all"): p1_generated(binary,td)
        write_build_manifest(binary)
    log(f"[PASS] public regression tier={args.tier}; static-only; self-contained")
    return 0


if __name__=="__main__": raise SystemExit(main())
