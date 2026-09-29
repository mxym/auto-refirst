#!/usr/bin/env python3
"""Exercise the bounded header probe through an existing public helper."""
import pathlib
import struct
import subprocess
import sys
import tempfile

from run_public_regression import ROOT, minimal_pe, minimal_elf, pyc310
from test_artifact_graph import make_fat_macho


def large_dos_pe():
    source=minimal_pe();nt=0x10100;section=nt+24+224
    raw=(section+40+511)&~511;rva=(raw+4095)&~4095
    out=bytearray(raw+512);out[:64]=source[:64]
    out[nt:section+40]=source[0x80:0x80+24+224+40]
    out[raw:]=source[0x200:]
    struct.pack_into('<I',out,0x3c,nt)
    for offset,value in ((nt+24+16,rva),(nt+24+20,rva),(nt+24+24,rva+4096),(nt+24+56,rva+4096),(nt+24+60,raw),(section+12,rva),(section+20,raw)):
        struct.pack_into('<I',out,offset,value)
    return bytes(out)


def minimal_asar():
    header=b'{"files":{"app.js":{"size":1}}}'
    aligned=(len(header)+3)&~3
    payload_size=4+aligned
    header_size=payload_size+4
    return struct.pack('<IIII',4,header_size,payload_size,len(header))+header+b'\0'*(aligned-len(header))+b'x'


def main():
    helper=pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix='ar-header-probe-') as temp:
        root=pathlib.Path(temp)
        def probe(data,name='renamed.data'):
            path=root/name;path.write_bytes(data)
            p=subprocess.run([str(helper),'preflight',str(path)],capture_output=True,check=True,timeout=20)
            fields=p.stdout.decode('utf-8').rstrip('\r\n').split('\t')
            assert len(fields)==5,fields
            return fields[0],fields[1],int(fields[2]),fields[3],fields[4]=='1'

        thin=struct.pack('<IiiIIIII',0xfeedfacf,0x01000007,3,2,0,0,0,0)
        thin_be=struct.pack('>IiiIIII',0xfeedface,18,0,1,0,0,0)
        cases=[(minimal_pe(),'PE executable'),(minimal_elf(),'ELF'),(thin,'Mach-O'),(thin_be,'Mach-O'),(make_fat_macho(),'Mach-O'),(pyc310(),'CPython bytecode'),((ROOT/'tests/corpus/jvm/LambdaSample.class').read_bytes(),'JVM Class'),(minimal_asar(),'Electron ASAR')]
        for version in (89,96,98):cases.append(((ROOT/f'tests/corpus/hermes/v{version}.hbc').read_bytes(),'Hermes HBC'))
        for version in ('5.1.5','5.2.4','5.3.6','5.4.8','5.5.0'):
            cases.append(((ROOT/f'tests/corpus/lua/sample-{version}.luac').read_bytes(),'Lua'))
        for data,expected in cases:
            result=probe(data)
            assert result[0]==expected and result[2]>=45,(expected,result)
            if expected not in ('PE executable','ELF'):assert result[1]=='medium' and result[4] is False,result
        js=probe(b"const x=require('x'); WebAssembly.instantiateStreaming(fetch('x.wasm'));",'main.js')
        assert js[0]=='JavaScript-like script' and js[1]=='low' and js[2]>=20 and js[3]=='script' and js[4] is False,js
        for data in (thin[:4],bytes.fromhex('cafebabe'),pyc310()[:4],b'\x1bLua',bytes.fromhex('c61fbc03c103191f'),minimal_asar()[:16]):
            result=probe(data);assert result[2]<=5 and result[4] is False,result
        for name in ('fake.class','fake.hbc','fake.luac','fake.pyc','fake.dylib'):
            assert probe(b'ordinary text with no binary header',name)[0]=='',name
        future=bytearray((ROOT/'tests/corpus/hermes/v98.hbc').read_bytes());struct.pack_into('<I',future,8,999)
        assert probe(future)[2]<=5
        bad_pyc=bytearray(pyc310());struct.pack_into('<I',bad_pyc,4,0x80)
        assert probe(bad_pyc)[2]<=5
        bad_lua=bytearray((ROOT/'tests/corpus/lua/sample-5.4.8.luac').read_bytes());bad_lua[12]=0
        assert probe(bad_lua)[2]<=5
        assert probe(make_fat_macho()[:-1])[2]<=5
        # The helper supplies the complete file, but the shared probe may only
        # inspect the first 64 KiB. Full analysis is tested separately.
        assert probe(large_dos_pe())[0]=='MZ/DOS-like'
    print('[PASS] bounded preflight formats: shared-magic disambiguation, known bytecodes, weak/unsupported headers, filename bait and prefix limit')


if __name__=='__main__':main()
