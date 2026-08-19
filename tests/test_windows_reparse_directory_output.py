#!/usr/bin/env python3
"""Windows-only reparse/junction regression for directory and artifact roots."""
from __future__ import annotations
import json, os, pathlib, struct, subprocess, sys, tempfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
AR=pathlib.Path(sys.argv[1]).resolve() if len(sys.argv)>1 else ROOT/'build'/'auto-refirst.exe'

if os.name!='nt':
    print('[SKIP] Windows junction/reparse regression')
    raise SystemExit(0)


def minimal_pe()->bytes:
    b=bytearray(0x400); b[:2]=b'MZ'; struct.pack_into('<I',b,0x3c,0x80); b[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<H',b,0x84,0x14c); struct.pack_into('<H',b,0x86,1); struct.pack_into('<H',b,0x94,224); struct.pack_into('<H',b,0x96,0x0102)
    o=0x98; struct.pack_into('<H',b,o,0x10b); struct.pack_into('<I',b,o+4,0x200); struct.pack_into('<I',b,o+16,0x1000); struct.pack_into('<I',b,o+20,0x1000); struct.pack_into('<I',b,o+24,0x2000)
    struct.pack_into('<I',b,o+28,0x400000); struct.pack_into('<I',b,o+32,0x1000); struct.pack_into('<I',b,o+36,0x200); struct.pack_into('<H',b,o+40,6); struct.pack_into('<H',b,o+48,6)
    struct.pack_into('<I',b,o+56,0x2000); struct.pack_into('<I',b,o+60,0x200); struct.pack_into('<H',b,o+68,3); struct.pack_into('<I',b,o+72,0x100000); struct.pack_into('<I',b,o+76,0x1000); struct.pack_into('<I',b,o+80,0x100000); struct.pack_into('<I',b,o+84,0x1000); struct.pack_into('<I',b,o+92,16)
    sh=o+224; b[sh:sh+8]=b'.text\0\0\0'; struct.pack_into('<I',b,sh+8,0x100); struct.pack_into('<I',b,sh+12,0x1000); struct.pack_into('<I',b,sh+16,0x200); struct.pack_into('<I',b,sh+20,0x200); struct.pack_into('<I',b,sh+36,0x60000020); b[0x200]=0xc3
    return bytes(b)


def junction(link:pathlib.Path,target:pathlib.Path)->None:
    cp=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(link),str(target)],capture_output=True,text=True,errors='replace')
    if cp.returncode: raise AssertionError((cp.returncode,cp.stdout,cp.stderr))


def unlink_junction(link:pathlib.Path)->None:
    if link.exists() or link.is_symlink(): os.rmdir(link)


def runj(path:pathlib.Path)->dict:
    cp=subprocess.run([str(AR),str(path),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace',timeout=60)
    if cp.returncode: raise AssertionError((path,cp.returncode,cp.stdout[-1500:],cp.stderr[-2500:]))
    return json.loads(cp.stdout)


tmpbase=pathlib.Path(os.environ.get('TMPDIR') or os.environ.get('TEMP') or tempfile.gettempdir())
with tempfile.TemporaryDirectory(prefix='ar-bb-win-reparse-',dir=tmpbase) as raw:
    td=pathlib.Path(raw)
    # Directory ingress: a junction is inventoried as a traversal refusal, never followed.
    inp=td/'input';outside=td/'outside';inp.mkdir();outside.mkdir()
    (inp/'inside.txt').write_text('inside\n',encoding='utf-8');(outside/'secret.txt').write_text('secret\n',encoding='utf-8')
    link=inp/'junction';junction(link,outside)
    try:
        j=runj(inp);plan=j['directory_plan']
        assert any('junction' in x['path'].lower() and ('reparse' in x['reason'].lower() or 'symlink' in x['reason'].lower()) for x in plan['traversal_skips']),plan['traversal_skips']
        assert not any(pathlib.Path(x['path']).name=='secret.txt' for x in plan['file_states'])
    finally: unlink_junction(link)

    # Product-owned output root: a pre-existing junction must fail closed before
    # any validated nested-PE materialization can write through it.
    nested=td/'nested.bin';nested.write_bytes(b'parent-prefix\0'+minimal_pe()+b'parent-tail')
    target=td/'artifact-target';target.mkdir();sentinel=target/'sentinel.txt';sentinel.write_text('sentinel\n',encoding='utf-8')
    aroot=pathlib.Path(str(nested)+'.auto-refirst');junction(aroot,target)
    try:
        j=runj(nested)
        assert list(target.iterdir())==[sentinel]
        assert sentinel.read_text(encoding='utf-8')=='sentinel\n'
        rawj=json.dumps(j,ensure_ascii=False).lower()
        assert 'reparse' in rawj or 'symlink' in rawj,rawj[-4000:]
    finally: unlink_junction(aroot)

print('[PASS] Windows directory/artifact-root junction reparse refusal + JSON validity')
