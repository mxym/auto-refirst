#!/usr/bin/env python3
import json,pathlib,struct,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
AR=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'build/auto-refirst'
WASM=(ROOT/'tests/corpus/wasm/check_flag.o').read_bytes()

def make_asar(files):
    off=0;meta={}
    for name,data in files:
        meta[name]={"size":len(data),"offset":str(off)};off+=len(data)
    h=json.dumps({"files":meta},separators=(',',':')).encode()
    aligned=(len(h)+3)&~3
    payload=4+aligned
    header_size=payload+4
    return struct.pack('<IIII',4,header_size,payload,len(h))+h+b'\0'*(aligned-len(h))+b''.join(data for _,data in files)

def make_fat_macho():
    def thin(cpu,sub):
        return struct.pack('<IiiIIIII',0xfeedfacf,cpu,sub,2,0,0,0,0)
    slices=[(0x01000007,3,thin(0x01000007,3)),(0x0100000c,0,thin(0x0100000c,0))]
    offsets=[0x1000,0x2000]
    out=bytearray(offsets[-1]+len(slices[-1][2]))
    struct.pack_into('>II',out,0,0xcafebabe,len(slices))
    for i,((cpu,sub,data),off) in enumerate(zip(slices,offsets)):
        struct.pack_into('>iiIII',out,8+i*20,cpu,sub,off,len(data),12)
        out[off:off+len(data)]=data
    return bytes(out)

def reports(p,*args):
    raw=subprocess.check_output([str(AR),str(p),*args,'--json'],text=True)
    j=json.loads(raw)
    if isinstance(j,dict) and 'directory_summary' in j and 'reports' in j: return j['reports']
    return j if isinstance(j,list) else [j]

def graph(rs): return rs[0]['artifact_graph']

def main():
    inner=make_asar([('a.wasm',WASM),('b.wasm',WASM)])
    outer=make_asar([('inner.bin',inner)])
    with tempfile.TemporaryDirectory(prefix='ar-graph-') as td:
        td=pathlib.Path(td);root=td/'renamed.bin';root.write_bytes(outer)

        rs=reports(root,'--extract','--recursive')
        assert len(rs)==3,(len(rs),[x['input'] for x in rs])
        assert rs[0]['asar']['valid'] and rs[0]['artifact']['root'] and rs[0]['artifact']['depth']==0
        assert rs[1]['asar']['valid'] and rs[1]['artifact']['depth']==1 and rs[1]['artifact']['relation']=='extracted:asar'
        w=[r for r in rs if r['wasm']['valid']];assert len(w)==1 and w[0]['artifact']['depth']==2
        g=graph(rs);assert g['enabled'] and not g['truncated'] and g['nodes']==3
        assert g['materialized_files']==3 and g['materialized_bytes']==len(inner)+2*len(WASM)
        assert g['deduplicated']==1 and sum(e['state']=='ADMITTED' for e in g['edges'])==2
        dup=[e for e in g['edges'] if e['state']=='DUPLICATE_SKIPPED'];assert len(dup)==1 and dup[0]['duplicate_of']
        f=[x for x in rs[0]['findings'] if x['family']=='Recursive artifact graph'];assert f and f[0]['state']=='CONFIRMED'

        # Depth=1 analyzes the nested ASAR but never materializes its grandchildren.
        root2=td/'depth.bin';root2.write_bytes(outer)
        rs=reports(root2,'--extract','--recursive','--artifact-depth=1')
        assert len(rs)==2 and rs[1]['asar']['valid'];g=graph(rs);assert g['truncated'] and g['nodes']==2 and g['materialized_files']==1
        assert any('depth limit reached' in w for w in g['warnings']) and not any(r['wasm']['valid'] for r in rs)

        # Byte budget is checked before extraction: the root output directory is never created.
        root3=td/'bytes.bin';root3.write_bytes(outer)
        rs=reports(root3,'--extract','--recursive',f'--artifact-bytes={len(inner)-1}')
        assert len(rs)==1;g=graph(rs);assert g['truncated'] and g['materialized_files']==0 and g['materialized_bytes']==0
        assert not (pathlib.Path(str(root3)+'.auto-refirst')/'static'/'asar').exists()
        b=[x for x in rs[0]['findings'] if x['family']=='Artifact extraction budget'];assert b and b[0]['state']=='REFUSED' and b[0]['fields']['ecosystem']=='Electron ASAR'

        # Node/file budget likewise blocks the next container before it fans out.
        root4=td/'nodes.bin';root4.write_bytes(outer)
        rs=reports(root4,'--extract','--recursive','--artifact-nodes=2')
        assert len(rs)==2 and rs[1]['asar']['valid'];g=graph(rs);assert g['truncated'] and g['nodes']==2 and g['materialized_files']==1
        assert any(x['family']=='Artifact extraction budget' and x['state']=='REFUSED' for x in rs[1]['findings'])

        # Nested format offsets are scoped to the materialized child artifact, not the outer root.
        universal=make_fat_macho();root5=td/'macho-container.bin';root5.write_bytes(make_asar([('universal.bin',universal)]))
        rs=reports(root5,'--extract','--recursive')
        assert len(rs)==2 and rs[0]['asar']['valid']
        m=next(r for r in rs if r['format']['kind']=='Mach-O')
        assert rs[0]['artifact']['root_input']==str(root5) and rs[0]['artifact']['offset_basis']==str(root5)
        assert m['artifact']['root_input']==str(root5) and m['artifact']['offset_basis']==m['input'] and m['artifact']['offset_space']=='current_input_file'
        assert m['format']['fat'] and m['format']['file_offset_scope']=='current_input_file'
        assert [x['slice_offset'] for x in m['macho_slices']]==[0x1000,0x2000]
        # The same 0x1000 is deliberately NOT presented as an outer-ASAR file offset.
        assert rs[0]['asar']['data_offset']+0x1000 != m['macho_slices'][0]['slice_offset']

        # Directory traversal does not follow symlinked files. The explicitly real file is analyzed once.
        dcase=td/'dircase';dcase.mkdir();real=dcase/'real.wasm';real.write_bytes(WASM);outside=td/'outside.wasm';outside.write_bytes(WASM)
        (dcase/'alias.wasm').symlink_to(outside)
        rs=reports(dcase,'--recursive')
        assert len(rs)==1 and pathlib.Path(rs[0]['input']).name=='real.wasm' and rs[0]['wasm']['valid']
        # Search must honor the same file-symlink/reparse boundary and never read outside via alias.wasm.
        outside.write_bytes(b'OUTSIDE_ONLY_SEARCH_SENTINEL')
        cp=subprocess.run([str(AR),str(dcase),'--search=OUTSIDE_ONLY_SEARCH_SENTINEL'],text=True,capture_output=True)
        assert cp.returncode==1 and 'matches=0' in cp.stdout

        # Recursive artifact mode is intentionally static-only.
        cp=subprocess.run([str(AR),str(root),'--extract','--recursive','--run=trace'],text=True,capture_output=True)
        assert cp.returncode==2 and 'static-only' in cp.stderr
    print('[PASS] Recursive artifact graph / SHA dedup / budgets / nested offset-basis provenance')
if __name__=='__main__': main()
