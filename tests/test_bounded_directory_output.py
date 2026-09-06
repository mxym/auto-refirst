#!/usr/bin/env python3
"""Public default directory output/resource contract regression.

No private/holdout fixture is used.  The stress corpus is source-generated so
this runs from a clean source archive as well as a Git checkout.
"""
from __future__ import annotations
import json, os, pathlib, struct, subprocess, sys, tempfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
AR=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'build'/('auto-refirst.exe' if os.name=='nt' else 'auto-refirst')
MIB=1024*1024


def minimal_pe()->bytes:
    b=bytearray(0x400); b[:2]=b'MZ'; struct.pack_into('<I',b,0x3c,0x80); b[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<H',b,0x84,0x14c); struct.pack_into('<H',b,0x86,1); struct.pack_into('<H',b,0x94,224); struct.pack_into('<H',b,0x96,0x0102)
    o=0x98; struct.pack_into('<H',b,o,0x10b); struct.pack_into('<I',b,o+4,0x200); struct.pack_into('<I',b,o+16,0x1000); struct.pack_into('<I',b,o+20,0x1000); struct.pack_into('<I',b,o+24,0x2000)
    struct.pack_into('<I',b,o+28,0x400000); struct.pack_into('<I',b,o+32,0x1000); struct.pack_into('<I',b,o+36,0x200); struct.pack_into('<H',b,o+40,6); struct.pack_into('<H',b,o+48,6)
    struct.pack_into('<I',b,o+56,0x2000); struct.pack_into('<I',b,o+60,0x200); struct.pack_into('<H',b,o+68,3); struct.pack_into('<I',b,o+72,0x100000); struct.pack_into('<I',b,o+76,0x1000); struct.pack_into('<I',b,o+80,0x100000); struct.pack_into('<I',b,o+84,0x1000); struct.pack_into('<I',b,o+92,16)
    sh=o+224; b[sh:sh+8]=b'.text\0\0\0'; struct.pack_into('<I',b,sh+8,0x100); struct.pack_into('<I',b,sh+12,0x1000); struct.pack_into('<I',b,sh+16,0x200); struct.pack_into('<I',b,sh+20,0x200); struct.pack_into('<I',b,sh+36,0x60000020); b[0x200]=0xc3
    return bytes(b)


def runj(path:pathlib.Path):
    cp=subprocess.run([str(AR),str(path),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
    if cp.returncode:
        raise AssertionError(f'rc={cp.returncode}\nstderr={cp.stderr[-4000:]!r}\nstdout_tail={cp.stdout[-2000:]!r}')
    return json.loads(cp.stdout),len(cp.stdout)


def assert_common_bounds(j:dict):
    rr=j['report_rendering']; ar=j['artifact_materialization']
    assert rr['profile']=='bounded_default'
    assert rr['inline_report_budget_bytes']==16*MIB,rr
    assert rr['per_report_max_bytes']==8*MIB,rr
    assert rr['spool_hard_budget_bytes']==24*MIB,rr
    assert 0<=rr['inline_report_bytes']<=rr['inline_report_budget_bytes'],rr
    assert 0<=rr['spool_peak_bytes']<=rr['spool_hard_budget_bytes'],rr
    assert rr['priorities_finalized'] is True,rr
    assert rr['inline_report_bytes']<=rr['spool_resident_bytes']<=rr['spool_hard_budget_bytes'],rr
    assert rr['full_reports_rendered']+rr['full_reports_deferred']==rr['full_report_count'],rr
    assert rr['inline_report_bytes']+rr['known_deferred_report_bytes']==rr['known_full_report_bytes'],rr
    assert rr['detail_retrieval']['mode']=='reanalyze_file' and '--json' in rr['detail_retrieval']['command']
    assert ar['profile']=='bounded_default'
    assert ar['max_bytes']==64*MIB and ar['max_files']==512,ar
    assert ar['pre_relationship_max_bytes']==56*MIB and ar['pre_relationship_max_files']==384,ar
    assert ar['post_relationship_reserve_bytes']==8*MIB and ar['post_relationship_reserve_files']==128,ar
    assert ar['pre_relationship_max_bytes']+ar['post_relationship_reserve_bytes']==ar['max_bytes']
    assert ar['pre_relationship_max_files']+ar['post_relationship_reserve_files']==ar['max_files']
    assert 0<=ar['materialized_bytes']<=ar['max_bytes'],ar
    assert 0<=ar['materialized_files']<=ar['max_files'],ar
    assert ar['detail_retrieval']['mode']=='reanalyze_file' and '--json' in ar['detail_retrieval']['command']


def main():
    # 1030 low-priority files + one structurally stronger PE at lexical tail.
    # Admission must retain the semantically stronger late candidate rather than
    # treating filesystem traversal order as product priority.
    with tempfile.TemporaryDirectory(prefix='ar-bb-admission-') as raw:
        d=pathlib.Path(raw)
        for i in range(1030):
            if i==0:
                (d/'a0000.py').write_text('obj=open("a1022.txt","rb").read()\n',encoding='utf-8')
            else:
                (d/f'a{i:04d}.txt').write_text('low priority text payload\n',encoding='utf-8')
        (d/'zzzz-decisive.bin').write_bytes(minimal_pe())
        j,n=runj(d); assert_common_bounds(j)
        s,p,rr=j['directory_summary'],j['directory_plan'],j['report_rendering']; fs=p['file_states']
        assert p['max_candidates']==1024 and p['regular_files_seen']==1031,p
        assert p['candidate_omitted_count']==7 and p['candidate_admission_budget_exhausted'] is True,p
        assert s['total_files']==1024 and s['discovered_regular_files']==1031 and s['candidate_omitted_count']==7,s
        assert s['partial'] is True and s['partial_reasons'],s
        assert any('report rendering deferred' in x for x in s['partial_reasons']),s['partial_reasons']
        assert len(fs)==1024 and rr['full_report_count']==1024
        decisive=next(x for x in fs if pathlib.Path(x['path']).name=='zzzz-decisive.bin')
        assert decisive['rank']==1 and decisive['tier']=='Tier 1' and decisive['role']=='executable_root',decisive
        assert not any(pathlib.Path(x['path']).name=='a1029.txt' for x in fs)
        # The late payload is admitted but falls outside the provisional inline
        # budget. Its exact cross-file reference is resolved only afterwards.
        payload=next(x for x in fs if pathlib.Path(x['path']).name=='a1022.txt')
        assert payload['report_detail_state']=='INLINE_FULL',payload
        assert rr['reports_reselected']>0,rr
        assert rr['cache_evicted_reports']==sum(x['report_detail_reason']=='DIRECTORY_SPOOL_CACHE_BUDGET' for x in fs),rr
        assert any(pathlib.Path(r['input']).name=='a1022.txt' for r in j['reports'])
        assert any(r['kind']=='script_literal_data_dependency' and pathlib.Path(r['second']).name=='a1022.txt' for r in p['relationships']),p['relationships']
        # This generated corpus drives the report selection right against the
        # aggregate boundary: at least one whole record must be deferred and the
        # remaining gap must be smaller than every aggregate-budget-deferred record.
        assert rr['full_reports_deferred']>0 and rr['inline_report_bytes']>15*MIB,rr
        remaining=rr['inline_report_budget_bytes']-rr['inline_report_bytes']
        agg_deferred=[x['report_full_bytes'] for x in fs if x['report_detail_state']=='DEFERRED' and x['report_detail_reason']=='DIRECTORY_INLINE_REPORT_BUDGET']
        assert agg_deferred and remaining < min(agg_deferred),(remaining,min(agg_deferred))
        # The whole default JSON envelope is also cardinality-bounded; this
        # 1024-state stress case remains comfortably below 24 MiB.
        assert n<24*MIB,n

    # UTF-8 path + binary input: directory JSON must remain valid and preserve
    # the path without requiring any filename semantics.
    with tempfile.TemporaryDirectory(prefix='ar-bb-utf8-') as raw:
        d=pathlib.Path(raw); p=d/'合法-目录-✓-данные.bin'; p.write_bytes(bytes(range(256))*4)
        j,_=runj(d); assert_common_bounds(j)
        states=j['directory_plan']['file_states']; assert len(states)==1 and pathlib.Path(states[0]['path']).name==p.name
        assert j['report_rendering']['full_report_count']==1
        assert j['directory_summary']['partial'] is False,j['directory_summary']

    print('[PASS] bounded directory admission/report-spool/artifact budgets + semantic-priority selection + UTF-8 JSON')

if __name__=='__main__': main()
