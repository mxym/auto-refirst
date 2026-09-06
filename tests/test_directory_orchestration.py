#!/usr/bin/env python3
import hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
AR=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'build/auto-refirst'

def runj(path,*args):
    cp=subprocess.run([str(AR),str(path),*map(str,args),'--json'],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if cp.returncode: raise AssertionError((path,args,cp.returncode,cp.stdout[-1000:],cp.stderr[-2000:]))
    j=json.loads(cp.stdout);assert isinstance(j,dict) and 'directory_summary' in j and 'directory_plan' in j and 'reports' in j
    return j,cp

def rel(p,root): return str(pathlib.Path(p).resolve().relative_to(root.resolve()))
def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def main():
    with tempfile.TemporaryDirectory(prefix='ar-dir-') as td:
        td=pathlib.Path(td);(td/'nested/deeper').mkdir(parents=True)
        (td/'plain.txt').write_text('ordinary text\n');(td/'unknown.bin').write_bytes(b'\x00\x01opaque\xff')
        renamed=td/'nested/renamed';shutil.copy2('/bin/true',renamed)
        (td/'nested/deeper/note').write_text('deep text')
        fake=td/'fake.exe';fake.write_text('not really a PE')
        unread=td/'nested/unreadable.bin';unread.write_bytes(b'secret');unread.chmod(0)
        outside=td.parent/(td.name+'-outside');outside.write_bytes(b'outside-not-admitted')
        (td/'nested/outside-link').symlink_to(outside)
        try:
            j,_=runj(td)
            sm,pl=j['directory_summary'],j['directory_plan'];reports=j['reports'];paths={rel(r['input'],td):r for r in reports}
            assert sm['total_files']==6,(sm['total_files'],paths.keys())
            assert sm['analyzed_files']==5 and sm['skipped_files']==1,(sm,paths.keys())
            assert {'plain.txt','unknown.bin','fake.exe','nested/renamed','nested/deeper/note'}<=set(paths)
            assert 'nested/unreadable.bin' not in paths and all('outside-link' not in x for x in paths)
            assert paths['nested/renamed']['format']['kind']=='ELF' and paths['nested/renamed']['format']['bits']==64
            assert paths['unknown.bin']['input'].endswith('unknown.bin')
            assert any('outside-link' in x['path'] and 'symlink' in x['reason'].lower() for x in pl['traversal_skips'])
            states={rel(x['path'],td):x for x in pl['file_states']}
            assert len(states)==6 and states['nested/unreadable.bin']['analysis_state']=='SKIPPED' and states['nested/unreadable.bin']['skipped_reason']
            assert states['nested/renamed']['analysis_state']=='ANALYZED' and states['nested/renamed']['runtime_eligible'] is True
            top=pl['top_priority_files'];ren=next(x for x in top if x['path'].endswith('/nested/renamed'));fakep=next(x for x in top if x['path'].endswith('/fake.exe'));assert ren['score']>fakep['score'] and ren['type_hint']=='ELF'
            # Deterministic priority/reasons across an immediate rerun.
            j2,_=runj(td);sig=lambda x:[(rel(q['path'],td),q['score'],q['tier'],tuple(q['reasons'])) for q in x['directory_plan']['top_priority_files']];assert sig(j)==sig(j2)
            # max-depth=0 keeps root files but does not descend into nested/.
            d0,_=runj(td,'--max-depth=0');p0={rel(r['input'],td) for r in d0['reports']};assert p0=={'plain.txt','unknown.bin','fake.exe'}
        finally:
            unread.chmod(0o600);outside.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix='ar-dir-target-limit-') as td:
        td=pathlib.Path(td)
        for n in ('a','b','c'):shutil.copy2('/bin/true',td/n)
        for i in range(128):(td/f'note-{i:03d}.txt').write_text('ordinary static data\n',encoding='utf-8')
        before={n:sha(td/n) for n in ('a','b','c')}
        j,_=runj(td,'--run','--max-runtime-targets=1','--timeout=500','--total-runtime-budget=2000')
        assert len(j['directory_plan']['runtime_selected'])==1
        rendering=j['report_rendering'];artifacts=j['artifact_materialization']
        assert rendering['profile']=='bounded_default' and rendering['priorities_finalized'],rendering
        assert rendering['retained_full_reports_peak']==3,rendering
        assert rendering['full_report_count']==131 and rendering['inline_report_bytes']<=16*1024*1024,rendering
        assert rendering['spool_resident_bytes']<=rendering['spool_hard_budget_bytes']==24*1024*1024,rendering
        assert rendering['runtime_detail_deferred'] is False and rendering['detail_retrieval']['mode']=='reanalyze_file',rendering
        assert artifacts['profile']=='bounded_static_preparation' and artifacts['scope']=='automatic_static_preparation',artifacts
        assert artifacts['max_bytes']==64*1024*1024 and artifacts['max_files']==512,artifacts
        sk=j['directory_plan']['runtime_skipped'];assert sum(x['state']=='SKIPPED_TARGET_LIMIT' for x in sk)==2
        assert before=={n:sha(td/n) for n in ('a','b','c')} and all(not r['replacement']['performed'] for r in j['reports'])

    with tempfile.TemporaryDirectory(prefix='ar-dir-budget-') as td:
        td=pathlib.Path(td);src=td/'slow.c';src.write_text('#include <unistd.h>\nint main(){usleep(200000);return 0;}\n')
        slow=td/'slow-bin';subprocess.check_call(['cc','-O2',str(src),'-o',str(slow)]);src.unlink();shutil.copy2(slow,td/'slow-b')
        j,_=runj(td,'--run','--run-all','--timeout=50','--total-runtime-budget=50','--max-runtime-targets=10')
        assert len(j['directory_plan']['runtime_selected'])==1
        assert any(x['state']=='SKIPPED_RUNTIME_BUDGET' for x in j['directory_plan']['runtime_skipped'])

    with tempfile.TemporaryDirectory(prefix='ar-dir-apply-') as td:
        td=pathlib.Path(td);shutil.copy2('/bin/true',td/'one');before=sha(td/'one')
        j,_=runj(td,'--run','--apply','--timeout=500','--max-runtime-targets=1','--total-runtime-budget=500')
        assert sha(td/'one')==before and not list(td.glob('one.bak*')) and all(not r['replacement']['performed'] for r in j['reports'])
        selected=next(r for r in j['reports'] if r['runtime']['requested']);install=next(x for x in selected['orchestration']['runtime_plan']['steps'] if x['analyzer']=='validated_transactional_install');assert install['selected'] and install['destructive']

    print('[PASS] default-recursive directory inventory/ranking/relations + symlink/unreadable safety + runtime target/budget/apply gates')
if __name__=='__main__': main()
