#!/usr/bin/env python3
import hashlib,json,pathlib,shutil,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
AR=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'build/auto-refirst'

def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def runj(p,*args):
    cp=subprocess.run([str(AR),str(p),*args,'--json'],text=True,capture_output=True,timeout=30)
    if cp.returncode: raise AssertionError((cp.returncode,cp.stdout[-1000:],cp.stderr[-2000:]))
    return json.loads(cp.stdout),cp

def step(j,name): return next(x for x in j['orchestration']['runtime_plan']['steps'] if x['analyzer']==name)

def main():
    if sys.platform.startswith('win'):
        print('[SKIP] Linux runtime authorization regression')
        return
    with tempfile.TemporaryDirectory(prefix='ar-runtime-auth-') as raw:
        td=pathlib.Path(raw)
        legacy=td/'legacy'; shutil.copy2('/bin/true',legacy); before=sha(legacy)
        j,cp=runj(legacy,'--run=unpack','--timeout=1000')
        assert 'DEPRECATED' in cp.stderr and 'non-destructive' in cp.stderr
        assert j['orchestration']['runtime_plan']['policy']=='legacy_unpack_non_destructive'
        assert not step(j,'validated_transactional_install')['selected']
        assert not j['replacement']['performed'] and sha(legacy)==before
        assert not list(td.glob('legacy.bak*'))

        explicit=td/'explicit'; shutil.copy2('/bin/true',explicit); before=sha(explicit)
        j,cp=runj(explicit,'--run=unpack','--apply','--timeout=1000')
        assert j['orchestration']['runtime_plan']['policy']=='legacy_unpack_apply'
        assert step(j,'validated_transactional_install')['selected']
        # /bin/true does not produce a validated replacement candidate; authorization
        # is exercised without modifying the fixture.
        assert not j['replacement']['performed'] and sha(explicit)==before
    print('[PASS] runtime authorization: legacy alias is non-destructive; install requires explicit --apply')
if __name__=='__main__': main()
