"""Public corpus static checks + owned realistic Wasm workload. No installs."""
import datetime,hashlib,json,os,platform,shutil,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
STAMP=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y%m%dT%H%M%S%f')
OUT=ROOT/'evidence'/('qualification-'+STAMP);OUT.mkdir()
WORK=ROOT/'work'/('qualification-'+STAMP);WORK.mkdir()
TC=Path(os.environ.get('MOONSHIELD_TOOLCHAIN',str(ROOT/'work/toolchain')))
ENV=os.environ.copy();ENV.update(MOON_HOME=str(TC),MOONSHIELD_TOOLCHAIN=str(TC),TEMP=str(WORK),TMP=str(WORK),TMPDIR=str(WORK),PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8')
# os.environ is case-insensitive on Windows; a copied plain dict is not.
MINIMAL={k:os.environ[k] for k in ('SystemRoot','WINDIR') if k in os.environ}
MINIMAL.update(TEMP=str(WORK),TMP=str(WORK),TMPDIR=str(WORK),MOONSHIELD_TOOLCHAIN=str(TC))
ROWS=[];COMMANDS=[];COMPLETED=False

def persist():
    summary=dict(tests=len(ROWS),passed=sum(r['passed'] for r in ROWS),suite_complete=COMPLETED,
      verdict='GO' if COMPLETED and len(ROWS)==39 and all(r['passed'] for r in ROWS) else 'NO-GO',rows=ROWS,commands=COMMANDS,
      environment=dict(os=platform.platform(),architecture=platform.machine(),toolchain=str(TC),
       minimal_environment_keys=sorted(MINIMAL),content='synthetic only',other_host_tested=False),
      compatibility=[dict(platform='Windows x64',toolchain='0.1.20261119 (738607b)',status='TESTED'),
       dict(platform='Linux / macOS',status='NOT_TESTED'),dict(platform='other toolchain versions',status='NOT_TESTED')])
    (OUT/'results.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    return summary

def invoke(label,argv,cwd=WORK,env=ENV):
    p=subprocess.run(list(map(str,argv)),cwd=cwd,env=env,capture_output=True,timeout=120,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    for stream in ('stdout','stderr'):(OUT/f'{label}.{stream}.bin').write_bytes(getattr(p,stream))
    row=dict(label=label,argv=list(map(str,argv)),cwd=str(cwd),exit_code=p.returncode,
      stdout=p.stdout.decode('utf-8','replace'),stderr=p.stderr.decode('utf-8','replace'),
      environment='minimal synthetic' if env is MINIMAL else 'configured compiler environment (values omitted)')
    COMMANDS.append(row);persist()
    return row

def check(label,row,passed,**extra):
    ROWS.append(dict(label=label,passed=bool(passed),command=COMMANDS.index(row),**extra));persist()
    print(label,bool(passed),flush=True)

try:
    # Public real project data. Bodies and imports are never built or run.
    corpus=ROOT/'examples/official-corpus'
    provenance=json.loads((corpus/'provenance.json').read_text(encoding='utf-8'))
    for f in provenance['files']:assert hashlib.sha256((corpus/f['file']).read_bytes()).hexdigest()==f['sha256']
    statuses={'embedded_policy.mbtx':'UNSUPPORTED','malformed_embedded_policy.mbtx':'UNSUPPORTED',
     'front_matter_permission.mbtx':'REVIEW_REQUIRED','import_block_ok.mbtx':'REVIEW_REQUIRED',
     'build config.mbtx':'REVIEW_REQUIRED','leaf.mbtx':'NO_FINDINGS'}
    for rep in range(1,4):
        for name,status in statuses.items():
            label=f'corpus-{Path(name).stem}-{rep}'
            row=invoke(label,[ROOT/'MoonShield.exe','audit',corpus/name])
            data=json.loads(row['stdout'])
            check(label,row,row['exit_code']==(0 if status=='NO_FINDINGS' else 1) and data['status']==status and not data['source_executed'],expected_status=status)
    # Owned workload runs only in a unique D: directory; no real orders or credentials.
    (WORK/'moon.mod').write_text('name = "moonshield-workload"\nversion = "0.0.0"\n',encoding='utf-8')
    (WORK/'moon.work').write_text('members = ["."]\n',encoding='utf-8')
    shutil.copyfile(ROOT/'examples/orders/orders.mbtx',WORK/'orders.mbtx')
    shutil.copyfile(ROOT/'examples/orders/orders.csv',WORK/'orders.csv')
    (WORK/'unrelated.csv').write_text('SYNTHETIC_UNRELATED',encoding='utf-8')
    (OUT/'orders.mbtx').write_bytes((WORK/'orders.mbtx').read_bytes())
    (OUT/'orders.csv').write_bytes((WORK/'orders.csv').read_bytes())
    row=invoke('compile-orders',[TC/'bin/moon.exe','build','--target','wasm','--frozen','--target-dir',WORK/'build-orders',WORK/'orders.mbtx'])
    assert row['exit_code']==0,'Trusted orders workload compilation failed; retained logs'
    artifacts=list((WORK/'build-orders').rglob('*.wasm'));assert len(artifacts)==1
    wasm=artifacts[0]
    cases=[('allow',{'fs':{'read':['orders.csv'],'write':[{'glob':'summary.txt'}]}},'allow'),
     ('read-denied',{},'file read'),
     ('write-denied',{'fs':{'read':['orders.csv']}},'file write'),
     ('wrong-read-file',{'fs':{'read':['unrelated.csv'],'write':[{'glob':'summary.txt'}]}},'file read')]
    for name,policy,expectation in cases:
        p=WORK/(name+'.json');p.write_text(json.dumps(policy),encoding='utf-8');shutil.copyfile(p,OUT/p.name)
        for rep in range(1,4):
            # Use separate output name per run by backing up own generated summary, never delete evidence.
            summary=WORK/'summary.txt'
            if summary.exists():shutil.move(summary,WORK/f'summary-before-{name}-{rep}.txt')
            label=f'orders-{name}-{rep}'
            row=invoke(label,[TC/'bin/moonrun.exe','--policy',p,wasm],env=MINIMAL)
            if expectation=='allow':
                passed=row['exit_code']==0 and row['stdout'].strip()=='orders=3;total_cents=4990' and summary.read_text(encoding='utf-8')=='orders=3;total_cents=4990'
                shutil.copyfile(summary,OUT/f'{label}.summary.txt')
            else:passed=row['exit_code']==1 and f'Sandbox policy blocked {expectation}' in row['stderr'] and not summary.exists()
            check(label,row,passed,backend='real Moonrun Wasm',expected=expectation)
    # Noop is owned too. These verify valid JSON null is a coverage gap, while bad FS object is invalid.
    (WORK/'noop.mbtx').write_text('---\npermission()\n---\nfn main { println("OWNED_NOOP") }\n',encoding='utf-8')
    row=invoke('compile-noop',[TC/'bin/moon.exe','build','--target','wasm','--frozen','--target-dir',WORK/'build-noop',WORK/'noop.mbtx'])
    assert row['exit_code']==0
    noop=list((WORK/'build-noop').rglob('*.wasm'));assert len(noop)==1
    for name,value,accepted in [('optional-null',{'fs':None},True),('invalid-fs-object',{'fs':{'read':[{'typo':'x'}]}},False)]:
        p=WORK/(name+'.json');p.write_text(json.dumps(value),encoding='utf-8');shutil.copyfile(p,OUT/p.name)
        for rep in range(1,4):
            label=f'schema-runtime-{name}-{rep}'
            row=invoke(label,[TC/'bin/moonrun.exe','--policy',p,noop[0]],env=MINIMAL)
            passed=(row['exit_code']==0 and row['stdout'].strip()=='OWNED_NOOP') if accepted else (row['exit_code']!=0 and 'OWNED_NOOP' not in row['stdout'] and 'policy' in row['stderr'].lower())
            check(label,row,passed,backend='real Moonrun Wasm',expected_runtime_acceptance=accepted)
    # Deliberately clean cwd and minimal launcher environment. Same machine, no claim of another PC.
    clean=WORK/'empty-cwd';clean.mkdir()
    for rep in range(1,4):
        label=f'minimal-launcher-{rep}'
        row=invoke(label,[ROOT/'MoonShield.exe','audit',ROOT/'examples/empty.mbtx'],cwd=clean,env=MINIMAL)
        try:data=json.loads(row['stdout'])
        except ValueError:data={}
        check(label,row,row['exit_code']==0 and data['status']=='NO_FINDINGS' and not data['source_executed'])
    COMPLETED=True
    summary=persist()
    print(json.dumps(dict(tests=summary['tests'],passed=summary['passed'],evidence=str(OUT)),indent=2))
    sys.exit(0 if summary['tests']==summary['passed'] else 1)
except Exception as error:
    (OUT/'harness-error.txt').write_text(str(error),encoding='utf-8');persist();raise
