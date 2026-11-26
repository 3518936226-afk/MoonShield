"""Developer-only acceptance harness. End-user CLI has no Python dependency."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
STAMP=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime('%Y%m%dT%H%M%S%f')
OUT=ROOT/'evidence'/('acceptance-'+STAMP)
WORK=ROOT/'work'/('acceptance-'+STAMP)
OUT.mkdir(parents=True);WORK.mkdir()
ENV=os.environ.copy();ENV.update(TEMP=str(ROOT/'work/tmp'),TMP=str(ROOT/'work/tmp'),TMPDIR=str(ROOT/'work/tmp'),PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8')
ROWS=[]

def run(label,args,expected,predicate=lambda x:True):
    argv=[str(ROOT/'MoonShield.exe'),*map(str,args)]
    p=subprocess.run(argv,cwd=ROOT,env=ENV,capture_output=True,timeout=90,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    for name in ['stdout','stderr']:(OUT/f'{len(ROWS):03}-{label}.{name}.bin').write_bytes(getattr(p,name))
    text=p.stdout.decode('utf-8','replace')
    try:data=json.loads(text)
    except ValueError:data={'text':text}
    passed=p.returncode==expected and predicate(data)
    row=dict(label=label,argv=argv,cwd=str(ROOT),exit_code=p.returncode,expected_exit_code=expected,
             stdout=text,stderr=p.stderr.decode('utf-8','replace'),passed=bool(passed))
    ROWS.append(row);print(label,passed,flush=True)
    return data

def fixture(name,policy):
    p=WORK/(name+'.mbtx')
    p.write_text('---\n'+policy+'\n---\nfn main { abort("CANDIDATE_BODY_MUST_NOT_EXECUTE") }\n',encoding='utf-8')
    return p

def has(code):return lambda d:any(f['code']==code for f in d.get('findings',[]))

cases=[
 ('wildcard','permission(fs:{"read":["*"]})','FS_BROAD_SCOPE'),
 ('unicode-star',r'permission(fs:{"read":["\u002a"]})','FS_BROAD_SCOPE'),
 ('unicode-key',r'permission(fs:{"\u0072ead":["*"]})','FS_BROAD_SCOPE'),
 ('bad-braces',r'permission(env:{"from_host":["\u{002a}"]})','INVALID_LITERAL'),
 ('duplicate','permission(fs:{"read":[],"read":["*"]})','DUPLICATE_KEY'),
 ('decoded-duplicate',r'permission(fs:{"read":[],"\u0072ead":[]})','DUPLICATE_KEY'),
 ('syntax','permission(fs:{"read":[})','CONFIG_SYNTAX'),
 ('unknown','permission(fs:{"reed":[]})','UNKNOWN_FIELD'),
 ('env-all','permission(env:{"from_host":["*"]})','ENV_HOST_ALL'),
 ('network','permission(net:{"connect":["*:*"]})','NETWORK_WILDCARD'),
 ('shell','permission(process:{"allow":[{"program":"cmd.exe","args_prefix":["/c"]}]})','PROCESS_INTERPRETER'),
 ('win-shell',r'permission(process:{"allow":[{"program":"C:\\Windows\\System32\\cmd.exe"}]})','PROCESS_INTERPRETER'),
]
files=[(label,fixture(label,policy),code) for label,policy,code in cases]
weird=WORK/'中文 空格 & % $(noop).mbtx';weird.write_bytes((ROOT/'examples/empty.mbtx').read_bytes())
jsondup=WORK/'duplicate.json';jsondup.write_text('{"fs":{},"fs":{}}',encoding='utf-8')
toml=WORK/'policy.toml';toml.write_text('[fs]\nread=[]',encoding='utf-8')
redacted=fixture('literal','permission(env:{"set":{"KEY":"SYNTHETIC_DO_NOT_LEAK_0917"}})')
missing_header=WORK/'no-header.mbtx';missing_header.write_text('fn main { abort("BODY_MUST_NOT_RUN") }',encoding='utf-8')
scanroot=WORK/'scan-root';scanroot.mkdir()
(scanroot/'inside.mbtx').write_bytes((ROOT/'examples/empty.mbtx').read_bytes())
outside=WORK/'outside';outside.mkdir()
(outside/'outside.mbtx').write_bytes((ROOT/'examples/risky.mbtx').read_bytes())
prep_env=ENV.copy();prep_env.update(MOONSHIELD_LINK=str(scanroot/'escape'),MOONSHIELD_LINK_TARGET=str(outside))
prep=subprocess.run(['powershell','-NoProfile','-Command','New-Item -ItemType Junction -Path $env:MOONSHIELD_LINK -Target $env:MOONSHIELD_LINK_TARGET -ErrorAction Stop | Out-Null'],env=prep_env,capture_output=True)
(OUT/'junction-fixture.stdout.bin').write_bytes(prep.stdout)
(OUT/'junction-fixture.stderr.bin').write_bytes(prep.stderr)
assert prep.returncode==0,'Mandatory junction fixture failed; do not claim the scan check passed'
before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in WORK.iterdir() if p.is_file()}
for rep in range(1,4):
    run('empty-'+str(rep),['audit','examples/empty.mbtx'],0,lambda d:d['status']=='NO_FINDINGS' and not d['source_executed'])
    run('unicode-path-'+str(rep),['audit',weird],0,lambda d:d['target']==str(weird))
    for label,path,code in files:run(label+'-'+str(rep),['audit',path],1,has(code))
    run('override-'+str(rep),['audit','examples/risky.mbtx','--policy','examples/policies/deny.json'],0,lambda d:d['embedded']['status']=='REVIEW_REQUIRED' and d['selected']['status']=='NO_FINDINGS')
    run('inherit-'+str(rep),['audit','examples/empty.mbtx','--inherit','examples/policies/parent.json'],0,lambda d:len(d['inherited'])==1 and d['status']=='NO_FINDINGS' and d['findings'][0]['severity']=='info' and d['configuration_findings'][0]['severity']=='high')
    run('json-duplicate-'+str(rep),['audit',jsondup],1,lambda d:d['status']=='INVALID')
    run('toml-unsupported-'+str(rep),['audit',toml,'--fail-on','error'],1,lambda d:d['selected']['coverage']=='INCOMPLETE' and d['status']=='UNSUPPORTED')
    run('redaction-'+str(rep),['audit',redacted],1,lambda d:'SYNTHETIC_DO_NOT_LEAK_0917' not in json.dumps(d))
    run('threshold-'+str(rep),['audit','examples/risky.mbtx','--fail-on','error'],0,lambda d:d['status']=='REVIEW_REQUIRED')
    sarif=run('sarif-'+str(rep),['audit','examples/risky.mbtx','--format','sarif'],1,lambda d:d.get('version')=='2.1.0' and len(d['runs'][0]['results'])>0)
    run('markdown-'+str(rep),['audit','examples/risky.mbtx','--format','md'],1,lambda d:d['text'].startswith('# MoonShield'))
    run('text-zh-'+str(rep),['audit','examples/risky.mbtx','--format','text'],1,lambda d:'需要人工复核' in d['text'] and '建议：' in d['text'] and 'FS_BROAD_SCOPE' in d['text'])
    run('text-en-'+str(rep),['audit','examples/risky.mbtx','--format','text','--lang','en'],1,lambda d:'Status: REVIEW_REQUIRED' in d['text'] and 'Action:' in d['text'])
    run('text-empty-'+str(rep),['audit','examples/empty.mbtx','--format','text'],0,lambda d:'当前上下文内无待处理风险' in d['text'] and '无发现不等于脚本安全' in d['text'])
    run('md-no-range-'+str(rep),['audit',missing_header,'--format','md'],1,lambda d:':null:null' not in d['text'])
    run('human-redaction-'+str(rep),['audit',redacted,'--format','text'],1,lambda d:'SYNTHETIC_DO_NOT_LEAK_0917' not in d['text'])
    run('bad-language-'+str(rep),['audit','examples/empty.mbtx','--lang','jp'],2)
    # Keep the original four owned examples independent of added public corpus formats.
    owned_scan=WORK/'owned-scan';owned_scan.mkdir(exist_ok=True)
    for p in (ROOT/'examples').glob('*.mbtx'):(owned_scan/p.name).write_bytes(p.read_bytes())
    run('scan-'+str(rep),['scan',owned_scan],1,lambda d:d['files']==4 and not d['source_executed'])
    run('scan-threshold-'+str(rep),['scan',owned_scan,'--fail-on','error'],0,lambda d:d['status']=='REVIEW_REQUIRED' and len(d['findings'])>0)
    run('junction-scan-'+str(rep),['scan',scanroot],1,lambda d:d['files']==1 and len(d['skipped'])==1 and all('outside.mbtx' not in r['target'] for r in d['reports']))
    run('bad-option-'+str(rep),['audit','examples/empty.mbtx','--bogus','x'],2)
    run('repeat-too-small-'+str(rep),['verify','--repeat','2'],2)
    run('missing-file-'+str(rep),['audit',WORK/'does-not-exist.mbtx'],2)
run('doctor',['doctor'],0,lambda d:d['status']=='READY' and d['python_required'] is False)
run('version',['--version'],0,lambda d:d['text'].strip()=='MoonShield 1.2.0')
# Persisted format verification and output path handling.
saved=WORK/'report.sarif'
run('saved-sarif',['audit','examples/risky.mbtx','--format','sarif','--out',saved],1,lambda d:saved.is_file())
assert json.loads(saved.read_text(encoding='utf-8'))['version']=='2.1.0'
# New schema-v2 cases: actual CLI adapter, not mocked filesystem observations.
(WORK/'data.csv').write_text('SYNTHETIC_CONTENT_MUST_NOT_APPEAR_120',encoding='utf-8')
(WORK/'data-dir').mkdir()
literal=fixture('file-context','permission(fs:{"read":["data.csv"]})')
directory=fixture('dir-context','permission(fs:{"read":["data-dir"]})')
missing=fixture('missing-context','permission(fs:{"read":["missing.csv"]})')
alias=fixture('alias-context','permission(fs:{"read":["scan-root/escape/alias.csv"]})')
(outside/'alias.csv').write_text('SYNTHETIC_ALIAS_NO_READ',encoding='utf-8')
nullpolicy=WORK/'null.json';nullpolicy.write_text('{"fs":null}',encoding='utf-8')
invalidtype=fixture('invalid-schema','permission(fs:{"read":true})')
legacy=WORK/'legacy.mbtx';legacy.write_text('// policy:\n//   fs: {}\nfn main {}',encoding='utf-8')
unclosed=WORK/'unclosed.mbtx';unclosed.write_text('---\npermission()',encoding='utf-8')
for rep in range(1,4):
    run('literal-static-'+str(rep),['audit',literal],1,lambda d:d['path_context']['mode']=='static' and d['findings'][0]['severity']=='warning')
    run('literal-inspect-'+str(rep),['audit',literal,'--path-context','inspect'],0,lambda d:d['status']=='NO_FINDINGS' and d['findings'][0]['assessment']=='observed_regular_file' and d['configuration_findings'][0]['severity']=='warning' and 'SYNTHETIC_CONTENT_MUST_NOT_APPEAR_120' not in json.dumps(d))
    run('directory-inspect-'+str(rep),['audit',directory,'--path-context','inspect'],1,lambda d:d['path_context']['observations'][0]['status']=='DIRECTORY')
    run('missing-inspect-'+str(rep),['audit',missing,'--path-context','inspect'],1,lambda d:d['path_context']['observations'][0]['status']=='UNAVAILABLE')
    run('alias-inspect-'+str(rep),['audit',alias,'--path-context','inspect'],1,lambda d:d['path_context']['observations'][0]['status']=='CANONICAL_MISMATCH')
    run('null-unsupported-'+str(rep),['audit',nullpolicy,'--fail-on','error'],1,lambda d:d['status']=='UNSUPPORTED' and d['summary']['unsupported']==1)
    run('invalid-not-unsupported-'+str(rep),['audit',invalidtype],1,lambda d:d['status']=='INVALID' and d['summary']['configuration_errors']==1 and d['summary']['unsupported']==0)
    run('legacy-unsupported-'+str(rep),['audit',legacy],1,lambda d:d['status']=='UNSUPPORTED')
    run('unclosed-invalid-'+str(rep),['audit',unclosed],1,lambda d:d['status']=='INVALID')
    run('unsupported-override-'+str(rep),['audit',legacy,'--policy','examples/policies/deny.json'],1,lambda d:d['status']=='UNSUPPORTED')
    run('invalid-ceiling-'+str(rep),['audit','examples/risky.mbtx','--inherit',invalidtype],1,lambda d:d['status']=='INVALID' and any(f['severity']=='high' for f in d['findings']))
    run('bad-path-mode-'+str(rep),['audit',literal,'--path-context','guess'],2)
    run('information-sarif-'+str(rep),['audit','examples/empty.mbtx','--inherit','examples/policies/parent.json','--format','sarif'],0,lambda d:all(f['level']=='note' for f in d['runs'][0]['results']))
unchanged=all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in before.items())
ROWS.append(dict(label='inputs-unchanged',passed=unchanged))
summary=dict(tests=len(ROWS),passed=sum(x['passed'] for x in ROWS),rows=ROWS)
(OUT/'results.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(tests=summary['tests'],passed=summary['passed'],evidence=str(OUT)),indent=2))
sys.exit(0 if summary['tests']==summary['passed'] else 1)
