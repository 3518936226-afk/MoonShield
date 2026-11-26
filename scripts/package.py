"""Package a fresh public checkout without raw logs, tools or Git metadata."""
import hashlib,json,zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
version=json.loads((ROOT/'dist/manifest.json').read_text(encoding='utf-8'))['version']
out=ROOT/'releases';out.mkdir(exist_ok=True)
archive=out/f'MoonShield-v{version}-windows-x64.zip'
if archive.exists():raise SystemExit('Archive exists; preserve it and use a new version for a new release.')
top=['MoonShield.exe','MoonShield.ps1','moon.mod','moon.work','toolchain.lock.json','upstream.lock.json',
 'README.md','LICENSE','NOTICE','THIRD_PARTY_NOTICES.md','CHANGELOG.md','CONTRIBUTING.md','AGENTS.md','.gitignore','.gitattributes']
files=[ROOT/name for name in top]
for name in ['src','cmd','scripts','vendor','docs','licenses','examples','dist','.github']:
    files.extend(p for p in (ROOT/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc')
files=sorted(set(files))
manifest=dict(version=version,scope='Public source and precompiled runtime artifacts; tools/raw logs excluded',
 files={p.relative_to(ROOT).as_posix():dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in files})
prefix=f'MoonShield-v{version}/'
with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as z:
    for p in files:z.write(p,prefix+p.relative_to(ROOT).as_posix())
    z.writestr(prefix+'release-manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for name,item in manifest['files'].items():
        data=z.read(prefix+name)
        assert len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256']
    assert not any('/.git/' in n or '/work/' in n or '/evidence/' in n for n in z.namelist())
hashes=dict(file=archive.name,bytes=archive.stat().st_size,sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
(out/f'MoonShield-v{version}.sha256.json').write_text(json.dumps(hashes,indent=2),encoding='utf-8')
print(json.dumps(hashes,indent=2))
