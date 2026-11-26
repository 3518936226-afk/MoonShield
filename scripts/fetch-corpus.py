"""One-time, pinned public test data download. Never executes corpus scripts."""
import hashlib,json,urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'examples'/'official-corpus'
COMMIT='738607b3e4005a0343f09b744dbde641b38de64c'
BASE=f'https://raw.githubusercontent.com/moonbitlang/moon/{COMMIT}/'
PATHS=[
 'LICENSE',
 'crates/moon/tests/test_cases/moon_test_single_file.in/embedded_policy.mbtx',
 'crates/moon/tests/test_cases/moon_test_single_file.in/front_matter_permission.mbtx',
 'crates/moon/tests/test_cases/moon_test_single_file.in/malformed_embedded_policy.mbtx',
 'crates/moon/tests/test_cases/moon_test_single_file.in/import_block_ok.mbtx',
 'crates/moon/tests/test_cases/prebuild_config_script/mbtx/build config.mbtx',
 'crates/moonrun/tests/test_cases/test_virtual_moon.in/leaf.mbtx',
]
OUT.mkdir(exist_ok=True)
rows=[]
for name in PATHS:
    url=BASE+urllib.parse.quote(name)
    data=urllib.request.urlopen(url,timeout=45).read()
    path=OUT/Path(name).name
    if path.exists():assert path.read_bytes()==data,'Existing corpus changed; refusing overwrite'
    else:path.write_bytes(data)
    rows.append(dict(file=path.name,upstream_path=name,url=url,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
(OUT/'provenance.json').write_text(json.dumps(dict(repository='https://github.com/moonbitlang/moon',commit=COMMIT,license='Apache-2.0',execution='STATIC_ONLY; bodies never compiled or executed',files=rows),indent=2),encoding='utf-8')
print(json.dumps(rows,indent=2))
