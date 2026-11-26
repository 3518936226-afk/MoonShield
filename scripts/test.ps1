param([switch]$Integration)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tc = $env:MOONSHIELD_TOOLCHAIN
if (!$tc) { $tc = "$root\work\toolchain" }
$env:MOON_HOME = $tc
$env:MOONSHIELD_TOOLCHAIN = $tc
$env:TEMP = "$root\work\tmp"; $env:TMP = $env:TEMP; $env:TMPDIR = $env:TEMP
$env:PYTHONDONTWRITEBYTECODE = '1'; $env:PYTHONIOENCODING = 'utf-8'
$stamp = Get-Date -Format 'yyyyMMddTHHmmssffff'
$logs = "$root\evidence\suite-$stamp"
New-Item -ItemType Directory -Force -Path $logs | Out-Null
& "$PSScriptRoot\build.ps1" -Toolchain $tc
$moon = "$tc\bin\moon.exe"
& $moon -C $root test src --target wasm --frozen --target-dir "$root\work\unit-tests" 1> "$logs\unit.stdout.txt" 2> "$logs\unit.stderr.txt"
if ($LASTEXITCODE) { throw "Unit tests failed: $logs" }
& $moon -C $root test work/parser-build/moon_config work/parser-build/lexer work/parser-build/lexer/basic work/parser-build/lexer/tokens --target wasm --frozen --target-dir "$root\work\official-tests" 1> "$logs\parser.stdout.txt" 2> "$logs\parser.stderr.txt"
if ($LASTEXITCODE) { throw "Official parser tests failed: $logs" }
& "$root\MoonShield.ps1" verify --out $logs
if ($LASTEXITCODE) { throw "Runtime conformance NO-GO: $logs" }
if ($Integration) {
  if (!(Get-Command python -ErrorAction SilentlyContinue)) { throw 'Developer integration tests require existing Python 3; it will not be installed automatically.' }
  & python "$PSScriptRoot\acceptance.py"
  if ($LASTEXITCODE) { throw 'CLI integration tests failed' }
  & python "$PSScriptRoot\qualification.py"
  if ($LASTEXITCODE) { throw 'Real-project qualification failed' }
}
Write-Output "PASS: $logs"
