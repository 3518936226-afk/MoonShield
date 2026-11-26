$ErrorActionPreference = 'Stop'
trap { Write-Output '{"status":"ERROR","message":"Launcher failed: check pinned toolchain, artifact hash and paths. No candidate code was executed."}'; exit 2 }
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $OutputEncoding
[Console]::InputEncoding = $OutputEncoding
function FileHash([string]$Path) {
  $stream = [System.IO.File]::OpenRead($Path)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLower() } finally { $sha.Dispose() }
  } finally { $stream.Dispose() }
}
$root = Split-Path $PSScriptRoot -Parent
$tc = $env:MOONSHIELD_TOOLCHAIN
if (!$tc -and (Test-Path "$root\work\toolchain\bin\moon.exe")) { $tc = "$root\work\toolchain" }
if (!$tc) { throw 'Set MOONSHIELD_TOOLCHAIN or prepare work/toolchain with scripts/bootstrap.ps1' }
$tc = (Resolve-Path -LiteralPath $tc).Path
$lock = Get-Content -Raw "$root\toolchain.lock.json" | ConvertFrom-Json
foreach ($name in @('moon.exe','moonc.exe','moonrun.exe')) {
  $file = "$tc\bin\$name"
  $expected = $lock.files.PSObject.Properties["bin/$name"].Value
  if ((FileHash $file) -ne $expected) { throw "NO-GO: unverified $name" }
}
$release = Get-Content -Raw "$root\dist\manifest.json" | ConvertFrom-Json
if ((FileHash "$root\dist\moonshield.wasm") -ne $release.wasm_sha256) { throw 'NO-GO: auditor artifact changed' }
$env:MOON_HOME = $tc
$env:MOONSHIELD_TOOLCHAIN = $tc
$env:MOONSHIELD_ROOT = $root
$env:TEMP = "$root\work\tmp"
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
# PowerShell 5 can silently skip an absolute .exe when PATHEXT lacks .EXE.
# This is launcher provisioning only, never a guest permission grant.
if (!$env:PATHEXT -or !($env:PATHEXT.Split(';') -contains '.EXE')) { $env:PATHEXT = '.EXE;' + $env:PATHEXT }
$global:LASTEXITCODE = $null
& "$tc\bin\moonrun.exe" "$root\dist\moonshield.wasm" -- @args
if ($null -eq $LASTEXITCODE) { throw 'Moonrun was not executed; refusing an empty success' }
exit $LASTEXITCODE
