param([string]$Toolchain = $env:MOONSHIELD_TOOLCHAIN)
$ErrorActionPreference = 'Stop'
function FileHash([string]$Path) {
  $stream = [System.IO.File]::OpenRead($Path)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLower() } finally { $sha.Dispose() }
  } finally { $stream.Dispose() }
}
$root = Split-Path $PSScriptRoot -Parent
if (!$Toolchain -and (Test-Path "$root\work\toolchain\bin\moon.exe")) { $Toolchain = "$root\work\toolchain" }
if (!$Toolchain) { throw 'Set MOONSHIELD_TOOLCHAIN or prepare work/toolchain with scripts/bootstrap.ps1' }
$Toolchain = (Resolve-Path -LiteralPath $Toolchain).Path
$env:MOON_HOME = $Toolchain
$env:MOONSHIELD_TOOLCHAIN = $Toolchain
$env:TEMP = "$root\work\tmp"
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
$env:PATH = "$Toolchain\bin;$env:PATH"
New-Item -ItemType Directory -Force -Path $env:TEMP,"$root\dist","$root\evidence" | Out-Null
$lock = Get-Content -Raw "$root\toolchain.lock.json" | ConvertFrom-Json
foreach ($entry in $lock.files.PSObject.Properties) {
  $path = Join-Path $Toolchain $entry.Name
  if (!(Test-Path -LiteralPath $path) -or (FileHash $path) -ne $entry.Value) { throw "Toolchain mismatch: $($entry.Name)" }
}
$up = Get-Content -Raw "$root\upstream.lock.json" | ConvertFrom-Json
foreach ($entry in $up.files.PSObject.Properties) {
  $path = Join-Path $root $entry.Name
  if ((FileHash $path) -ne $entry.Value) { throw "Upstream mismatch: $($entry.Name)" }
}
New-Item -ItemType Directory -Force -Path "$root\work\parser-build" | Out-Null
Copy-Item "$root\vendor\parser\*" "$root\work\parser-build" -Recurse -Force
$manifest = "$root\work\parser-build\lexer\tokens\moon.pkg"
$text = Get-Content -Raw $manifest
[System.IO.File]::WriteAllText($manifest, $text.Substring(0,$text.IndexOf('rule(')).TrimEnd() + "`n", (New-Object System.Text.UTF8Encoding($false)))
$moon = "$Toolchain\bin\moon.exe"
& $moon -C $root build cmd --target wasm --release --frozen --target-dir "$root\work\build"
if ($LASTEXITCODE) { throw 'MoonBit build failed' }
$artifacts = @(Get-ChildItem "$root\work\build" -Recurse -Force -Filter *.wasm)
if ($artifacts.Count -ne 1) { throw 'Ambiguous artifact set' }
Copy-Item -LiteralPath $artifacts[0].FullName -Destination "$root\dist\moonshield.wasm" -Force
$release = [ordered]@{version='1.2.0';wasm_sha256=(FileHash "$root\dist\moonshield.wasm");toolchain='Pinned external toolchain; see toolchain.lock.json';source='MoonBit Wasm; not Native isolation evidence'}
[System.IO.File]::WriteAllText("$root\dist\manifest.json", ($release | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Built $root\dist\moonshield.wasm"
if (Test-Path 'C:\mingw64\bin\gcc.exe') {
  & 'C:\mingw64\bin\gcc.exe' '-O2' '-static' '-municode' "$root\scripts\launcher.c" '-o' "$root\MoonShield.exe"
  if ($LASTEXITCODE) { throw 'Windows launcher build failed' }
}
