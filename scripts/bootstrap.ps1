param([string]$ArchiveDir = '', [switch]$Download, [string]$BinaryArchive = '', [string]$CoreArchive = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$env:TEMP = "$root\work\tmp"; $env:TMP = $env:TEMP; $env:TMPDIR = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP,"$root\work\downloads" | Out-Null
$target = "$root\work\toolchain"
if (Test-Path -LiteralPath $target) { throw 'Keep the existing toolchain. Bootstrap into a fresh checkout; nothing was deleted.' }
$archives = @(
  @{name='moonbit-windows-x86_64.zip';url='https://cli.moonbitlang.com/binaries/0.10.22%2B124d61d05/moonbit-windows-x86_64.zip';sha='8e552848a5c06dcce6bab725687562a689397948b7144e9087e9ffa4c1d38be4'},
  @{name='core.zip';url='https://cli.moonbitlang.com/cores/core-0.10.22%2B124d61d05.zip';sha='2ce9e6112f2db09eeb52c7865459df3de27e42badb6be26db77347187ab8fbfe'}
)
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($item in $archives) {
  $file = if ($item.name -eq 'core.zip' -and $CoreArchive) { $CoreArchive }
    elseif ($item.name -ne 'core.zip' -and $BinaryArchive) { $BinaryArchive }
    elseif ($ArchiveDir) { Join-Path $ArchiveDir $item.name } else { "$root\work\downloads\$($item.name)" }
  if (!(Test-Path -LiteralPath $file)) {
    if (!$Download) { throw "Missing archive $file. Supply -ArchiveDir or explicitly opt into -Download." }
    & "$env:SystemRoot\System32\curl.exe" -fL --connect-timeout 15 --max-time 300 $item.url -o $file
    if ($LASTEXITCODE) { throw 'Official archive download failed; no replacement version is accepted.' }
  }
  $stream = [System.IO.File]::OpenRead($file)
  try { $sha = [System.Security.Cryptography.SHA256]::Create(); $actual = [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLower() }
  finally { $stream.Dispose(); if ($sha) { $sha.Dispose() } }
  if ($actual -ne $item.sha) { throw "Archive checksum mismatch: $file" }
  $dest = if ($item.name -eq 'core.zip') { "$target\lib" } else { $target }
  $prefix = [System.IO.Path]::GetFullPath($dest).TrimEnd('\') + '\'
  $zip = [System.IO.Compression.ZipFile]::OpenRead($file)
  try {
    foreach ($entry in $zip.Entries) {
      $resolved = [System.IO.Path]::GetFullPath((Join-Path $dest $entry.FullName))
      if (!$resolved.StartsWith($prefix,[System.StringComparison]::OrdinalIgnoreCase)) { throw 'Archive path escaped destination' }
    }
  } finally { $zip.Dispose() }
  [System.IO.Compression.ZipFile]::ExtractToDirectory($file,$dest)
}
$env:MOON_HOME = $target
$env:PATH = "$target\bin;$env:PATH"
Push-Location "$target\lib\core"
try {
  & "$target\bin\moon.exe" bundle --target wasm --warn-list '-a'
  if ($LASTEXITCODE) { throw 'Wasm core bundle failed' }
} finally { Pop-Location }
Write-Output "Prepared isolated toolchain: $target"
