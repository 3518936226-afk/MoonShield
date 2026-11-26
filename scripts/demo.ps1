param([switch]$Fast)
$ErrorActionPreference = 'Stop'
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $OutputEncoding
$root = Split-Path $PSScriptRoot -Parent
$demo = "$root/evidence/demo-v1.2-$(Get-Date -Format yyyyMMddTHHmmssffff)"
New-Item -ItemType Directory -Force -Path $demo | Out-Null
$records = New-Object System.Collections.Generic.List[object]
$transcript = New-Object System.Text.StringBuilder
$encoding = New-Object System.Text.UTF8Encoding($false)
function Invoke-Step([string]$Name, [string[]]$CommandArgs, [int]$Expected) {
  Write-Host "`n=== $Name ==="
  Write-Host ('.\MoonShield.exe ' + ($CommandArgs -join ' '))
  $stderr = "$demo/$Name.stderr.txt"
  $lines = @(& "$root/MoonShield.exe" @CommandArgs 2> $stderr)
  $code = $LASTEXITCODE
  $stdout = $lines -join "`n"
  [System.IO.File]::WriteAllText("$demo/$Name.stdout.txt", $stdout + "`n", $encoding)
  Write-Host $stdout
  [void]$transcript.AppendLine("=== $Name ===")
  [void]$transcript.AppendLine($stdout)
  [void]$transcript.AppendLine("Exit: $code (expected $Expected)")
  [void]$records.Add([ordered]@{step=$Name;program="$root/MoonShield.exe";argv=$CommandArgs;cwd=$root;exit_code=$code;expected_exit_code=$Expected;passed=($code -eq $Expected);stdout=$stdout;stderr_file=$stderr;capture='UTF-8 text lines; verify subfolder retains original process bytes'})
  [System.IO.File]::WriteAllText("$demo/steps.json", ($records | ConvertTo-Json -Depth 20), $encoding)
  if ($code -ne $Expected) {
    $failed = [ordered]@{version='1.2.0';passed=$false;failed_step=$Name;steps=$records}
    [System.IO.File]::WriteAllText("$demo/results.json", ($failed | ConvertTo-Json -Depth 20), $encoding)
    throw "Unexpected exit in $Name; evidence: $demo"
  }
}
Push-Location $root
try {
  Invoke-Step '01-doctor' @('doctor') 0
  Invoke-Step '02-empty-policy' @('audit','examples/empty.mbtx','--format','text') 0
  Invoke-Step '03-risk-findings' @('audit','examples/risky.mbtx','--format','text') 1
  Invoke-Step '04-escaped-wildcard' @('audit','examples/escaped.mbtx','--format','text') 1
  Invoke-Step '05-effective-override' @('audit','examples/risky.mbtx','--policy','examples/policies/deny.json','--format','text') 0
  Invoke-Step '06-sarif-export' @('audit','examples/risky.mbtx','--format','sarif','--out',"$demo/report.sarif") 1
  Invoke-Step '07-inherited-context' @('audit','examples/empty.mbtx','--inherit','examples/policies/parent.json','--format','text') 0
  Invoke-Step '08-metadata-context' @('audit','examples/orders/orders.mbtx','--path-context','inspect','--format','text') 1
  Invoke-Step '09-unsupported' @('audit','examples/official-corpus/embedded_policy.mbtx','--format','text') 1
  if (!$Fast) { Invoke-Step '10-runtime-conformance' @('verify','--out',$demo) 0 }
  else { Write-Host 'Runtime verification skipped explicitly (-Fast). No runtime GO is claimed.' }
  $result = [ordered]@{version='1.2.0';passed=$true;runtime_verification_skipped=[bool]$Fast;steps=$records}
  [System.IO.File]::WriteAllText("$demo/results.json", ($result | ConvertTo-Json -Depth 20), $encoding)
  [System.IO.File]::WriteAllText("$demo/TRANSCRIPT.txt", $transcript.ToString(), $encoding)
  Write-Output "Demo PASS: $demo"
} finally { Pop-Location }
