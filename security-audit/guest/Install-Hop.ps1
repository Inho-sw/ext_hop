<#
.SYNOPSIS
    (게스트) 공식 HOP MSI 를 해시 재확인 후 무인 설치한다.
#>
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$MsiPath,
    [Parameter(Mandatory)][string]$Sha256
)
$ErrorActionPreference = 'Stop'

$actual = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $Sha256.ToLowerInvariant()) { throw "MSI 해시 불일치: $actual" }

$logDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$msiLog = Join-Path $logDir 'hop-install.log'
$started = Get-Date

# /qn 무인 설치. AUTOLAUNCHAPP 은 지정하지 않으므로 설치 후 자동 실행되지 않는다.
$argLine = '/i "{0}" /qn /norestart /l*v "{1}"' -f $MsiPath, $msiLog
$proc = Start-Process -FilePath msiexec.exe -ArgumentList $argLine -Wait -PassThru
if ($proc.ExitCode -notin 0, 3010) { throw "msiexec 실패: exit $($proc.ExitCode) (로그: $msiLog)" }

$exe = Get-ChildItem -Path "$env:ProgramFiles\HOP", "${env:ProgramFiles(x86)}\HOP" -Filter 'hop-desktop.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
$info = [ordered]@{
    InstalledAt = $started.ToString('o')
    ExitCode    = $proc.ExitCode
    ExePath     = if ($exe) { $exe.FullName } else { $null }
    ExeSha256   = if ($exe) { (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash } else { $null }
}
$info | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'install-info.json') -Encoding utf8

Write-Output "설치 완료: exit=$($info.ExitCode) exe=$($info.ExePath)"
Write-Output "hop-desktop.exe SHA-256: $($info.ExeSha256)"
Write-Output '  (1단계 확인값: CA8D6708842DE134B2ECC98F2EF7F5BC7458F19B75386E25CD785E6B7A4ED55F)'
