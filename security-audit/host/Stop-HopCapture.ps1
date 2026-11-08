#Requires -RunAsAdministrator
<#
.SYNOPSIS
    실행 중인 캡처를 멈추고, pktmon ETL 을 pcapng 로 변환한다.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\HopAudit.config.psd1')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HopAudit.Common.ps1')

$cfg = Import-HopAuditConfig $ConfigPath
$log = Join-Path $cfg.HostWorkDir 'logs'
$state = Read-HopState $cfg
if (-not ($state.ContainsKey('Capture') -and $state.Capture -and $state.Capture.Running)) {
    throw '실행 중인 캡처 기록이 없습니다.'
}
$cap = $state.Capture

if ($cap.Tool -eq 'pktmon') {
    pktmon stop | Out-Host
    pktmon filter remove | Out-Null
    $etls = Get-ChildItem -LiteralPath $cap.OutDir -Filter '*.etl' | Sort-Object Name
    foreach ($etl in $etls) {
        $pcap = [IO.Path]::ChangeExtension($etl.FullName, '.pcapng')
        Write-HopStep "변환: $($etl.Name) -> $([IO.Path]::GetFileName($pcap))" $log
        pktmon etl2pcap $etl.FullName --out $pcap | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning "etl2pcap 실패: $($etl.FullName)" }
    }
} else {
    $proc = Get-Process -Id $cap.Pid -ErrorAction SilentlyContinue
    if ($proc) { Stop-Process -Id $cap.Pid }
}

$files = Get-ChildItem -LiteralPath $cap.OutDir -File
$total = ($files | Measure-Object Length -Sum).Sum
$manifest = $files | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; Bytes = $_.Length; Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
}
$manifest | Export-Csv -LiteralPath (Join-Path $cap.OutDir 'manifest.csv') -NoTypeInformation -Encoding utf8

$cap.Running = $false
$cap | Add-Member -NotePropertyName StoppedAt -NotePropertyValue (Get-Date).ToString('o') -Force
$state.Capture = $cap
if (-not $state.ContainsKey('CaptureHistory') -or -not $state.CaptureHistory) { $state.CaptureHistory = @() }
$state.CaptureHistory = @($state.CaptureHistory) + $cap
Save-HopState $cfg $state
Write-HopStep ("캡처 중지: phase={0} 파일 {1}개, {2:N1} MB -> {3}" -f $cap.Phase, $files.Count, ($total / 1MB), $cap.OutDir) $log
