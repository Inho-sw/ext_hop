<#
.SYNOPSIS
    (게스트) Watch-HopResources.ps1 을 SYSTEM 예약 작업으로 등록·시작한다.

.DESCRIPTION
    PowerShell Direct 세션이 끊겨도 감시가 계속되도록 예약 작업으로 돌린다.
    작업 이름은 HopAuditMonitor 이며, 기준선 비교 때 감사 도구 자신의 흔적으로 제외한다.
#>
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][double]$Hours,
    [Parameter(Mandatory)][int]$IntervalSec
)
$ErrorActionPreference = 'Stop'

$script = Join-Path $Root 'scripts\Watch-HopResources.ps1'
$outDir = Join-Path $Root 'monitor'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$taskName = 'HopAuditMonitor'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -OutDir "{1}" -Hours {2} -IntervalSec {3}' -f $script, $outDir, $Hours, $IntervalSec
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argLine
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours ([math]::Ceiling($Hours) + 2)) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $taskName

Start-Sleep -Seconds 5
$task = Get-ScheduledTask -TaskName $taskName
Write-Output "감시 예약 작업 상태: $($task.State) / 출력: $outDir"
