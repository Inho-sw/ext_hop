#Requires -RunAsAdministrator
#Requires -Modules Hyper-V
<#
.SYNOPSIS
    시간 트리거 시험용: VM 시계를 앞으로 옮기거나 원래대로 돌린다.

.DESCRIPTION
    -OffsetDays N : Hyper-V 시간 동기화와 게스트 w32time 을 끄고 게스트 시계를 N 일 뒤로 옮긴다.
    -Restore      : 시간 동기화와 w32time 을 다시 켜고 시계를 맞춘다.

    시계를 옮긴 뒤 HOP 를 실행해 10~30분 관찰하고, 캡처/감시 결과에서 평소와 다른 동작을 찾는다.
    업데이트 확인 요청의 TLS 인증서 검증이 날짜 때문에 실패하는 것은 정상이다.
#>
[CmdletBinding(DefaultParameterSetName = 'Shift')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Shift')][int]$OffsetDays,
    [Parameter(Mandatory, ParameterSetName = 'Restore')][switch]$Restore,
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\HopAudit.config.psd1'),
    [pscredential]$Credential
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HopAudit.Common.ps1')

$cfg = Import-HopAuditConfig $ConfigPath
$log = Join-Path $cfg.HostWorkDir 'logs'
$vm = Get-HopAuditVM $cfg
$timeSync = Get-VMIntegrationService -VM $vm | Where-Object { $_.Name -match 'Time Synchronization|시간 동기화' }
if (-not $timeSync) { throw '시간 동기화 통합 서비스를 찾지 못했습니다.' }

if ($Restore) {
    Enable-VMIntegrationService -VMIntegrationService $timeSync
    $session = New-HopGuestSession -VM $vm -Credential $Credential
    try {
        Invoke-Command -Session $session -ScriptBlock {
            Set-Service -Name w32time -StartupType Manual
            Start-Service -Name w32time
            w32tm /resync /force | Out-Null
            Get-Date
        } | Out-Host
    } finally { Remove-PSSession $session }
    Write-HopStep 'VM 시계 복원 (시간 동기화 ON)' $log
    return
}

Disable-VMIntegrationService -VMIntegrationService $timeSync
$session = New-HopGuestSession -VM $vm -Credential $Credential
try {
    $now = Invoke-Command -Session $session -ScriptBlock {
        param($days)
        Stop-Service -Name w32time -Force -ErrorAction SilentlyContinue
        Set-Service -Name w32time -StartupType Disabled
        Set-Date -Date (Get-Date).AddDays($days) | Out-Null
        Get-Date
    } -ArgumentList $OffsetDays
} finally { Remove-PSSession $session }
Write-HopStep "VM 시계를 $OffsetDays 일 이동: 게스트 현재 시각 $now (시간 동기화 OFF)" $log
