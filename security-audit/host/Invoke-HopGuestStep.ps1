#Requires -RunAsAdministrator
#Requires -Modules Hyper-V
<#
.SYNOPSIS
    게스트(VM) 안의 감시 단계를 호스트에서 PowerShell Direct 로 실행한다.

.PARAMETER Step
    Install      공식 MSI 해시 재확인 후 무인 설치 (설치 로그 남김)
    StartMonitor 자원·연결 감시 예약 작업 시작 (기본 24시간)
    StopMonitor  감시 예약 작업 중지
    Canary       카나리 문자열 생성 (게스트 C:\HopAudit\canary.txt 와 호스트에 저장)
    Collect      사후 기준선·이벤트 로그·감시 CSV 를 모아 압축한 뒤 호스트로 가져옴
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Install', 'StartMonitor', 'StopMonitor', 'Canary', 'Collect')][string]$Step,
    [string]$Label = 'post',
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\HopAudit.config.psd1'),
    [pscredential]$Credential
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HopAudit.Common.ps1')

$cfg = Import-HopAuditConfig $ConfigPath
$log = Join-Path $cfg.HostWorkDir 'logs'
$vm = Get-HopAuditVM $cfg
$state = Read-HopState $cfg
$root = $cfg.GuestWorkDir
$guestScripts = Join-Path $PSScriptRoot '..\guest'

$session = New-HopGuestSession -VM $vm -Credential $Credential
try {
    # 게스트 스크립트를 항상 최신본으로 덮어쓴다.
    Copy-Item -Path (Join-Path $guestScripts '*.ps1') -Destination (Join-Path $root 'scripts') -ToSession $session -Force

    switch ($Step) {
        'Install' {
            $msiName = [IO.Path]::GetFileName($state.MsiPath)
            Write-HopStep "게스트 설치 시작: $msiName" $log
            Invoke-Command -Session $session -FilePath (Join-Path $guestScripts 'Install-Hop.ps1') `
                -ArgumentList $root, (Join-Path $root "installer\$msiName"), $cfg.MsiSha256 | Out-Host
            $state.InstalledAt = (Get-Date).ToString('o')
            Save-HopState $cfg $state
        }
        'StartMonitor' {
            Write-HopStep "게스트 감시 시작: $($cfg.MonitorHours)시간, $($cfg.MonitorIntervalSec)초 간격" $log
            Invoke-Command -Session $session -FilePath (Join-Path $guestScripts 'Start-HopMonitor.ps1') `
                -ArgumentList $root, $cfg.MonitorHours, $cfg.MonitorIntervalSec | Out-Host
        }
        'StopMonitor' {
            Invoke-Command -Session $session -ScriptBlock { Stop-ScheduledTask -TaskName 'HopAuditMonitor' -ErrorAction SilentlyContinue } | Out-Null
            Write-HopStep '게스트 감시 예약 작업 중지' $log
        }
        'Canary' {
            $canary = Invoke-Command -Session $session -FilePath (Join-Path $guestScripts 'New-HopCanary.ps1') -ArgumentList $root
            $canaryText = @($canary)[-1]
            $state.Canary = [string]$canaryText
            Save-HopState $cfg $state
            Set-Content -LiteralPath (Join-Path $cfg.HostWorkDir 'canary.txt') -Value $canaryText -Encoding utf8
            Write-HopStep "카나리 생성: $canaryText (호스트 $($cfg.HostWorkDir)\canary.txt 에도 저장)" $log
        }
        'Collect' {
            $since = if ($state.ContainsKey('InstalledAt') -and $state.InstalledAt) { [string]$state.InstalledAt } else { (Get-Date).AddDays(-3).ToString('o') }
            Write-HopStep "게스트 결과 수집 (label=$Label, since=$since)" $log
            $zip = Invoke-Command -Session $session -FilePath (Join-Path $guestScripts 'Export-HopAuditData.ps1') `
                -ArgumentList $root, $Label, $since
            $zipPath = [string](@($zip)[-1])
            $dest = Join-Path $cfg.HostWorkDir 'results'
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
            Copy-Item -Path $zipPath -Destination $dest -FromSession $session -Force
            Write-HopStep "결과 가져옴: $(Join-Path $dest ([IO.Path]::GetFileName($zipPath)))" $log
        }
    }
} finally {
    Remove-PSSession $session
}
