#Requires -RunAsAdministrator
#Requires -Modules Hyper-V
<#
.SYNOPSIS
    HOP 보안 감시 환경을 준비한다 (호스트에서 실행).

.DESCRIPTION
    1. 체크포인트 HOP-Audit-00-Clean 생성 (아무것도 바꾸기 전)
    2. 공식 MSI 다운로드 및 SHA-256 검증 (호스트)
    3. VM 네트워크 어댑터 MAC/스위치 정보 기록 (캡처 필터용)
    4. 게스트로 스크립트·MSI·(선택) Sysmon 복사 후 감사 로깅 활성화
    5. 설치 전 기준선(pre-install) 수집
    6. 체크포인트 HOP-Audit-01-Instrumented 생성

    HOP 는 설치하지 않는다. 설치는 캡처를 켠 뒤 Invoke-HopGuestStep.ps1 -Step Install 로 한다.

.PARAMETER SysmonPath
    (선택) 호스트에 내려받은 Sysmon64.exe 경로. 주면 게스트에 설치한다.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\HopAudit.config.psd1'),
    [string]$SysmonPath,
    [pscredential]$Credential
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HopAudit.Common.ps1')

$cfg = Import-HopAuditConfig $ConfigPath
$log = Join-Path $cfg.HostWorkDir 'logs'
$vm = Get-HopAuditVM $cfg
$state = Read-HopState $cfg

Write-HopStep "VM: $($vm.Name) / 상태: $($vm.State)" $log
Get-VMSnapshot -VM $vm | Format-Table Name, CreationTime, SnapshotType -AutoSize | Out-Host

# 1. 깨끗한 상태 체크포인트
if (Get-VMSnapshot -VM $vm -Name $cfg.CheckpointClean -ErrorAction SilentlyContinue) {
    Write-HopStep "체크포인트 '$($cfg.CheckpointClean)' 가 이미 있어 새로 만들지 않습니다." $log
} else {
    Write-HopStep "체크포인트 생성: $($cfg.CheckpointClean)" $log
    Checkpoint-VM -VM $vm -SnapshotName $cfg.CheckpointClean
}

# 2. 공식 MSI 다운로드·검증 (호스트에서 받으므로 VM 캡처에 섞이지 않는다)
$installerDir = Join-Path $cfg.HostWorkDir 'installer'
New-Item -ItemType Directory -Force -Path $installerDir | Out-Null
$msiPath = Join-Path $installerDir ([IO.Path]::GetFileName(([uri]$cfg.MsiUrl).AbsolutePath))
if (-not (Test-Path -LiteralPath $msiPath)) {
    Write-HopStep "MSI 다운로드: $($cfg.MsiUrl)" $log
    Invoke-WebRequest -Uri $cfg.MsiUrl -OutFile $msiPath -UseBasicParsing
}
$actual = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $cfg.MsiSha256.ToLowerInvariant()) {
    throw "MSI SHA-256 불일치. 기대=$($cfg.MsiSha256) 실제=$actual  (파일을 지우고 다시 받거나 점검을 중단하세요)"
}
Write-HopStep "MSI SHA-256 일치: $actual" $log
$sig = Get-AuthenticodeSignature -LiteralPath $msiPath
Write-HopStep "MSI 서명 상태: $($sig.Status) (공식 v0.4.5 는 미서명이 정상)" $log

# 3. NIC 정보
$nic = Get-HopVmNicInfo $vm
Write-HopStep ("NIC: {0} MAC={1} Switch={2}({3}) DynamicMac={4}" -f $nic.AdapterName, $nic.MacAddress, $nic.SwitchName, $nic.SwitchType, $nic.DynamicMac) $log
if ($nic.DynamicMac) {
    Write-Warning '동적 MAC 입니다. 감시 도중 MAC 이 바뀌면 캡처 필터가 놓칩니다. VM 을 끈 상태에서 정적 MAC 으로 바꾸는 것을 권장합니다.'
}
$state.Nic = $nic
$state.MsiPath = $msiPath
$state.VMName = $vm.Name
Save-HopState $cfg $state

# 4. 게스트 준비
$session = New-HopGuestSession -VM $vm -Credential $Credential
try {
    $guestRoot = $cfg.GuestWorkDir
    Invoke-Command -Session $session -ScriptBlock {
        param($root)
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'scripts'), (Join-Path $root 'installer'), (Join-Path $root 'tools') | Out-Null
    } -ArgumentList $guestRoot

    $guestScripts = Join-Path $PSScriptRoot '..\guest'
    Copy-Item -Path (Join-Path $guestScripts '*.ps1') -Destination (Join-Path $guestRoot 'scripts') -ToSession $session -Force
    Copy-Item -LiteralPath $msiPath -Destination (Join-Path $guestRoot 'installer') -ToSession $session -Force
    if ($SysmonPath) {
        Copy-Item -LiteralPath $SysmonPath -Destination (Join-Path $guestRoot 'tools\Sysmon64.exe') -ToSession $session -Force
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\sysmon\sysmonconfig-hop.xml') -Destination (Join-Path $guestRoot 'tools') -ToSession $session -Force
    }
    Write-HopStep '게스트로 스크립트/설치 파일 복사 완료' $log

    Write-HopStep '게스트 감사 로깅 활성화' $log
    Invoke-Command -Session $session -FilePath (Join-Path $guestScripts 'Enable-HopAuditLogging.ps1') -ArgumentList $guestRoot | Out-Host

    Write-HopStep '게스트 기준선 수집 (pre-install)' $log
    Invoke-Command -Session $session -FilePath (Join-Path $guestScripts 'Get-HopBaseline.ps1') -ArgumentList $guestRoot, 'pre-install' | Out-Host
} finally {
    Remove-PSSession $session
}

# 6. 계측 완료 체크포인트
if (-not (Get-VMSnapshot -VM $vm -Name $cfg.CheckpointReady -ErrorAction SilentlyContinue)) {
    Write-HopStep "체크포인트 생성: $($cfg.CheckpointReady)" $log
    Checkpoint-VM -VM $vm -SnapshotName $cfg.CheckpointReady
}

Write-HopStep '준비 완료. 다음: Start-HopCapture.ps1 -Phase control (HOP 설치 전 대조군 캡처)' $log
