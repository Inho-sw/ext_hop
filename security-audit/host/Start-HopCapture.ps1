#Requires -RunAsAdministrator
<#
.SYNOPSIS
    VM 트래픽 패킷 캡처를 호스트에서 시작한다.

.DESCRIPTION
    기본 도구는 Windows 내장 pktmon 이다. Hyper-V 가상 스위치 구간에서 VM 의 MAC 으로 거르므로
    스위치 종류(Default/Internal/External)와 무관하게 VM 의 모든 프레임을 잡는다.
    VM 내부 프로그램은 이 캡처를 보거나 끌 수 없다.

    pktmon 은 같은 패킷을 여러 계층에서 중복 기록할 수 있다. analyze_capture.py 가 중복을 제거한다.

    -Tool dumpcap 을 주면 Wireshark 의 dumpcap 으로 'vEthernet (<스위치>)' 를 캡처한다.
    이 방식은 Default Switch/Internal 스위치에서만 VM 트래픽이 보인다.

.PARAMETER Phase
    control = HOP 설치 전 대조군(배경 트래픽 파악), main = HOP 설치 후 24시간 본 감시.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('control', 'main', 'timeshift')][string]$Phase,
    [ValidateSet('pktmon', 'dumpcap')][string]$Tool = 'pktmon',
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\HopAudit.config.psd1')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HopAudit.Common.ps1')

$cfg = Import-HopAuditConfig $ConfigPath
$log = Join-Path $cfg.HostWorkDir 'logs'
$state = Read-HopState $cfg
if ($state.ContainsKey('Capture') -and $state.Capture -and $state.Capture.Running) {
    throw "이미 캡처가 실행 중입니다 (phase=$($state.Capture.Phase)). Stop-HopCapture.ps1 을 먼저 실행하세요."
}

# MAC 은 매번 다시 읽는다 (체크포인트 복원 후에도 정확하도록).
$vm = Get-HopAuditVM $cfg
$nic = Get-HopVmNicInfo $vm
$state.Nic = $nic

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $cfg.HostWorkDir "capture\$Phase-$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$capture = [ordered]@{
    Phase     = $Phase
    Tool      = $Tool
    OutDir    = $outDir
    Mac       = $nic.MacAddress
    StartedAt = (Get-Date).ToString('o')
    Running   = $true
    Pid       = $null
}

if ($Tool -eq 'pktmon') {
    pktmon stop 2>$null | Out-Null
    pktmon filter remove | Out-Null
    pktmon filter add HopAuditVM -m $nic.MacAddress | Out-Host
    $etl = Join-Path $outDir 'capture.etl'
    pktmon start --capture --pkt-size 0 --file-name $etl --file-size $cfg.CaptureFileSizeMB --log-mode multi-file | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "pktmon start 실패 (exit $LASTEXITCODE)" }
} else {
    $dumpcap = Join-Path $env:ProgramFiles 'Wireshark\dumpcap.exe'
    if (-not (Test-Path -LiteralPath $dumpcap)) { throw "dumpcap 을 찾을 수 없습니다: $dumpcap" }
    if ($nic.SwitchType -eq 'External') {
        Write-Warning 'External 스위치에서는 호스트 vEthernet 에 VM 트래픽이 보이지 않을 수 있습니다. pktmon 을 권장합니다.'
    }
    $iface = "vEthernet ($($nic.SwitchName))"
    $macColon = $nic.MacAddress -replace '-', ':'
    $pcap = Join-Path $outDir 'capture.pcapng'
    # Start-Process 는 배열 인자의 공백을 따옴표로 감싸 주지 않으므로 직접 감싼다.
    $dumpArgs = '-i "{0}" -f "ether host {1}" -b filesize:{2} -w "{3}" -q' -f $iface, $macColon, ($cfg.CaptureFileSizeMB * 1024), $pcap
    $proc = Start-Process -FilePath $dumpcap -ArgumentList $dumpArgs -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 3
    if ($proc.HasExited) { throw "dumpcap 이 바로 종료되었습니다 (exit $($proc.ExitCode)). 인터페이스 이름을 확인하세요: $iface" }
    $capture.Pid = $proc.Id
}

$state.Capture = $capture
Save-HopState $cfg $state
Write-HopStep "캡처 시작: phase=$Phase tool=$Tool MAC=$($nic.MacAddress) -> $outDir" $log
