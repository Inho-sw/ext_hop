# 호스트 스크립트 공용 함수. 각 호스트 스크립트가 dot-source 한다.
# 이 파일 자체는 아무것도 실행하지 않는다.

Set-StrictMode -Version 3.0

function Import-HopAuditConfig {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "설정 파일이 없습니다: $Path" }
    return Import-PowerShellDataFile -LiteralPath $Path
}

function Write-HopStep {
    param([Parameter(Mandatory)][string]$Message, [string]$LogDir)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line -ForegroundColor Cyan
    if ($LogDir) {
        New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
        Add-Content -LiteralPath (Join-Path $LogDir 'host-steps.log') -Value $line -Encoding utf8
    }
}

function Get-HopAuditVM {
    param([Parameter(Mandatory)][hashtable]$Config)
    if ([string]::IsNullOrWhiteSpace($Config.VMName)) {
        Write-Host '설정의 VMName 이 비어 있습니다. 아래 VM 중 하나를 HopAudit.config.psd1 에 넣으세요.' -ForegroundColor Yellow
        Get-VM | Format-Table Name, State, Generation, Version -AutoSize | Out-Host
        throw 'VMName 미설정'
    }
    $vm = Get-VM -Name $Config.VMName -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM 을 찾을 수 없습니다: $($Config.VMName)" }
    return $vm
}

function Get-HopStatePath {
    param([Parameter(Mandatory)][hashtable]$Config)
    return Join-Path $Config.HostWorkDir 'state.json'
}

function Read-HopState {
    param([Parameter(Mandatory)][hashtable]$Config)
    $path = Get-HopStatePath $Config
    if (-not (Test-Path -LiteralPath $path)) { return @{} }
    $obj = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json
    $state = @{}
    foreach ($p in $obj.PSObject.Properties) { $state[$p.Name] = $p.Value }
    return $state
}

function Save-HopState {
    param([Parameter(Mandatory)][hashtable]$Config, [Parameter(Mandatory)][hashtable]$State)
    New-Item -ItemType Directory -Force -Path $Config.HostWorkDir | Out-Null
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Get-HopStatePath $Config) -Encoding utf8
}

function New-HopGuestSession {
    # PowerShell Direct: VM 네트워크를 쓰지 않고 VMBus 로 접속하므로 캡처 대상 트래픽에 섞이지 않는다.
    param(
        [Parameter(Mandatory)]$VM,
        [pscredential]$Credential
    )
    if ($VM.State -ne 'Running') { throw "VM 이 실행 중이 아닙니다 (현재: $($VM.State)). 먼저 VM 을 켜고 로그인하세요." }
    if (-not $Credential) {
        $Credential = Get-Credential -Message "VM '$($VM.Name)' 의 관리자 계정 (HOP 를 실행할 그 계정)"
    }
    return New-PSSession -VMName $VM.Name -Credential $Credential
}

function Get-HopVmNicInfo {
    param([Parameter(Mandatory)]$VM)
    $nics = @(Get-VMNetworkAdapter -VM $VM)
    if ($nics.Count -ne 1) {
        Write-Warning "VM 네트워크 어댑터가 $($nics.Count) 개입니다. 첫 번째 어댑터만 캡처 필터에 씁니다."
    }
    $nic = $nics[0]
    $mac = ($nic.MacAddress -replace '(..)(?!$)', '$1-').ToUpper()
    $switch = if ($nic.SwitchName) { Get-VMSwitch -Name $nic.SwitchName } else { $null }
    return [ordered]@{
        AdapterName = $nic.Name
        MacAddress  = $mac
        SwitchName  = $nic.SwitchName
        SwitchType  = if ($switch) { [string]$switch.SwitchType } else { '' }
        DynamicMac  = [bool]$nic.DynamicMacAddressEnabled
    }
}
