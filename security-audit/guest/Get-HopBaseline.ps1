<#
.SYNOPSIS
    (게스트) 시스템 지속성·보안 설정 스냅샷을 JSON 으로 저장한다.

.DESCRIPTION
    설치 전(pre-install)과 감시 후(post)에 한 번씩 찍어 Export-HopAuditData.ps1 이 비교한다.
    수집 항목: 프로세스, 서비스, 예약 작업, 자동 실행 레지스트리/시작 폴더, WMI 영구 구독,
    방화벽 규칙, 설치 프로그램, 드라이버, 수신 대기 포트, 루트 인증서, hosts, 프록시,
    Defender 제외 항목, 로컬 관리자 그룹, .hwp/.hwpx 연결.
#>
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Label
)
$ErrorActionPreference = 'Continue'
$out = Join-Path $Root "baseline\$Label"
New-Item -ItemType Directory -Force -Path $out | Out-Null

function Save-Json([string]$Name, $Data) {
    @($Data) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out "$Name.json") -Encoding utf8
}

function Get-RegValues([string[]]$Paths) {
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $item = Get-ItemProperty -LiteralPath $p
        foreach ($prop in $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
            [pscustomobject]@{ Key = $p; Name = $prop.Name; Value = [string]$prop.Value }
        }
    }
}

Save-Json 'processes' (Get-CimInstance Win32_Process | Sort-Object Name, ProcessId |
    Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine)

Save-Json 'services' (Get-CimInstance Win32_Service | Sort-Object Name |
    Select-Object Name, DisplayName, State, StartMode, PathName, StartName)

Save-Json 'scheduled-tasks' (Get-ScheduledTask | Sort-Object TaskPath, TaskName | ForEach-Object {
    [pscustomobject]@{
        Path     = $_.TaskPath + $_.TaskName
        State    = [string]$_.State
        Author   = $_.Author
        Actions  = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        Triggers = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','
    }
})

$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
$startupDirs = @(
    [Environment]::GetFolderPath('Startup'),
    [Environment]::GetFolderPath('CommonStartup')
)
Save-Json 'autoruns' (@(Get-RegValues $runKeys) + @(
    foreach ($d in $startupDirs) {
        Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue |
            ForEach-Object { [pscustomobject]@{ Key = $d; Name = $_.Name; Value = $_.Length } }
    }
))

Save-Json 'ifeo' (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
    ForEach-Object { $d = (Get-ItemProperty -LiteralPath $_.PSPath).Debugger; if ($d) { [pscustomobject]@{ Image = $_.PSChildName; Debugger = $d } } })

Save-Json 'wmi-subscriptions' (@('__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') | ForEach-Object {
    $cls = $_
    Get-CimInstance -Namespace root\subscription -ClassName $cls -ErrorAction SilentlyContinue |
        ForEach-Object { [pscustomobject]@{ Class = $cls; Name = [string]($_.Name); Detail = [string]($_.Query + $_.CommandLineTemplate + $_.ScriptText) } }
})

# 규칙별 조회는 느리므로 응용 프로그램 필터를 한 번에 받아 InstanceID(=규칙 Name)로 맞춘다.
$appByRule = @{}
Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $appByRule[$_.InstanceID] = $_.Program }
Save-Json 'firewall-rules' (Get-NetFirewallRule | ForEach-Object {
    $app = $appByRule[$_.Name]
    [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; Enabled = [string]$_.Enabled; Direction = [string]$_.Direction; Action = [string]$_.Action; Program = $app }
} | Sort-Object Name)

$uninstall = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Save-Json 'programs' (Get-ItemProperty -Path $uninstall -ErrorAction SilentlyContinue | Where-Object DisplayName |
    Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation)

Save-Json 'drivers' (Get-CimInstance Win32_SystemDriver | Sort-Object Name | Select-Object Name, State, StartMode, PathName)

Save-Json 'listening' (@(
    Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{ Proto = 'TCP'; Address = $_.LocalAddress; Port = $_.LocalPort; Process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } }
    Get-NetUDPEndpoint | ForEach-Object { [pscustomobject]@{ Proto = 'UDP'; Address = $_.LocalAddress; Port = $_.LocalPort; Process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } }
) | Sort-Object Proto, Port, Address, Process -Unique)

Save-Json 'root-certs' (@('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root', 'Cert:\LocalMachine\AuthRoot') | ForEach-Object {
    $store = $_
    Get-ChildItem -Path $store | ForEach-Object { [pscustomobject]@{ Store = $store; Thumbprint = $_.Thumbprint; Subject = $_.Subject } }
} | Sort-Object Store, Thumbprint)

$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
Save-Json 'network-config' ([pscustomobject]@{
    HostsSha256     = (Get-FileHash -LiteralPath $hosts -Algorithm SHA256).Hash
    HostsEntries    = @(Get-Content -LiteralPath $hosts | Where-Object { $_ -and $_ -notmatch '^\s*#' })
    WinHttpProxy    = (netsh winhttp show proxy | Out-String).Trim()
    UserProxyEnable = $inet.ProxyEnable
    UserProxyServer = $inet.ProxyServer
    UserAutoConfig  = $inet.AutoConfigURL
})

$mp = Get-MpPreference -ErrorAction SilentlyContinue
Save-Json 'defender' ([pscustomobject]@{
    ExclusionPath      = $mp.ExclusionPath
    ExclusionProcess   = $mp.ExclusionProcess
    ExclusionExtension = $mp.ExclusionExtension
    RealTimeDisabled   = $mp.DisableRealtimeMonitoring
})

# 관리자 그룹은 SID(S-1-5-32-544)로 찾는다 (한국어 Windows 는 그룹 이름이 '관리자')
Save-Json 'admins' (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass, PrincipalSource)

Save-Json 'file-assoc' (@('.hwp', '.hwpx') | ForEach-Object {
    [pscustomobject]@{ Ext = $_; Assoc = (cmd /c "assoc $_" 2>$null) }
})

Write-Output "기준선 저장: $out ($((Get-ChildItem -LiteralPath $out).Count) 개 파일)"
