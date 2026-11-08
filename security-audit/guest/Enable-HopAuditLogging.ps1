<#
.SYNOPSIS
    (게스트) 프로세스별 네트워크 연결과 프로세스 생성을 Windows 기본 감사로 기록하도록 설정한다.

.DESCRIPTION
    - 보안 이벤트 5156/5158 (WFP 연결 허용/바인드): 어떤 실행 파일이 어느 IP:포트로 연결했는지
    - 보안 이벤트 4688 (프로세스 생성, 명령줄 포함)
    - DNS Client Operational 로그
    - Sysmon (C:\HopAudit\tools\Sysmon64.exe 가 있을 때만)
    auditpol 은 한국어 Windows 에서도 동작하도록 하위 범주 GUID 를 쓴다.
#>
param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference = 'Stop'

$subcategories = [ordered]@{
    'Filtering Platform Connection' = '{0CCE9226-69AE-11D9-BED3-505054503030}'
    'Process Creation'              = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'Process Termination'           = '{0CCE922C-69AE-11D9-BED3-505054503030}'
}
foreach ($name in $subcategories.Keys) {
    auditpol /set /subcategory:$($subcategories[$name]) /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol 실패: $name" }
    Write-Output "감사 활성화: $name"
}

# 4688 이벤트에 명령줄 포함
$auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $auditKey -Force | Out-Null
Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord

# 24시간 분량을 담도록 로그 크기 확대 (보안 2GB, DNS 256MB)
wevtutil sl Security /ms:2147483648
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:268435456
Write-Output '보안 로그 2GB, DNS Client Operational 로그 활성화'

$sysmon = Join-Path $Root 'tools\Sysmon64.exe'
$sysmonConfig = Join-Path $Root 'tools\sysmonconfig-hop.xml'
if ((Test-Path -LiteralPath $sysmon) -and (Test-Path -LiteralPath $sysmonConfig)) {
    if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
        & $sysmon -c $sysmonConfig | Out-Null
        Write-Output 'Sysmon 설정 갱신'
    } else {
        & $sysmon -accepteula -i $sysmonConfig | Out-Null
        Write-Output 'Sysmon 설치'
    }
    wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
} else {
    Write-Output 'Sysmon 없음: WFP/4688 감사만 사용 (충분함)'
}

# 24시간 감시 중 VM 이 절전/최대 절전에 들어가지 않도록 (점검 전용 VM 이므로 되돌리지 않음)
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /change monitor-timeout-ac 0
Write-Output 'VM 절전 해제'

$marker = Join-Path $Root 'logging-enabled.txt'
Set-Content -LiteralPath $marker -Value (Get-Date).ToString('o') -Encoding utf8
