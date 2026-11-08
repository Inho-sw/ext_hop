<#
.SYNOPSIS
    (게스트) 감시 결과를 모아 하나의 zip 으로 만든다. 마지막 출력 줄이 zip 경로다.

.DESCRIPTION
    1. 사후 기준선(Label) 수집 후 pre-install 과 비교 -> baseline-diff.txt
    2. 보안 이벤트 5156(WFP 연결 허용)/4688(프로세스 생성) -> wfp-connections.csv, process-creation.csv
    3. DNS Client Operational 이벤트 -> dns-queries.csv
    4. Sysmon 로그(있으면) -> sysmon.evtx
    5. HOP 앱 데이터 폴더 파일 목록(내용은 복사하지 않음) -> hop-appdata.csv
    6. 감시 CSV, 설치 로그, 카나리를 포함해 압축
#>
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$Since
)
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$work = Join-Path $Root "export\$Label-$stamp"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$sinceTime = [datetime]::Parse($Since, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()

# 1. 사후 기준선과 비교 (감사 도구 자신의 흔적은 제외)
& (Join-Path $Root 'scripts\Get-HopBaseline.ps1') -Root $Root -Label $Label | Out-Null
$pre = Join-Path $Root 'baseline\pre-install'
$post = Join-Path $Root "baseline\$Label"
$ignore = 'HopAudit|Sysmon'
$diff = foreach ($file in Get-ChildItem -LiteralPath $pre -Filter '*.json') {
    $postFile = Join-Path $post $file.Name
    if (-not (Test-Path -LiteralPath $postFile)) { continue }
    $a = @(Get-Content -LiteralPath $file.FullName -Raw -Encoding utf8 | ConvertFrom-Json)
    $b = @(Get-Content -LiteralPath $postFile -Raw -Encoding utf8 | ConvertFrom-Json)
    if ($file.BaseName -eq 'processes') {
        # PID/명령줄은 매번 바뀌므로 실행 파일 단위로만 비교
        $a = @($a | Select-Object Name, ExecutablePath -Unique)
        $b = @($b | Select-Object Name, ExecutablePath -Unique)
    }
    $sa = @($a | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 })
    $sb = @($b | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 })
    # Compare-Object 는 빈 배열을 받지 못하므로 빈 쪽은 빈 문자열 하나로 채운다.
    if ($sa.Count -eq 0) { $sa = @('') }
    if ($sb.Count -eq 0) { $sb = @('') }
    Compare-Object -ReferenceObject $sa -DifferenceObject $sb | Where-Object { $_.InputObject -ne '' } | Where-Object { $_.InputObject -notmatch $ignore } | ForEach-Object {
        $mark = if ($_.SideIndicator -eq '=>') { '+ 추가' } else { '- 삭제' }
        '[{0}] {1} {2}' -f $file.BaseName, $mark, $_.InputObject
    }
}
$diffPath = Join-Path $work 'baseline-diff.txt'
if ($diff) { $diff | Set-Content -LiteralPath $diffPath -Encoding utf8 } else { '변경 없음' | Set-Content -LiteralPath $diffPath -Encoding utf8 }

# 2~3. 이벤트 로그 -> CSV (XML EventData 이름으로 읽으므로 언어와 무관)
function Export-EventCsv([string]$LogName, [int[]]$Ids, [string]$OutFile, [scriptblock]$Map) {
    $events = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Ids; StartTime = $sinceTime } -ErrorAction SilentlyContinue
    @($events) | Where-Object { $_ } | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $d = @{}
        foreach ($n in @($xml.Event.EventData.Data)) { if ($n) { $d[$n.Name] = $n.'#text' } }
        & $Map $_ $d
    } | Export-Csv -LiteralPath (Join-Path $work $OutFile) -NoTypeInformation -Encoding utf8
}

Export-EventCsv 'Security' @(5156) 'wfp-connections.csv' {
    param($e, $d)
    [pscustomobject]@{
        Time = $e.TimeCreated.ToString('o'); Pid = $d.ProcessID; Application = $d.Application
        Direction = if ($d.Direction -eq '%%14593') { 'Outbound' } elseif ($d.Direction -eq '%%14592') { 'Inbound' } else { $d.Direction }
        Protocol = $d.Protocol; SourceAddress = $d.SourceAddress; SourcePort = $d.SourcePort
        DestAddress = $d.DestAddress; DestPort = $d.DestPort
    }
}
Export-EventCsv 'Security' @(4688) 'process-creation.csv' {
    param($e, $d)
    [pscustomobject]@{
        Time = $e.TimeCreated.ToString('o'); NewPid = $d.NewProcessId; NewProcess = $d.NewProcessName
        ParentPid = $d.ProcessId; ParentProcess = $d.ParentProcessName; CommandLine = $d.CommandLine; User = $d.SubjectUserName
    }
}
Export-EventCsv 'Microsoft-Windows-DNS-Client/Operational' @(3006, 3008, 3020) 'dns-queries.csv' {
    param($e, $d)
    [pscustomobject]@{ Time = $e.TimeCreated.ToString('o'); EventId = $e.Id; QueryName = $d.QueryName; QueryType = $d.QueryType; Results = $d.QueryResults; Status = $d.QueryStatus }
}

# 4. Sysmon (있으면)
if (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) {
    wevtutil epl Microsoft-Windows-Sysmon/Operational (Join-Path $work 'sysmon.evtx')
}

# 5. HOP 앱 데이터 폴더: 파일 목록과 해시만 (문서 내용은 복사하지 않음)
$appDirs = @(
    (Join-Path $env:APPDATA 'net.golbin.hop'),
    (Join-Path $env:LOCALAPPDATA 'net.golbin.hop'),
    (Join-Path $env:LOCALAPPDATA 'Temp')
) | Where-Object { Test-Path -LiteralPath $_ }
$appDirs | ForEach-Object { Get-ChildItem -LiteralPath $_ -Recurse -File -Force -ErrorAction SilentlyContinue } |
    Where-Object { $_.LastWriteTime -ge $sinceTime } |
    Select-Object FullName, Length, LastWriteTime, @{ n = 'Sha256'; e = { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } } |
    Export-Csv -LiteralPath (Join-Path $work 'hop-appdata.csv') -NoTypeInformation -Encoding utf8

# 6. 나머지 산출물 복사 후 압축
foreach ($item in @('monitor', 'logs', 'install-info.json', 'canary.txt', 'baseline')) {
    $src = Join-Path $Root $item
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $work -Recurse -Force }
}
$zip = Join-Path $Root "export\hop-audit-$Label-$stamp.zip"
Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -Force
Write-Output $zip
