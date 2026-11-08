<#
.SYNOPSIS
    (게스트) HOP 프로세스 트리의 자원 사용과 네트워크 연결을 주기적으로 기록한다.

.DESCRIPTION
    대상: hop-desktop.exe 와 그 모든 자손 프로세스 (WebView2 msedgewebview2.exe 포함).
    출력 (OutDir):
      resources.csv    프로세스별 CPU%, 메모리, 누적 I/O 바이트, 스레드/핸들 수, GPU%
      system.csv       전체 CPU%, 가용 메모리, HOP 프로세스 수와 합계 CPU%
      connections.csv  HOP 트리 소유 TCP 연결/UDP 엔드포인트를 처음 본 시각에 한 줄
      events.csv       프로세스 시작/종료, HOP 실행 여부 변화, 오류
    샘플 사이에 열렸다 닫힌 짧은 연결은 여기서 놓칠 수 있다. 그런 연결은 보안 이벤트 5156 이 잡는다.
#>
param(
    [Parameter(Mandatory)][string]$OutDir,
    [double]$Hours = 24,
    [int]$IntervalSec = 60
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$files = @{
    Resources   = Join-Path $OutDir 'resources.csv'
    System      = Join-Path $OutDir 'system.csv'
    Connections = Join-Path $OutDir 'connections.csv'
    Events      = Join-Path $OutDir 'events.csv'
}
$cores = [Environment]::ProcessorCount
$end = (Get-Date).AddHours($Hours)
$prevCpu = @{}      # pid -> CPU 초 (커널+사용자)
$known = @{}        # pid -> 프로세스 이름
$seenConn = @{}
$hopWasRunning = $null

function Add-Row([string]$File, $Row) {
    $Row | Export-Csv -LiteralPath $File -Append -NoTypeInformation -Encoding utf8
}

function Add-HopEvent([string]$Kind, [string]$Detail) {
    Add-Row $files.Events ([pscustomobject]@{ Time = (Get-Date).ToString('o'); Kind = $Kind; Detail = $Detail })
}

function Get-HopTree {
    $all = @(Get-CimInstance Win32_Process)
    $byParent = @{}
    foreach ($p in $all) {
        $key = [int]$p.ParentProcessId
        if (-not $byParent.ContainsKey($key)) { $byParent[$key] = New-Object System.Collections.ArrayList }
        [void]$byParent[$key].Add($p)
    }
    $queue = New-Object System.Collections.Queue
    $all | Where-Object { $_.Name -ieq 'hop-desktop.exe' } | ForEach-Object { $queue.Enqueue($_) }
    $tree = @{}
    while ($queue.Count -gt 0) {
        $p = $queue.Dequeue()
        if ($tree.ContainsKey([int]$p.ProcessId)) { continue }
        $tree[[int]$p.ProcessId] = $p
        if ($byParent.ContainsKey([int]$p.ProcessId)) { $byParent[[int]$p.ProcessId] | ForEach-Object { $queue.Enqueue($_) } }
    }
    return $tree
}

function Get-GpuByPid {
    $gpu = @{}
    $engines = Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction SilentlyContinue
    foreach ($e in @($engines)) {
        if ($e.Name -match 'pid_(\d+)_') {
            $id = [int]$Matches[1]
            $gpu[$id] = [double]($gpu[$id]) + [double]$e.UtilizationPercentage
        }
    }
    return $gpu
}

function Save-Connections([hashtable]$Tree, [string]$Now) {
    $ids = @($Tree.Keys)
    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.OwningProcess -and $_.State -ne 'Listen' }
    foreach ($c in @($tcp)) {
        $key = 'TCP|{0}|{1}|{2}' -f $c.OwningProcess, $c.RemoteAddress, $c.RemotePort
        if ($seenConn.ContainsKey($key)) { continue }
        $seenConn[$key] = $Now
        Add-Row $files.Connections ([pscustomobject]@{
            FirstSeen = $Now; Proto = 'TCP'; Pid = $c.OwningProcess; Process = $Tree[[int]$c.OwningProcess].Name
            Local = "$($c.LocalAddress):$($c.LocalPort)"; Remote = "$($c.RemoteAddress):$($c.RemotePort)"; State = [string]$c.State
        })
    }
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.OwningProcess }
    foreach ($u in @($udp)) {
        $key = 'UDP|{0}|{1}|{2}' -f $u.OwningProcess, $u.LocalAddress, $u.LocalPort
        if ($seenConn.ContainsKey($key)) { continue }
        $seenConn[$key] = $Now
        Add-Row $files.Connections ([pscustomobject]@{
            FirstSeen = $Now; Proto = 'UDP'; Pid = $u.OwningProcess; Process = $Tree[[int]$u.OwningProcess].Name
            Local = "$($u.LocalAddress):$($u.LocalPort)"; Remote = ''; State = 'Bound'
        })
    }
}

function Save-Sample {
    $now = (Get-Date).ToString('o')
    $tree = Get-HopTree
    $gpu = Get-GpuByPid
    $hopCpu = 0.0

    foreach ($id in @($known.Keys)) {
        if (-not $tree.ContainsKey($id)) { Add-HopEvent 'ProcessExit' "$id $($known[$id])"; $known.Remove($id); $prevCpu.Remove($id) }
    }
    foreach ($id in $tree.Keys) {
        $p = $tree[$id]
        if (-not $known.ContainsKey($id)) {
            $known[$id] = $p.Name
            Add-HopEvent 'ProcessStart' ("{0} {1} parent={2} cmd={3}" -f $id, $p.Name, $p.ParentProcessId, $p.CommandLine)
        }
        $cpuSec = ([double]$p.KernelModeTime + [double]$p.UserModeTime) / 1e7
        $cpuPct = if ($prevCpu.ContainsKey($id)) { [math]::Round(($cpuSec - $prevCpu[$id]) / ($IntervalSec * $cores) * 100, 2) } else { $null }
        $prevCpu[$id] = $cpuSec
        if ($cpuPct) { $hopCpu += $cpuPct }
        Add-Row $files.Resources ([pscustomobject]@{
            Time = $now; Pid = $id; Name = $p.Name; CpuPct = $cpuPct
            WorkingSetMB = [math]::Round($p.WorkingSetSize / 1MB, 1); PrivateMB = [math]::Round($p.PrivatePageCount / 1MB, 1)
            ReadBytes = $p.ReadTransferCount; WriteBytes = $p.WriteTransferCount; OtherBytes = $p.OtherTransferCount
            Threads = $p.ThreadCount; Handles = $p.HandleCount; GpuPct = $gpu[$id]
        })
    }

    $running = $tree.Count -gt 0
    if ($running -ne $hopWasRunning) { Add-HopEvent 'HopRunning' ([string]$running); $script:hopWasRunning = $running }

    $cpuTotal = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Row $files.System ([pscustomobject]@{
        Time = $now; CpuTotalPct = $cpuTotal; FreeMemMB = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
        HopProcesses = $tree.Count; HopCpuPct = [math]::Round($hopCpu, 2)
    })

    if ($running) { Save-Connections $tree $now }
}

Add-HopEvent 'MonitorStart' "hours=$Hours interval=$IntervalSec cores=$cores"
while ((Get-Date) -lt $end) {
    $tick = Get-Date
    try { Save-Sample } catch { Add-HopEvent 'Error' $_.Exception.Message }
    $sleep = $IntervalSec - ((Get-Date) - $tick).TotalSeconds
    if ($sleep -gt 0) { Start-Sleep -Milliseconds ([int]($sleep * 1000)) }
}
Add-HopEvent 'MonitorEnd' ''
