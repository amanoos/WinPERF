# Measures what WinPerf costs while it records (T36, NFR-001): the CPU and memory of the process
# doing the recording, how fast the database file grows, and how many bytes it writes. Attaches to a
# process that is ALREADY running (the installed service, or a `winperf monitor run` you started),
# so it measures the real thing and changes nothing.
#
#   .\scripts\overhead.ps1 -Hours 24                       # the service (winperf-service)
#   .\scripts\overhead.ps1 -Hours 1 -Process winperf       # a foreground `monitor run`
#
# One row a minute goes to the CSV (default: %TEMP%\winperf-overhead.csv); the summary prints at the
# end and is also written next to it. Stop early with Ctrl+C: the summary then covers what was seen.
param(
    [double]$Hours = 24,
    [string]$Process = "winperf-service",
    [string]$Db = (Join-Path $env:ProgramData "WinPerf\winperf.db"),
    [string]$Csv = (Join-Path $env:TEMP "winperf-overhead.csv")
)
$ErrorActionPreference = "Stop"
$p = Get-Process -Name $Process -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p) { throw "no running process named '$Process' (is the service started? winperf service status)" }
$cores = [Environment]::ProcessorCount

function Db-Bytes { (Get-ChildItem "$Db*" -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum }

"time,cpu_pct_of_one_core,cpu_pct_of_machine,rss_mb,private_mb,handles,db_mb,io_write_mb_total" | Set-Content $Csv
$start = Get-Date
$end = $start.AddHours($Hours)
$prevCpu = $p.TotalProcessorTime.TotalSeconds
$prevT = $start
$dbStart = Db-Bytes
try {
    while ((Get-Date) -lt $end) {
        Start-Sleep -Seconds 60
        $p.Refresh()
        if ($p.HasExited) { Write-Warning "the process exited"; break }
        $now = Get-Date
        $cpu = $p.TotalProcessorTime.TotalSeconds
        $one = 100 * ($cpu - $prevCpu) / ($now - $prevT).TotalSeconds
        $prevCpu = $cpu; $prevT = $now
        # Bytes the process has written so far (all its I/O, which for this program is the database).
        $io = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").WriteTransferCount
        # F formats (no thousands separators, invariant culture) keep each value one CSV field.
        $inv = [Globalization.CultureInfo]::InvariantCulture
        $row = [string]::Format($inv, "{0:s},{1:F2},{2:F3},{3:F1},{4:F1},{5},{6:F1},{7:F1}", $now, $one, ($one / $cores), ($p.WorkingSet64 / 1MB), ($p.PrivateMemorySize64 / 1MB), $p.HandleCount, ((Db-Bytes) / 1MB), ($io / 1MB))
        # A scanner or backup can hold the file for a moment: retry rather than end the run.
        for ($try = 0; $try -lt 5; $try++) {
            try { Add-Content $Csv $row -ErrorAction Stop; break } catch { Start-Sleep -Seconds 2 }
        }
    }
}
finally {
    $rows = @(Import-Csv $Csv)
    if ($rows.Count -gt 0) {
        $elapsed = ((Get-Date) - $start).TotalHours
        $cpuAvg = ($rows | Measure-Object cpu_pct_of_one_core -Average).Average
        $cpuMax = ($rows | Measure-Object cpu_pct_of_one_core -Maximum).Maximum
        $sorted = @($rows | ForEach-Object { [double]$_.cpu_pct_of_one_core } | Sort-Object)
        $p95 = $sorted[[math]::Min($sorted.Count - 1, [math]::Floor($sorted.Count * 0.95))]
        $rssAvg = ($rows | Measure-Object rss_mb -Average).Average
        $rssMax = ($rows | Measure-Object rss_mb -Maximum).Maximum
        $dbGrowth = [double]$rows[-1].db_mb - $dbStart / 1MB
        $written = [double]$rows[-1].io_write_mb_total - [double]$rows[0].io_write_mb_total
        $text = @(
            ("process {0} (pid {1}), {2} one-minute samples over {3:N1} h, {4} logical cores" -f $Process, $p.Id, $rows.Count, $elapsed, $cores)
            ("cpu, % of ONE core  : avg {0:N2}   p95 {1:N2}   max {2:N2}   (= {3:N2} % of the whole machine on average)" -f $cpuAvg, $p95, $cpuMax, ($cpuAvg / $cores))
            ("memory (working set): avg {0:N1} MB   max {1:N1} MB   (first {2} MB, last {3} MB)" -f $rssAvg, $rssMax, $rows[0].rss_mb, $rows[-1].rss_mb)
            ("handles first/last  : {0} / {1}" -f $rows[0].handles, $rows[-1].handles)
            ("database (with wal) : {0:N1} MB now, {1:N1} MB change over the run" -f [double]$rows[-1].db_mb, $dbGrowth)
            ("bytes written       : {0:N1} MB over the run = {1:N2} MB/hour" -f $written, ($written / [math]::Max($elapsed, 0.01)))
        )
        $text | Write-Host   # (summary uses the current culture's numbers; only the CSV is invariant)
        $text | Set-Content ($Csv -replace "\.csv$", "-summary.txt")
    }
}
