# Soak test: run `winperf monitor run` for a while and record its own CPU, memory and DB growth.
# Usage: ./scripts/soak.ps1 [-Minutes 60] [-Interval 5] [-NoNetwork] [-OutDir <dir>]
param(
    [int]$Minutes = 60,
    [int]$Interval = 5,
    [switch]$NoNetwork,
    [string]$OutDir = (Join-Path $env:TEMP "winperf-soak")
)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot '..\target\release\winperf.exe'
if (-not (Test-Path $exe)) { throw "build first: cargo build --release -p winperf-cli" }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$db = Join-Path $OutDir 'soak.db'
Remove-Item "$db*" -Force -ErrorAction SilentlyContinue
$csv = Join-Path $OutDir 'soak.csv'
$procArgs = @('--db', $db, 'monitor', 'run', '--interval', $Interval)
if ($NoNetwork) { $procArgs += '--no-network' }
$p = Start-Process -FilePath $exe -ArgumentList $procArgs -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $OutDir 'out.log') -RedirectStandardError (Join-Path $OutDir 'err.log')
$cores = [Environment]::ProcessorCount
"minute,cpu_pct_of_one_core,rss_mb,db_mb" | Set-Content $csv
$end = (Get-Date).AddMinutes($Minutes)
$prevCpu = $p.TotalProcessorTime.TotalSeconds; $prevT = Get-Date; $n = 0
while ((Get-Date) -lt $end -and -not $p.HasExited) {
    Start-Sleep -Seconds 60
    $p.Refresh(); if ($p.HasExited) { break }
    $now = Get-Date; $cpu = $p.TotalProcessorTime.TotalSeconds
    $pct = 100 * ($cpu - $prevCpu) / ($now - $prevT).TotalSeconds
    $prevCpu = $cpu; $prevT = $now; $n++
    $dbmb = (Get-ChildItem "$db*" | Measure-Object Length -Sum).Sum / 1MB
    "{0},{1:N2},{2:N1},{3:N1}" -f $n, $pct, ($p.WorkingSet64 / 1MB), $dbmb | Add-Content $csv
}
$exited = $p.HasExited
if (-not $exited) { Stop-Process -Id $p.Id }
$rows = Import-Csv $csv
"exited early: $exited ; samples: $($rows.Count) ; logical cores: $cores"
"cpu % of one core: avg {0:N2}  max {1:N2}" -f ($rows | Measure-Object cpu_pct_of_one_core -Average).Average, ($rows | Measure-Object cpu_pct_of_one_core -Maximum).Maximum
"rss MB: first {0}  last {1}  max {2:N1}" -f $rows[0].rss_mb, $rows[-1].rss_mb, ($rows | Measure-Object rss_mb -Maximum).Maximum
"db MB: last {0}" -f $rows[-1].db_mb
