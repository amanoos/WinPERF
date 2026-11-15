# Does WinPerf talk to anything outside this machine? (T35, NFR-003)
#
# Starts the report and a short monitor run against a scratch database, uses the report, and lists
# every TCP connection and UDP endpoint the two processes own. The report may LISTEN on 127.0.0.1;
# anything else (a connection to another address, any UDP endpoint) makes this fail.
#
#   .\scripts\net-check.ps1            # uses target\release
#   .\scripts\net-check.ps1 -Port 8161 -Seconds 25
param([int]$Port = 8161, [int]$Seconds = 25, [string]$Bin = "$PSScriptRoot\..\target\release")

$scratch = Join-Path $env:TEMP "winperf-net-check"
Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
$db = Join-Path $scratch "n.db"

$report = Start-Process "$Bin\winperf-report.exe" -ArgumentList "--db", $db, "--port", $Port -PassThru -WindowStyle Hidden
$monitor = Start-Process "$Bin\winperf.exe" -ArgumentList "monitor", "run", "--db", $db, "--ticks", $Seconds, "--interval", "1" -PassThru -WindowStyle Hidden
try {
    Start-Sleep 6
    1..5 | ForEach-Object {
        try { $null = Invoke-WebRequest "http://127.0.0.1:$Port/api/status" -UseBasicParsing } catch { }
        Start-Sleep 1
    }
    $ids = @($report.Id, $monitor.Id)
    $tcp = @(Get-NetTCPConnection -OwningProcess $ids -ErrorAction SilentlyContinue)
    $udp = @(Get-NetUDPEndpoint -OwningProcess $ids -ErrorAction SilentlyContinue)
    $tcp | Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize | Out-String | Write-Host
    $outside = @($tcp | Where-Object {
        $_.State -ne "Listen" -and $_.RemoteAddress -notin "127.0.0.1", "::1"
    })
    $badListen = @($tcp | Where-Object { $_.State -eq "Listen" -and $_.LocalAddress -notin "127.0.0.1", "::1" })
    "TCP connections to other addresses : $($outside.Count)"
    "TCP listeners not on loopback      : $($badListen.Count)"
    "UDP endpoints                      : $($udp.Count)"
    if ($outside.Count -or $badListen.Count -or $udp.Count) { Write-Error "WinPerf is using the network beyond localhost"; exit 1 }
    "OK: nothing leaves this machine."
}
finally {
    Stop-Process -Id $report.Id -Force -ErrorAction SilentlyContinue
    Wait-Process -Id $monitor.Id -Timeout ($Seconds + 15) -ErrorAction SilentlyContinue
    Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
