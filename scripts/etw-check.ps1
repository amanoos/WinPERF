#Requires -Version 7
# Verifies per-process network attribution (ETW). MUST be run from an ELEVATED PowerShell
# ("Run as administrator"): kernel tracing needs administrator rights.
#
#   pwsh -File scripts\etw-check.ps1
#
# 1. attribution tests: loopback TCP and UDP traffic must be credited to this test process, the
#    metrics source must turn it into a rate, and the kernel session must be gone afterwards;
# 2. an overhead report: CPU, memory and bytes attributed during ~10 s of heavy loopback traffic.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This shell is NOT elevated. Re-run from "Run as administrator".' -ForegroundColor Red
    exit 2
}

Write-Host '==> attribution tests' -ForegroundColor Cyan
cargo test -p winperf-windows --test etw_live -- --nocapture --test-threads=1
if ($LASTEXITCODE -ne 0) { Write-Host 'FAILED: attribution tests' -ForegroundColor Red; exit $LASTEXITCODE }

Write-Host '==> overhead report (about 10 s of heavy loopback traffic)' -ForegroundColor Cyan
cargo test -p winperf-windows --test etw_live -- --ignored --nocapture
if ($LASTEXITCODE -ne 0) { Write-Host 'FAILED: overhead report' -ForegroundColor Red; exit $LASTEXITCODE }

Write-Host '==> leftover WinPerf ETW sessions (should be none)' -ForegroundColor Cyan
$left = logman query -ets 2>&1 | Select-String 'winperf'
if ($left) { $left } else { 'none' }
Write-Host 'Done. Paste the output back so the results can be recorded.' -ForegroundColor Green
