#Requires -Version 7
# Definition-of-done gate: format, lint, test. Run from anywhere.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

function Step($name, [scriptblock]$cmd) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $cmd
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $name" -ForegroundColor Red; exit $LASTEXITCODE }
}

Step 'cargo fmt --check'  { cargo fmt --all -- --check }
Step 'cargo clippy'       { cargo clippy --workspace --all-targets -- -D warnings }
Step 'cargo test'         { cargo test --workspace }
Write-Host 'All checks passed.' -ForegroundColor Green
