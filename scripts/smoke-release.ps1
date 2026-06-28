$ErrorActionPreference = 'Stop'

param(
    [string]$BinaryPath = ".\\cape.exe"
)

Write-Host "== cape smoke (windows) =="
& $BinaryPath --help | Out-Null
Write-Host "help: ok"

& $BinaryPath audit | Out-Null
Write-Host "audit: ok"

& $BinaryPath sentinel --interval 5ms | Out-Null
Write-Host "sentinel: ok"

Write-Host "smoke: ok"
