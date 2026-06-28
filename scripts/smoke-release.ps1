param(
    [string]$BinaryPath = ".\\cape.exe"
)

$ErrorActionPreference = 'Stop'

Write-Host "== cape smoke (windows) =="
& $BinaryPath --help | Out-Null
Write-Host "help: ok"

& $BinaryPath audit | Out-Null
Write-Host "audit: ok"

& $BinaryPath registry list | Out-Null
Write-Host "registry: ok"

& $BinaryPath score --help | Out-Null
Write-Host "score: ok"

Write-Host "smoke: ok"
