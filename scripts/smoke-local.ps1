param(
    [string]$BinaryPath = ".\target\debug\cape.exe",
    [int]$Port = 8484
)

$ErrorActionPreference = 'Stop'

Write-Host "== SafeRouter local smoke =="

$root = Split-Path -Parent $PSScriptRoot
$bin = (Resolve-Path $BinaryPath).Path
$stdout = Join-Path $env:TEMP 'saferouter-web.out.log'
$stderr = Join-Path $env:TEMP 'saferouter-web.err.log'

$proc = Start-Process -FilePath $bin -ArgumentList @('web', '--listen', "127.0.0.1:$Port", '--site', 'site') -PassThru -WindowStyle Hidden -WorkingDirectory $root -RedirectStandardOutput $stdout -RedirectStandardError $stderr

try {
    for ($i = 0; $i -lt 50; $i++) {
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/health" -Method Get | Out-Null
            break
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }

    if ($proc.HasExited) {
        throw "web daemon exited early. stderr: $(Get-Content $stderr -ErrorAction SilentlyContinue | Out-String)"
    }
    Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/health" -Method Get | Out-Null
    Write-Host "health: ok"

    try {
        Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/score" -Method Post -ContentType 'application/json' -Body '{"base_url":""}' | Out-Null
        throw "expected /api/score invalid request to fail"
    } catch {
        Write-Host "invalid score request: ok"
    }

    $session = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/session/init" -Method Post -ContentType 'application/json' -Body '{"task":"Smoke test session"}'
    if (-not $session.session_id) { throw "session init returned no session_id" }
    Write-Host "session init: ok"

    $policy = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/policy/evaluate" -Method Post -ContentType 'application/json' -Body (@{
        session_id    = $session.session_id
        action_kind   = 'file-read'
        target        = '.env'
        provider_risk = 'high'
    } | ConvertTo-Json -Compress)
    if (-not $policy.decision) { throw "policy evaluation returned no decision" }
    Write-Host "policy evaluate: ok"

    Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -UseBasicParsing | Out-Null
    Write-Host "site: ok"

    Write-Host "smoke-local: ok"
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
    }
}
