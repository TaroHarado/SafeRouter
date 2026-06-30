param(
    [Parameter(Mandatory = $true)]
    [string]$Host,

    [Parameter(Mandatory = $true)]
    [string]$User,

    [string]$TargetDir = '/opt/saferouter',
    [string]$ServiceName = 'saferouter',
    [string]$RemoteBuildDir = '/tmp/saferouter-build',
    [string]$SshPath = 'C:\Windows\System32\OpenSSH\ssh.exe',
    [string]$ScpPath = 'C:\Windows\System32\OpenSSH\scp.exe',
    [string]$TarPath = 'tar.exe'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $SshPath)) {
    throw "ssh.exe not found at $SshPath"
}

if (-not (Test-Path -LiteralPath $ScpPath)) {
    throw "scp.exe not found at $ScpPath"
}

if (-not (Get-Command $TarPath -ErrorAction SilentlyContinue)) {
    throw "tar not found: $TarPath"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$servicePath = Join-Path $PSScriptRoot 'saferouter.service'
$envExamplePath = Join-Path $PSScriptRoot 'saferouter.env.example'
$renderedServicePath = Join-Path $env:TEMP "$ServiceName.service"
$archivePath = Join-Path $env:TEMP 'saferouter-src.tgz'

if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}

$serviceTemplate = Get-Content -LiteralPath $servicePath -Raw
$serviceRendered = $serviceTemplate.Replace('__SERVICE_USER__', $User)
[System.IO.File]::WriteAllText($renderedServicePath, $serviceRendered, [System.Text.UTF8Encoding]::new($false))

& $TarPath -czf $archivePath -C $repoRoot --exclude target --exclude .git .
if (-not $?) { throw 'source archive creation failed' }

& $SshPath "$User@$Host" "command -v cargo >/dev/null 2>&1 || { echo 'cargo not installed on remote host'; exit 1; }; sudo mkdir -p $TargetDir /etc/saferouter /var/log/saferouter /var/lib/saferouter $RemoteBuildDir; sudo chown -R ${User}:${User} $TargetDir /var/log/saferouter /var/lib/saferouter $RemoteBuildDir"
if (-not $?) { throw 'remote mkdir/chown failed' }

& $ScpPath $archivePath "$User@$Host`:$RemoteBuildDir/source.tgz"
if (-not $?) { throw 'source archive upload failed' }

& $ScpPath $renderedServicePath "$User@$Host`:/tmp/$ServiceName.service"
if (-not $?) { throw 'service upload failed' }

& $ScpPath $envExamplePath "$User@$Host`:/tmp/$ServiceName.env.example"
if (-not $?) { throw 'env example upload failed' }

& $SshPath "$User@$Host" "rm -rf $RemoteBuildDir/src && mkdir -p $RemoteBuildDir/src && tar -xzf $RemoteBuildDir/source.tgz -C $RemoteBuildDir/src && cd $RemoteBuildDir/src && cargo build --release && install -m 0755 target/release/sr $TargetDir/sr && sudo mv /tmp/$ServiceName.service /etc/systemd/system/$ServiceName.service && if [ ! -f /etc/saferouter/$ServiceName.env ]; then sudo mv /tmp/$ServiceName.env.example /etc/saferouter/$ServiceName.env; else rm -f /tmp/$ServiceName.env.example; fi && sudo systemctl daemon-reload && sudo systemctl enable $ServiceName && sudo systemctl restart $ServiceName && sudo systemctl --no-pager --full status $ServiceName"
if (-not $?) { throw 'remote service install failed' }

Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $renderedServicePath -Force -ErrorAction SilentlyContinue
