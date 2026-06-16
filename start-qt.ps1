param(
    [ValidateSet("run", "build", "b")]
    [string]$Mode = "run",
    [switch]$SkipRustBuild,
    [string]$Listen = "127.0.0.1:31337",
    [string]$HttpListen = "127.0.0.1:31338",
    [string]$RustToolchain = "stable-x86_64-pc-windows-msvc",
    [string]$RustTarget = "x86_64-pc-windows-msvc",
    [string]$QtPrefix = $env:QT_ROOT
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$debugDir = Join-Path $root "target\$RustTarget\debug"
$coreExe = Join-Path $debugDir "hywdbg-core-daemon.exe"
$qtBuildDir = Join-Path $root "target\hywdbg-qt-build"
$qtExe = Join-Path $qtBuildDir "Debug\hywdbg-qt.exe"
if(-not (Test-Path $qtExe)) { $qtExe = Join-Path $qtBuildDir "hywdbg-qt.exe" }

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "Required command not found: $Name" }
}

function Invoke-Step([string]$Name, [scriptblock]$Body) {
    Write-Host "[HYWDbg] $Name" -ForegroundColor Cyan
    & $Body
}

function Invoke-MsvcCargo([string[]]$CargoArgs) {
    Write-Host "[HYWDbg] cargo +$RustToolchain $($CargoArgs -join ' ')" -ForegroundColor DarkCyan
    & cargo "+$RustToolchain" @CargoArgs
    if($LASTEXITCODE -ne 0) { throw "cargo failed with exit code $LASTEXITCODE" }
}

function Split-Endpoint([string]$Endpoint) {
    $idx = $Endpoint.LastIndexOf(":")
    if ($idx -lt 1) { throw "Bad endpoint: $Endpoint" }
    [pscustomobject]@{ Host = $Endpoint.Substring(0, $idx); Port = [int]$Endpoint.Substring($idx + 1) }
}

function Test-TcpPort([string]$HostName, [int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(500)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch { return $false } finally { $client.Close() }
}

function Wait-TcpPort([string]$Endpoint, [int]$TimeoutSeconds = 20) {
    $parsed = Split-Endpoint $Endpoint
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-TcpPort $parsed.Host $parsed.Port) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Timed out waiting for $Endpoint"
}

Require-Command cargo
Require-Command cmake

$packages = @(
    "hywdbg-core-daemon",
    "winapi-backend",
    "titan-backend",
    "dbgeng-backend",
    "lldb-backend",
    "gdbremote-backend",
    "frida-backend"
)

if(-not $SkipRustBuild) {
    Invoke-Step "Building Rust core and backends" {
        Push-Location $root
        try {
            $cargoArgs = @("build", "--target", $RustTarget)
            foreach($p in $packages) { $cargoArgs += @("-p", $p) }
            Invoke-MsvcCargo $cargoArgs
        } finally { Pop-Location }
    }
}

Invoke-Step "Configuring Qt UI" {
    # Remove stale cmake cache (e.g. leftover ARM64 config from a previous failed run).
    if (Test-Path (Join-Path $qtBuildDir "CMakeCache.txt")) {
        Write-Host "[HYWDbg] Removing stale cmake cache at $qtBuildDir" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $qtBuildDir
    }
    $cmakeArgs = @("-S", (Join-Path $root "apps\hywdbg-qt"), "-B", $qtBuildDir, "-A", "x64")
    if($QtPrefix) { $cmakeArgs += "-DCMAKE_PREFIX_PATH=$QtPrefix" }
    & cmake @cmakeArgs
    if($LASTEXITCODE -ne 0) {
        throw "cmake configure failed. Install Qt 6 Widgets/Network and set `$env:QT_ROOT, e.g. C:\Qt\6.11.1\msvc2022_64"
    }
}

Invoke-Step "Building Qt UI" {
    & cmake --build $qtBuildDir --config Debug
    if($LASTEXITCODE -ne 0) { throw "cmake build failed" }
}

if($Mode -eq "b" -or $Mode -eq "build") {
    Write-Host "[HYWDbg] Build-only finished." -ForegroundColor Green
    exit 0
}

if(-not (Test-Path $coreExe)) { throw "Core daemon not found: $coreExe" }
if(-not (Test-Path $qtExe)) { throw "Qt GUI not found: $qtExe" }

$coreJob = $null
try {
    Invoke-Step "Starting core daemon" {
        $script = {
            param([string]$Exe, [string]$ListenArg, [string]$HttpListenArg, [string]$BackendDirArg)
            & $Exe "--listen" $ListenArg "--http-listen" $HttpListenArg "--backend-dir" $BackendDirArg
            exit $LASTEXITCODE
        }
        $script:coreJob = Start-Job -Name "HYWDbg core" -ScriptBlock $script -ArgumentList $coreExe, $Listen, $HttpListen, $debugDir
        Wait-TcpPort $Listen
    }
    Invoke-Step "Starting Qt GUI" { & $qtExe }
} finally {
    if($coreJob) {
        Write-Host "[HYWDbg] Stopping core daemon" -ForegroundColor Cyan
        Stop-Job $coreJob -ErrorAction SilentlyContinue
        Receive-Job $coreJob -ErrorAction SilentlyContinue | Write-Host
        Remove-Job $coreJob -Force -ErrorAction SilentlyContinue
    }
}
