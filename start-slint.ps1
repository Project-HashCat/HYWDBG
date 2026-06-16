param(
    [ValidateSet("run", "build", "b")]
    [string]$Mode = "run",

    [switch]$SkipBuild,
    [string]$Listen = "127.0.0.1:31337",
    [string]$HttpListen = "127.0.0.1:31338",

    [string]$RustToolchain = "stable-x86_64-pc-windows-msvc",
    [string]$RustTarget = "x86_64-pc-windows-msvc"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$targetRoot = Join-Path $root "target\$RustTarget"
$debugDir = Join-Path $targetRoot "debug"

$coreExe = Join-Path $debugDir "hywdbg-core-daemon.exe"
$guiExe = Join-Path $debugDir "hywdbg-slint.exe"

$packages = @(
    "hywdbg-core-daemon",
    "hywdbg-slint",
    "winapi-backend",
    "titan-backend",
    "dbgeng-backend",
    "lldb-backend",
    "gdbremote-backend",
    "frida-backend"
)

function Require-Command {
    param([string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Body
    )

    Write-Host "[HYWDbg] $Name" -ForegroundColor Cyan
    & $Body
}

function Invoke-MsvcCargo {
    param([string[]]$CargoArgs)

    Write-Host "[HYWDbg] cargo +$RustToolchain $($CargoArgs -join ' ')" -ForegroundColor DarkCyan

    & cargo "+$RustToolchain" @CargoArgs

    if ($LASTEXITCODE -ne 0) {
        throw "cargo failed with exit code $LASTEXITCODE"
    }
}

function Split-Endpoint {
    param([string]$Endpoint)

    $idx = $Endpoint.LastIndexOf(":")
    if ($idx -lt 1) {
        throw "Bad endpoint: $Endpoint"
    }

    [pscustomobject]@{
        Host = $Endpoint.Substring(0, $idx)
        Port = [int]$Endpoint.Substring($idx + 1)
    }
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port
    )

    $client = [System.Net.Sockets.TcpClient]::new()

    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)

        if (-not $async.AsyncWaitHandle.WaitOne(500)) {
            return $false
        }

        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Wait-TcpPort {
    param(
        [string]$Endpoint,
        [int]$TimeoutSeconds = 20
    )

    $parsed = Split-Endpoint $Endpoint
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        if (Test-TcpPort $parsed.Host $parsed.Port) {
            return
        }

        Start-Sleep -Milliseconds 250
    }

    throw "Timed out waiting for $Endpoint"
}

Require-Command cargo

Invoke-Step "Using MSVC x64 Rust toolchain" {
    Write-Host "Toolchain : $RustToolchain" -ForegroundColor Gray
    Write-Host "Target    : $RustTarget" -ForegroundColor Gray
    Write-Host "Debug dir : $debugDir" -ForegroundColor Gray
}

if (-not $SkipBuild) {
    Invoke-Step "Building HYWDbg Slint GUI, core, and backends" {
        Push-Location $root

        try {
            $cargoArgs = @(
                "build",
                "--target", $RustTarget
            )

            foreach ($pkg in $packages) {
                $cargoArgs += @("-p", $pkg)
            }

            Invoke-MsvcCargo -CargoArgs $cargoArgs
        } finally {
            Pop-Location
        }
    }
}

if ($Mode -eq "b" -or $Mode -eq "build") {
    Write-Host "[HYWDbg] Build-only mode finished." -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $coreExe)) {
    throw "Core daemon not found: $coreExe"
}

if (-not (Test-Path $guiExe)) {
    throw "Slint GUI not found: $guiExe"
}

$coreJob = $null

try {
    Invoke-Step "Starting core daemon on $Listen and $HttpListen" {
        $script = {
            param(
                [string]$Exe,
                [string]$ListenArg,
                [string]$HttpListenArg,
                [string]$BackendDirArg
            )

            & $Exe "--listen" $ListenArg "--http-listen" $HttpListenArg "--backend-dir" $BackendDirArg
            exit $LASTEXITCODE
        }

        $script:coreJob = Start-Job `
            -Name "HYWDbg core" `
            -ScriptBlock $script `
            -ArgumentList $coreExe, $Listen, $HttpListen, $debugDir

        Wait-TcpPort $Listen
    }

    Invoke-Step "Starting Slint GUI" {
        & $guiExe
        if ($LASTEXITCODE -ne 0) {
            throw "Slint GUI exited with code $LASTEXITCODE"
        }
    }
} finally {
    if ($coreJob) {
        Write-Host "[HYWDbg] Stopping core daemon" -ForegroundColor Cyan

        Stop-Job $coreJob -ErrorAction SilentlyContinue
        Receive-Job $coreJob -ErrorAction SilentlyContinue | Write-Host
        Remove-Job $coreJob -Force -ErrorAction SilentlyContinue
    }
}