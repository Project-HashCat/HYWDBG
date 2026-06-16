param(
    [switch]$SkipBuild,
    [switch]$Browser,
    [switch]$NoInstall,
    [string]$Listen = "127.0.0.1:31337",
    [string]$HttpListen = "127.0.0.1:31338",

    [string]$RustToolchain = "stable-x86_64-pc-windows-msvc",
    [string]$RustTarget = "x86_64-pc-windows-msvc"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$uiDir = Join-Path $root "apps\hywdbg-tauri"

$targetDir = Join-Path $root "target\$RustTarget"
$debugDir = Join-Path $targetDir "debug"
$coreExe = Join-Path $debugDir "hywdbg-core-daemon.exe"

$backendPackages = @(
    "hywdbg-core-daemon",
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

function Invoke-Cargo {
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
    param([string]$HostName, [int]$Port)

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
    param([string]$Endpoint, [int]$TimeoutSeconds = 20)

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

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)

    Write-Host "[HYWDbg] $Name" -ForegroundColor Cyan
    & $Body
}

Require-Command cargo
Require-Command npm

Invoke-Step "Using Rust toolchain" {
    Write-Host "Toolchain : $RustToolchain" -ForegroundColor Gray
    Write-Host "Target    : $RustTarget" -ForegroundColor Gray
    Write-Host "Debug dir : $debugDir" -ForegroundColor Gray
}

if (-not $NoInstall -and -not (Test-Path (Join-Path $uiDir "node_modules"))) {
    Invoke-Step "Installing frontend dependencies" {
        Push-Location $uiDir
        try {
            & npm install --package-lock=false

            if ($LASTEXITCODE -ne 0) {
                throw "npm install failed with exit code $LASTEXITCODE"
            }
        } finally {
            Pop-Location
        }
    }
}

if (-not $SkipBuild) {
    Invoke-Step "Building MSVC x64 core and backends" {
        Push-Location $root
        try {
            $args = @("build", "--target", $RustTarget)

            foreach ($pkg in $backendPackages) {
                $args += @("-p", $pkg)
            }

            Invoke-Cargo $args
        } finally {
            Pop-Location
        }
    }
} elseif (-not (Test-Path $coreExe)) {
    Invoke-Step "Building missing MSVC x64 core daemon" {
        Push-Location $root
        try {
            Invoke-Cargo @(
                "build",
                "--target", $RustTarget,
                "-p", "hywdbg-core-daemon"
            )
        } finally {
            Pop-Location
        }
    }
}

if (-not (Test-Path $coreExe)) {
    throw "Core daemon not found: $coreExe"
}

$coreArgs = @(
    "--listen", $Listen,
    "--http-listen", $HttpListen,
    "--backend-dir", $debugDir
)

$coreJob = $null

$oldRustupToolchain = $env:RUSTUP_TOOLCHAIN
$oldCargoBuildTarget = $env:CARGO_BUILD_TARGET

try {
    # 让 npm run tauri dev 内部调用 cargo 时也强制走 MSVC x64
    $env:RUSTUP_TOOLCHAIN = $RustToolchain
    $env:CARGO_BUILD_TARGET = $RustTarget

    Invoke-Step "Starting core daemon on $Listen and $HttpListen" {
        $script = {
            param([string]$Exe, [string[]]$Args)

            & $Exe @Args
            exit $LASTEXITCODE
        }

        $script:coreJob = Start-Job -Name "HYWDbg core" -ScriptBlock $script -ArgumentList $coreExe, $coreArgs

        Wait-TcpPort $Listen
    }

    Push-Location $uiDir

    try {
        if ($Browser) {
            Invoke-Step "Starting browser UI at http://127.0.0.1:1420" {
                Start-Process "http://127.0.0.1:1420"

                & npm run dev

                if ($LASTEXITCODE -ne 0) {
                    throw "npm run dev failed with exit code $LASTEXITCODE"
                }
            }
        } else {
            Invoke-Step "Starting Tauri GUI with MSVC x64 cargo" {
                & npm run tauri dev -- --target $RustTarget

                if ($LASTEXITCODE -ne 0) {
                    throw "npm run tauri dev failed with exit code $LASTEXITCODE"
                }
            }
        }
    } finally {
        Pop-Location
    }
} finally {
    $env:RUSTUP_TOOLCHAIN = $oldRustupToolchain
    $env:CARGO_BUILD_TARGET = $oldCargoBuildTarget

    if ($coreJob) {
        Write-Host "[HYWDbg] Stopping core daemon" -ForegroundColor Cyan

        Stop-Job $coreJob -ErrorAction SilentlyContinue
        Receive-Job $coreJob -ErrorAction SilentlyContinue | Write-Host
        Remove-Job $coreJob -Force -ErrorAction SilentlyContinue
    }
}