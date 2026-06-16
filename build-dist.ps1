param(
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [switch]$Clean,
    [switch]$NoZip,
    [switch]$SkipRustBuild,
    [switch]$SkipQtBuild,

    [string]$Listen = "127.0.0.1:31337",
    [string]$HttpListen = "127.0.0.1:31338",

    [string]$RustToolchain = "stable-x86_64-pc-windows-msvc",
    [string]$RustTarget = "x86_64-pc-windows-msvc",
    [string]$QtPrefix = $env:QT_ROOT,
    [string]$Generator = "Visual Studio 17 2022"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$qtSrc = Join-Path $root "apps\hywdbg-qt"
$qtBuildDir = Join-Path $root "target\hywdbg-qt-build"
$distRoot = Join-Path $root "dist"
$cmakeArch = "x64"
$distSuffix = "x64"
if ($RustTarget -match "i686") {
    $distSuffix = "x86"
} elseif ($RustTarget -match "aarch64") {
    $distSuffix = "arm64"
}

$distDir = Join-Path $distRoot "HYWDbg-$Config-$distSuffix"
$distZip = "$distDir.zip"

$rustProfile = if ($Config -eq "Release") { "release" } else { "debug" }
$rustProfileDir = Join-Path $root "target\$RustTarget\$rustProfile"

$rustPackages = @(
    "hywdbg-core-daemon",
    "winapi-backend",
    "titan-backend",
    "dbgeng-backend",
    "lldb-backend",
    "gdbremote-backend",
    "frida-backend"
)

$backendExeNames = @(
    "winapi-backend.exe",
    "titan-backend.exe",
    "dbgeng-backend.exe",
    "lldb-backend.exe",
    "gdbremote-backend.exe",
    "frida-backend.exe"
)

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "[HYWDbg] $Name" -ForegroundColor Cyan
    & $Body
}

function Invoke-CmdChecked {
    param(
        [string]$Name,
        [string]$Exe,
        [string[]]$CmdArgs
    )
    Write-Host "[HYWDbg] $Exe $($CmdArgs -join ' ')" -ForegroundColor DarkCyan
    & $Exe @CmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

function Find-QtExe {
    $preferred = Join-Path $qtBuildDir "$Config\hywdbg-qt.exe"
    if (Test-Path $preferred) { return $preferred }

    $found = Get-ChildItem -Path $qtBuildDir -Recurse -Filter "hywdbg-qt.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName |
        Select-Object -First 1

    if ($found) { return $found.FullName }
    throw "Qt GUI exe not found under: $qtBuildDir"
}

function Copy-RequiredFile {
    param([string]$Source, [string]$Destination)
    if (-not (Test-Path $Source)) {
        throw "Required file missing: $Source"
    }
    Copy-Item -Force $Source $Destination
}

Require-Command cargo
Require-Command cmake

if (-not $QtPrefix) {
    $candidates = @(
        "C:\Qt\6.11.1\msvc2022_64",
        "C:\Qt\6.10.0\msvc2022_64",
        "C:\Qt\6.9.0\msvc2022_64",
        "C:\Qt\6.8.0\msvc2022_64"
    )
    foreach ($p in $candidates) {
        if (Test-Path (Join-Path $p "bin\windeployqt.exe")) {
            $QtPrefix = $p
            break
        }
    }
}

if (-not $QtPrefix -or -not (Test-Path (Join-Path $QtPrefix "bin\windeployqt.exe"))) {
    throw "Qt MSVC x64 not found. Set QT_ROOT, e.g. C:\Qt\6.11.1\msvc2022_64"
}

$qtBin = Join-Path $QtPrefix "bin"
$windeployqt = Join-Path $qtBin "windeployqt.exe"
$env:PATH = "$qtBin;$env:PATH"

Invoke-Step "Using toolchains" {
    Write-Host "Rust toolchain : $RustToolchain" -ForegroundColor Gray
    Write-Host "Rust target    : $RustTarget" -ForegroundColor Gray
    Write-Host "Qt prefix      : $QtPrefix" -ForegroundColor Gray
    Write-Host "Config         : $Config" -ForegroundColor Gray
    Write-Host "Dist           : $distDir" -ForegroundColor Gray
}

if (-not $SkipRustBuild) {
    Invoke-Step "Building Rust core and backends" {
        Push-Location $root
        try {
            $cargoArgs = @("build", "--target", $RustTarget)
            if ($Config -eq "Release") { $cargoArgs += "--release" }
            foreach ($p in $rustPackages) { $cargoArgs += @("-p", $p) }
            Invoke-CmdChecked "cargo build" "cargo" (@("+$RustToolchain") + $cargoArgs)
        } finally {
            Pop-Location
        }
    }
}

if (-not $SkipQtBuild) {
    Invoke-Step "Configuring Qt UI" {
        # Remove stale cmake cache (e.g. leftover ARM64 config) before reconfiguring.
        if (Test-Path (Join-Path $qtBuildDir "CMakeCache.txt")) {
            Write-Host "[HYWDbg] Removing stale cmake cache at $qtBuildDir" -ForegroundColor Yellow
            Remove-Item -Recurse -Force $qtBuildDir
        }
        $cmakeArgs = @(
            "-S", $qtSrc,
            "-B", $qtBuildDir,
            "-G", "Ninja",
            "-DCMAKE_BUILD_TYPE=$Config",
            "-DCMAKE_PREFIX_PATH=$QtPrefix"
        )
        Invoke-CmdChecked "cmake configure" "cmake" $cmakeArgs
    }

    Invoke-Step "Building Qt UI" {
        Invoke-CmdChecked "cmake build" "cmake" @("--build", $qtBuildDir, "--config", $Config)
    }
}

$qtExe = Find-QtExe
$coreExe = Join-Path $rustProfileDir "hywdbg-core-daemon.exe"

Invoke-Step "Preparing dist folder" {
    if ($Clean -and (Test-Path $distDir)) {
        Remove-Item -Recurse -Force $distDir
    }
    New-Item -ItemType Directory -Force -Path $distDir | Out-Null
}

Invoke-Step "Copying HYWDbg executables" {
    Copy-RequiredFile $qtExe (Join-Path $distDir "HYWDbg.exe")
    Copy-RequiredFile $coreExe (Join-Path $distDir "hywdbg-core-daemon.exe")

    foreach ($exe in $backendExeNames) {
        $src = Join-Path $rustProfileDir $exe
        Copy-RequiredFile $src (Join-Path $distDir $exe)
    }

    if ($Config -eq "Debug") {
        foreach ($pdb in @("hywdbg-qt.pdb", "HYWDbg.pdb")) {
            $maybe = Join-Path (Split-Path -Parent $qtExe) $pdb
            if (Test-Path $maybe) { Copy-Item -Force $maybe $distDir }
        }
        Get-ChildItem -Path $rustProfileDir -Filter "*.pdb" -ErrorAction SilentlyContinue | Copy-Item -Destination $distDir -Force -ErrorAction SilentlyContinue
    }

    $themesSource = Join-Path $root "themes"
    if (Test-Path $themesSource) {
        $themesDest = Join-Path $distDir "themes"
        Write-Host "[HYWDbg] Copying themes directory" -ForegroundColor Green
        Copy-Item -Recurse -Force $themesSource $distDir
    }
}

Invoke-Step "Writing runner scripts" {
    $runPs1 = @'
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$core = Join-Path $dir "hywdbg-core-daemon.exe"
$gui = Join-Path $dir "HYWDbg.exe"
$listen = "127.0.0.1:31337"
$httpListen = "127.0.0.1:31338"

Write-Host "[HYWDbg] Starting core..." -ForegroundColor Cyan
$coreProcess = Start-Process -FilePath $core -ArgumentList @("--listen", $listen, "--http-listen", $httpListen, "--backend-dir", $dir) -WorkingDirectory $dir -PassThru
Start-Sleep -Milliseconds 700

try {
    Write-Host "[HYWDbg] Starting GUI..." -ForegroundColor Cyan
    $guiProcess = Start-Process -FilePath $gui -WorkingDirectory $dir -PassThru
    Wait-Process -Id $guiProcess.Id
} finally {
    if ($coreProcess -and -not $coreProcess.HasExited) {
        Write-Host "[HYWDbg] Stopping core..." -ForegroundColor Cyan
        Stop-Process -Id $coreProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
'@
    $runPs1 | Set-Content -Encoding UTF8 (Join-Path $distDir "run-hywdbg.ps1")

    $runBat = @'
@echo off
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0run-hywdbg.ps1"
'@
    $runBat | Set-Content -Encoding ASCII (Join-Path $distDir "run-hywdbg.bat")

    $readme = @"
HYWDbg $Config x64 portable package

Run:
  run-hywdbg.bat

Manual:
  hywdbg-core-daemon.exe --listen 127.0.0.1:31337 --http-listen 127.0.0.1:31338 --backend-dir .
  HYWDbg.exe

Notes:
  Debug builds deploy qwindowsd.dll and Qt6*D.dll.
  Release builds deploy qwindows.dll and non-debug Qt6*.dll.
"@
    $readme | Set-Content -Encoding UTF8 (Join-Path $distDir "README.txt")
}

Invoke-Step "Deploying Qt DLLs/plugins with windeployqt" {
    $modeFlag = if ($Config -eq "Debug") { "--debug" } else { "--release" }
    $deployArgs = @(
        $modeFlag,
        "--compiler-runtime",
        "--no-translations",
        "--force",
        (Join-Path $distDir "HYWDbg.exe")
    )
    Invoke-CmdChecked "windeployqt" $windeployqt $deployArgs
}

Invoke-Step "Verifying Qt platform plugin" {
    $platformDir = Join-Path $distDir "platforms"
    $platformPlugin = if ($Config -eq "Debug") {
        Join-Path $platformDir "qwindowsd.dll"
    } else {
        Join-Path $platformDir "qwindows.dll"
    }

    if (-not (Test-Path $platformPlugin)) {
        $any = Get-ChildItem -Path $platformDir -Filter "qwindows*.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $any) {
            throw "Qt platform plugin missing. Expected: $platformPlugin"
        }
        Write-Host "[HYWDbg] Found platform plugin: $($any.FullName)" -ForegroundColor Yellow
    } else {
        Write-Host "[HYWDbg] Found platform plugin: $platformPlugin" -ForegroundColor Green
    }
}

if (-not $NoZip) {
    Invoke-Step "Creating zip package" {
        if (Test-Path $distZip) { Remove-Item -Force $distZip }
        Compress-Archive -Path (Join-Path $distDir "*") -DestinationPath $distZip -Force
        Write-Host "[HYWDbg] Wrote $distZip" -ForegroundColor Green
    }
}

Write-Host "[HYWDbg] Dist ready: $distDir" -ForegroundColor Green
