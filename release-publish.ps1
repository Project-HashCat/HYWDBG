param(
    [string]$Version = "",
    [string]$PublishDir = "",
    [switch]$SkipTauri,
    [switch]$NoInstall,
    [switch]$NoZip,
    [switch]$Clean,
    [switch]$GitHubRelease,
    [switch]$Draft
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$uiDir = Join-Path $root "apps\hywdbg-tauri"
$releaseDir = Join-Path $root "target\release"
$packageJsonPath = Join-Path $uiDir "package.json"

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

function Copy-IfExists {
    param([string]$Path, [string]$Destination)
    if (Test-Path $Path) {
        Copy-Item $Path $Destination -Force
        return $true
    }
    Write-Warning "Missing artifact: $Path"
    return $false
}

Require-Command cargo
Require-Command npm

if (-not $Version) {
    $pkg = Get-Content $packageJsonPath -Raw | ConvertFrom-Json
    $Version = [string]$pkg.version
}

if (-not $PublishDir) {
    $PublishDir = Join-Path $root "dist\publish"
}

if ($GitHubRelease -and $NoZip) {
    throw "-GitHubRelease requires a zip artifact; remove -NoZip."
}

$packageName = "HYWDbg-$Version-windows-x64"
$stage = Join-Path $PublishDir $packageName
$zipPath = Join-Path $PublishDir "$packageName.zip"
$binDir = Join-Path $stage "bin"
$guiDir = Join-Path $stage "gui"
$installerDir = Join-Path $stage "installer"

if ($Clean) {
    Invoke-Step "Cleaning publish output" {
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    }
}

New-Item -ItemType Directory -Force $binDir, $guiDir, $installerDir | Out-Null

if (-not $NoInstall -and -not (Test-Path (Join-Path $uiDir "node_modules"))) {
    Invoke-Step "Installing frontend dependencies" {
        Push-Location $uiDir
        try {
            & npm install --package-lock=false
            if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE" }
        } finally {
            Pop-Location
        }
    }
}

Invoke-Step "Building release core and backends" {
    Push-Location $root
    try {
        & cargo build --workspace --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

if (-not $SkipTauri) {
    Invoke-Step "Building release Tauri bundle" {
        Push-Location $uiDir
        try {
            & npm run tauri build
            if ($LASTEXITCODE -ne 0) { throw "npm run tauri build failed with exit code $LASTEXITCODE" }
        } finally {
            Pop-Location
        }
    }
}

$backendExeNames = @(
    "hywdbg-core-daemon.exe",
    "winapi-backend.exe",
    "titan-backend.exe",
    "dbgeng-backend.exe",
    "lldb-backend.exe",
    "gdbremote-backend.exe",
    "frida-backend.exe"
)

Invoke-Step "Collecting daemon and backend binaries" {
    foreach ($name in $backendExeNames) {
        Copy-IfExists (Join-Path $releaseDir $name) $binDir | Out-Null
    }
}

Invoke-Step "Collecting GUI binaries and installers" {
    $tauriReleaseRoots = @(
        (Join-Path $uiDir "src-tauri\target\release"),
        $releaseDir
    )

    foreach ($dir in $tauriReleaseRoots) {
        if (-not (Test-Path $dir)) { continue }

        Get-ChildItem $dir -Filter "*.exe" -File -ErrorAction SilentlyContinue |
            Where-Object { $backendExeNames -notcontains $_.Name } |
            ForEach-Object { Copy-Item $_.FullName $guiDir -Force }

        $bundleDir = Join-Path $dir "bundle"
        if (Test-Path $bundleDir) {
            Copy-Item $bundleDir (Join-Path $installerDir "bundle") -Recurse -Force
        }
    }
}

Invoke-Step "Writing release launchers" {
    @'
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin = Join-Path $root "bin"
$core = Join-Path $bin "hywdbg-core-daemon.exe"
& $core --listen 127.0.0.1:31337 --http-listen 127.0.0.1:31338 --backend-dir $bin
'@ | Set-Content (Join-Path $stage "run-core.ps1") -Encoding UTF8

    @'
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin = Join-Path $root "bin"
$core = Join-Path $bin "hywdbg-core-daemon.exe"
$gui = Get-ChildItem (Join-Path $root "gui") -Filter "*.exe" -File | Select-Object -First 1

if (-not (Test-Path $core)) {
    throw "Missing core daemon: $core"
}
if (-not $gui) {
    throw "Missing GUI executable under $root\gui"
}

$args = @("--listen", "127.0.0.1:31337", "--http-listen", "127.0.0.1:31338", "--backend-dir", $bin)
$coreProcess = Start-Process -FilePath $core -ArgumentList $args -PassThru
try {
    Start-Process -FilePath $gui.FullName -Wait
} finally {
    Stop-Process -Id $coreProcess.Id -Force -ErrorAction SilentlyContinue
}
'@ | Set-Content (Join-Path $stage "start-hywdbg.ps1") -Encoding UTF8
}

Copy-IfExists (Join-Path $root "README.md") $stage | Out-Null
Copy-IfExists (Join-Path $uiDir "README.md") (Join-Path $stage "README-tauri.md") | Out-Null

if (-not $NoZip) {
    Invoke-Step "Creating zip package" {
        New-Item -ItemType Directory -Force $PublishDir | Out-Null
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -Force
        Write-Host "[HYWDbg] Zip: $zipPath" -ForegroundColor Green
    }
}

if ($GitHubRelease) {
    Require-Command gh
    $tag = "v$Version"
    $ghArgs = @("release", "create", $tag, $zipPath, "--title", "HYWDbg $Version", "--notes", "HYWDbg $Version release package")
    if ($Draft) {
        $ghArgs += "--draft"
    }
    Invoke-Step "Publishing GitHub release $tag" {
        & gh @ghArgs
        if ($LASTEXITCODE -ne 0) { throw "gh release create failed with exit code $LASTEXITCODE" }
    }
}

Write-Host "[HYWDbg] Publish directory: $stage" -ForegroundColor Green
