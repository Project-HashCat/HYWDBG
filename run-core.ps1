$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $root "target\debug"
cargo run -p hywdbg-core-daemon -- --listen 127.0.0.1:31337 --http-listen 127.0.0.1:31338 --backend-dir $backendDir
