$ErrorActionPreference = "Stop"
cargo build --workspace
Write-Host "Built core + backend shells. Binaries are under target/debug or target/release." -ForegroundColor Green
