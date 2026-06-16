# HYWDbg build-dist.ps1

Copies the Qt GUI, Rust core daemon, all backend executables, Qt runtime DLLs/plugins, and runner scripts into `dist/HYWDbg-<Config>-x64`. It also creates a zip unless `-NoZip` is passed.

Usage:

```powershell
cd C:\HYWDbg
set QT_ROOT=C:\Qt\6.11.1\msvc2022_64
powershell -ExecutionPolicy Bypass -File .\build-dist.ps1 -Config Debug -Clean
```

Release build:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-dist.ps1 -Config Release -Clean
```

Output:

```text
dist\HYWDbg-Debug-x64\
dist\HYWDbg-Debug-x64.zip
```
