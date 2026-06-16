# HYWDbg dist script fix

This patch replaces `build-dist.ps1`.

Fixes:
- Debug builds verify `platforms/qwindowsd.dll`, not `qwindows.dll`.
- Release builds verify `platforms/qwindows.dll`.
- Copies Qt GUI, Rust core daemon, and all backend EXEs into `dist/HYWDbg-<Config>-x64`.
- Runs `windeployqt` on `HYWDbg.exe`.
- Writes `run-hywdbg.bat` and `run-hywdbg.ps1`.
