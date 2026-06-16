# HYWDbg Qt x64dbg-like UI patch

This adds `apps/hywdbg-qt`, a native Qt Widgets frontend that talks to the existing HYWDbg core over HTTP JSON-RPC.

It is intentionally closer to x64dbg than the Slint mock:

- QMainWindow + QDockWidget layout
- movable/floating docks
- QTableWidget disassembly/register/module/thread views
- scrollbars, row selection, context-menu-ready tables
- QPlainTextEdit dump/stack/log panes
- native QFileDialog for Open EXE
- x64dbg-like dark theme and colored mnemonics

## Build

Install Qt 6 for MSVC 64-bit, then set:

```powershell
$env:QT_ROOT="C:\Qt\6.8.0\msvc2022_64"
```

Run:

```powershell
cd C:\HYWDbg
.\start-qt.ps1 b
.\start-qt.ps1
```

If CMake cannot find Qt, pass `-QtPrefix` explicitly:

```powershell
.\start-qt.ps1 -QtPrefix C:\Qt\6.8.0\msvc2022_64
```
