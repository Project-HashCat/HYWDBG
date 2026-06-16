# HYWDbg x64dbg-like Slint UI patch

This patch makes the Slint frontend look closer to a real debugger:

- x64dbg/IDA-like dark palette
- compact menu/toolbar/status bar
- real column layout for disassembly: address / bytes / mnemonic / operands / comment
- shorter command placeholder
- better process/module/thread/register panels
- WinAPI backend now uses iced-x86 to decode x64 instructions instead of dumping raw `db` bytes

Apply to both source and build mirrors:

```powershell
Expand-Archive .\HYWDbg_x64dbg_like_slint_patch.zip -DestinationPath L:\ProjectHashCat\HYWDbg -Force
Expand-Archive .\HYWDbg_x64dbg_like_slint_patch.zip -DestinationPath C:\HYWDbg -Force
```

Then build/run:

```powershell
cd C:\HYWDbg
.\start-slint.ps1 b
.\start-slint.ps1
```

If Cargo says `iced-x86` is missing, make sure the root `Cargo.toml` has the workspace dependency from this patch.
