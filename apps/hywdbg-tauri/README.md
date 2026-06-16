# HYWDbg Tauri shell

This app is intentionally outside the root workspace. Run it separately:

```powershell
cd apps/hywdbg-tauri
npm install
npm run tauri dev
```

From the repository root, the shortcut is:

```powershell
.\start.ps1
```

Start the core daemon first:

```powershell
cd ../..
.\run-core.ps1
```

The Tauri side talks to `hywdbg-core-daemon` over TCP. If you open the Vite UI in a normal browser, it uses the daemon's local HTTP bridge at `http://127.0.0.1:31338/rpc` instead.
