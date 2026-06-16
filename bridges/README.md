# Bridge plugins

Future bridge layout:

```text
bridges/x64dbg/hywdbg_bridge.dp64 -> TCP 127.0.0.1:31337
bridges/ida/hywdbg_ida.py         -> TCP 127.0.0.1:31337
bridges/binaryninja/plugin.py     -> TCP 127.0.0.1:31337
```

These bridge plugins must never attach to the target if HYWDbg Core already owns a backend.
They are frontends only.
