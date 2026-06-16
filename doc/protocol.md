# HYWDbg Protocol

HYWDbg uses newline-delimited JSON.

## Frontend -> Core

```json
{"id":1,"method":"core.hello","params":null}
{"id":2,"method":"core.startBackend","params":{"kind":"titan"}}
{"id":3,"method":"dbg.regs","params":null}
{"id":4,"method":"dbg.attach","params":{"pid":1234}}
```

Core replies:

```json
{"id":1,"ok":true,"result":{"name":"hywdbg-core","version":"0.1.0"}}
{"id":3,"ok":true,"result":{"arch":"x64","registers":{"rip":"0x0000000000001000"}}}
```

Core emits async events:

```json
{"event":"backend.started","data":{"kind":"titan"}}
{"event":"target.stopped","data":{"reason":"breakpoint","pc":"0x140001000"}}
```

## Core -> Backend

Backends use the same request/response frame, but method names do not need the `dbg.` prefix.

```json
{"id":1,"method":"hello","params":null}
{"id":2,"method":"regs","params":null}
{"id":3,"method":"go","params":null}
```

## Core methods

- `core.hello`
- `core.startBackend { kind, path? }`
- `core.stopBackend`
- `core.backendStatus`

## Debug methods

- `dbg.capabilities`
- `dbg.launch { path, args?, cwd? }`
- `dbg.attach { pid }`
- `dbg.detach`
- `dbg.kill`
- `dbg.go`
- `dbg.pause`
- `dbg.stepInto`
- `dbg.stepOver`
- `dbg.stepOut`
- `dbg.regs`
- `dbg.setReg { name, value }`
- `dbg.readMem { addr, size }`
- `dbg.writeMem { addr, hex }`
- `dbg.disasm { addr, count }`
- `dbg.bpSet { addr, kind?, condition? }`
- `dbg.bpClear { id }`
- `dbg.threads`
- `dbg.modules`

## Address / integer representation

For frontend friendliness, addresses are strings such as:

```json
"0x00007ff612341000"
```

Backends may also accept decimal strings.
