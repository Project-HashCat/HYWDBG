# Roadmap

## Phase 0: spine

- [x] Rust workspace
- [x] HYWDbg protocol crate
- [x] Core daemon TCP server
- [x] One active backend rule
- [x] Stdio backend protocol
- [x] Tauri shell

## Phase 1: Windows x86/x64 TitanEngine backend

- [ ] Add TitanEngine import library / dynamic loader
- [ ] Launch / attach target
- [ ] Debug event loop
- [ ] Read/write memory
- [ ] Registers x86/x64
- [ ] Software breakpoints
- [ ] Thread/module list
- [ ] Basic disasm via Capstone in core or frontend

## Phase 2: DbgEng backend

- [ ] DebugCreate host
- [ ] Attach/launch
- [ ] DbgEng event callbacks
- [ ] WinDbg command passthrough
- [ ] ARM64 registers
- [ ] DbgEng memory/symbol APIs

## Phase 3: LLDB + GDB remote

- [ ] LLDB command driver or liblldb bridge
- [ ] GDB remote packet codec
- [ ] qSupported / registers / memory / continue / step
- [ ] macOS debugserver support

## Phase 4: Frida backend

- [ ] frida-core bridge process
- [ ] attach/spawn
- [ ] script injection
- [ ] JS hook event -> HYWDbg event mapping

## Phase 5: reverse UI features

- [ ] CPU view
- [ ] hex view
- [ ] register editor
- [ ] breakpoints manager
- [ ] trace DB
- [ ] script API
- [ ] x64dbg/IDA bridge plugins
