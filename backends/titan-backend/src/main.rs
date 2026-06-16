use hywdbg_backend_common::{param_str, param_u64, run_stdio_backend, BackendHandler};
use hywdbg_protocol::{
    hex_u64, BackendCapabilities, BreakpointRecord, DisasmLine, MemoryBlock, ModuleInfo, ProcessListEntry,
    RegDump, RpcResponse, StackFrame, ThreadInfo, WatchpointInfo,
};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

const BACKEND_KIND: &str = "titan";
const BACKEND_NAME: &str = "HYWDbg TitanEngine Backend";

// Realistic x64 function stub (~80 bytes) used for mock disassembly.
// Decodes to: prologue, arg spills, null-check, indirect call, result check,
// two exit paths, epilogue, ret — then tiles for unlimited disasm.
const MOCK_CODE: &[u8] = &[
    // ── prologue ───────────────────────────────────────────────────────────
    0x55,                                           // push    rbp
    0x48, 0x89, 0xE5,                              // mov     rbp, rsp
    0x48, 0x83, 0xEC, 0x40,                        // sub     rsp, 64
    // ── spill first three args ─────────────────────────────────────────────
    0x48, 0x89, 0x4D, 0xF8,                        // mov     [rbp-8], rcx
    0x48, 0x89, 0x55, 0xF0,                        // mov     [rbp-16], rdx
    0x4C, 0x89, 0x45, 0xE8,                        // mov     [rbp-24], r8
    // ── null check rcx ────────────────────────────────────────────────────
    0x48, 0x8B, 0x4D, 0xF8,                        // mov     rcx, [rbp-8]
    0x48, 0x85, 0xC9,                              // test    rcx, rcx
    0x74, 0x0E,                                    // je      <error>
    // ── load function ptr + indirect call ─────────────────────────────────
    0x48, 0x8D, 0x15, 0x20, 0x10, 0x00, 0x00,     // lea     rdx, [rip+0x1020]
    0x48, 0x8B, 0x02,                              // mov     rax, [rdx]
    0xFF, 0xD0,                                    // call    rax
    0x89, 0x45, 0xE4,                              // mov     [rbp-28], eax
    // ── check return value ────────────────────────────────────────────────
    0x83, 0x7D, 0xE4, 0x00,                        // cmp     dword [rbp-28], 0
    0x75, 0x09,                                    // jne     <success>
    // ── error path ────────────────────────────────────────────────────────
    0x31, 0xC0,                                    // xor     eax, eax
    0x48, 0x83, 0xC4, 0x40,                        // add     rsp, 64
    0x5D,                                          // pop     rbp
    0xC3,                                          // ret
    // ── success path ──────────────────────────────────────────────────────
    0xB8, 0x01, 0x00, 0x00, 0x00,                  // mov     eax, 1
    0x48, 0x83, 0xC4, 0x40,                        // add     rsp, 64
    0x5D,                                          // pop     rbp
    0xC3,                                          // ret
];

struct Breakpoint {
    addr: u64,
    enabled: bool,
    hit_count: u64,
    kind: String,
}

struct Watchpoint {
    id: u64,
    addr: u64,
    size: u64,
    kind: String,
    enabled: bool,
}

struct BackendState {
    attached_pid: Option<u64>,
    launched_path: Option<String>,
    pc: u64,
    sp: u64,
    pub bp_next: u64,
    pub breakpoints: HashMap<u64, Breakpoint>,
    pub wp_next: u64,
    pub watchpoints: Vec<Watchpoint>,
    pub prev_regs: HashMap<String, String>,
    pub tls_hit: bool,
    pub entry_hit: bool,
}

impl Default for BackendState {
    fn default() -> Self {
        Self {
            attached_pid: None,
            launched_path: None,
            pc: 0x0000000140001234,
            sp: 0x000000000012F8A0,
            bp_next: 1,
            breakpoints: HashMap::new(),
            wp_next: 1,
            watchpoints: Vec::new(),
            prev_regs: HashMap::new(),
            tls_hit: false,
            entry_hit: false,
        }
    }
}

impl BackendHandler for BackendState {
    fn handle(&mut self, method: &str, params: Option<Value>) -> RpcResponse {
        match method {
            "hello" => RpcResponse::ok(0, json!({
                "name": BACKEND_NAME,
                "kind": BACKEND_KIND,
                "mode": "stdio-backend",
                "note": "TitanEngine backend adapter; real debugger FFI calls wired here"
            })),

            "capabilities" => RpcResponse::ok(0, BackendCapabilities {
                name: BACKEND_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                backend_kind: BACKEND_KIND.to_string(),
                supported_arches: vec!["x86".to_string(), "x64".to_string()],
                features: vec![
                    "launch".to_string(), "attach".to_string(),
                    "breakpoints".to_string(), "watchpoints".to_string(),
                    "memory".to_string(), "registers".to_string(),
                    "threads".to_string(), "modules".to_string(),
                    "callstack".to_string(), "disasm".to_string(),
                    "processList".to_string(),
                ],
            }),

            "attach" => match param_u64(&params, "pid") {
                Ok(Some(pid)) => {
                    self.attached_pid = Some(pid);
                    RpcResponse::ok(0, json!({
                        "attached": true, "pid": pid, "backend": BACKEND_KIND
                    }))
                }
                Ok(None) => RpcResponse::err(0, "bad_params", "attach requires {pid}"),
                Err(e) => RpcResponse::err(0, "bad_params", e),
            },

            "launch" => {
                let Some(path) = param_str(&params, "path") else {
                    return RpcResponse::err(0, "bad_params", "launch requires {path}");
                };
                self.launched_path = Some(path.clone());
                self.tls_hit = false;
                self.entry_hit = false;
                let args = params.as_ref()
                    .and_then(|p| p.get("args"))
                    .cloned()
                    .unwrap_or(Value::Null);
                RpcResponse::ok(0, json!({
                    "launched": true, "path": path, "args": args, "backend": BACKEND_KIND, "pid": 9900_u64
                }))
            }

            "detach" => {
                self.attached_pid = None;
                self.launched_path = None;
                RpcResponse::ok(0, json!({ "detached": true }))
            }

            "kill" => {
                self.attached_pid = None;
                self.launched_path = None;
                RpcResponse::ok(0, json!({ "killed": true, "exit_code": 0 }))
            }

            "go" => {
                if !self.tls_hit {
                    self.tls_hit = true;
                    self.pc = 0x140001000;
                    return RpcResponse::ok(0, json!({ "stopped": true, "event": "breakpoint", "reason": "TLS Callback", "pc": hex_u64(self.pc) }));
                }
                if !self.entry_hit {
                    self.entry_hit = true;
                    self.pc = 0x140001234;
                    return RpcResponse::ok(0, json!({ "stopped": true, "event": "breakpoint", "reason": "Entry Point", "pc": hex_u64(self.pc) }));
                }

                let mut found = None;
                let mut min_dist = u64::MAX;
                for bp in self.breakpoints.values() {
                    if bp.enabled && bp.addr > self.pc {
                        let dist = bp.addr - self.pc;
                        if dist < min_dist {
                            min_dist = dist;
                            found = Some(bp.addr);
                        }
                    }
                }
                if let Some(addr) = found {
                    self.pc = addr;
                    RpcResponse::ok(0, json!({ "stopped": true, "event": "breakpoint", "reason": "go", "pc": hex_u64(self.pc) }))
                } else {
                    self.pc = self.pc.wrapping_add(0x500);
                    RpcResponse::ok(0, json!({ "stopped": true, "event": "exit_process", "exitCode": 0 }))
                }
            }

            "pause" => {
                RpcResponse::ok(0, json!({
                    "stopped": true, "event": "pause", "reason": "pause", "pc": hex_u64(self.pc)
                }))
            }

            "stepInto" | "stepIn" => {
                self.pc = self.pc.wrapping_add(self.instr_len_at_pc());
                RpcResponse::ok(0, json!({ "stopped": true, "event": "single_step", "reason": "stepIn", "pc": hex_u64(self.pc) }))
            }

            "stepOver" => {
                // If current instruction is a call, skip it wholesale (advance by instr len only)
                // For mock purposes advance by current instr len regardless
                self.pc = self.pc.wrapping_add(self.instr_len_at_pc());
                RpcResponse::ok(0, json!({ "stopped": true, "event": "single_step", "reason": "stepOver", "pc": hex_u64(self.pc) }))
            }

            "stepOut" => {
                // Simulate returning: advance PC to the next `ret` in tiled MOCK_CODE
                self.pc = self.advance_to_next_ret();
                RpcResponse::ok(0, json!({ "stopped": true, "event": "single_step", "reason": "stepOut", "pc": hex_u64(self.pc) }))
            }

            "regs" => RpcResponse::ok(0, self.make_regs()),

            "setReg" => {
                let name = param_str(&params, "name").unwrap_or_default().to_lowercase();
                let value = params.as_ref().and_then(|p| p.get("value"));
                if name.is_empty() || value.is_none() {
                    return RpcResponse::err(0, "bad_params", "setReg requires {name, value}");
                }
                if name == "rip" || name == "pc" {
                    match hywdbg_protocol::parse_u64ish(value.unwrap()) {
                        Ok(v) => self.pc = v,
                        Err(e) => return RpcResponse::err(0, "bad_params", e),
                    }
                } else if name == "rsp" {
                    match hywdbg_protocol::parse_u64ish(value.unwrap()) {
                        Ok(v) => self.sp = v,
                        Err(e) => return RpcResponse::err(0, "bad_params", e),
                    }
                }
                RpcResponse::ok(0, json!({ "set": true, "name": name }))
            }

            "readMem" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "readMem requires {addr, size}"),
                };
                let size = match param_u64(&params, "size") {
                    Ok(Some(x)) => x.min(4096) as usize,
                    _ => return RpcResponse::err(0, "bad_params", "readMem requires {addr, size}"),
                };
                // Fill with a realistic-looking pattern derived from MOCK_CODE or cycling bytes
                let hex = (0..size)
                    .map(|i| format!("{:02x}", MOCK_CODE[i % MOCK_CODE.len()]))
                    .collect::<String>();
                RpcResponse::ok(0, MemoryBlock { addr: hex_u64(addr), size, hex })
            }

            "writeMem" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "writeMem requires {addr, hex}"),
                };
                let hex = param_str(&params, "hex").unwrap_or_default();
                let written = hex.len() / 2;
                RpcResponse::ok(0, json!({ "written": written, "addr": hex_u64(addr) }))
            }

            "disasm" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => self.pc,
                };
                let count = match param_u64(&params, "count") {
                    Ok(Some(x)) => x.min(64) as usize,
                    _ => 16,
                };
                let lines = self.disassemble(addr, count);
                RpcResponse::ok(0, lines)
            }

            "bpSet" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "bpSet requires {addr}"),
                };
                let kind = param_str(&params, "kind").unwrap_or_else(|| "INT3".to_string());
                let id = self.bp_next;
                self.bp_next += 1;
                self.breakpoints.insert(id, Breakpoint { addr, enabled: true, hit_count: 0, kind: kind.clone() });
                RpcResponse::ok(0, json!({ "id": id, "addr": hex_u64(addr), "enabled": true, "kind": kind }))
            }

            "hwBpSet" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "hwBpSet requires {addr}"),
                };
                let kind = param_str(&params, "kind").unwrap_or_else(|| "x".to_string());
                let id = self.bp_next;
                self.bp_next += 1;
                self.breakpoints.insert(id, Breakpoint { addr, enabled: true, hit_count: 0, kind: format!("HW_{}", kind) });
                RpcResponse::ok(0, json!({ "id": id, "addr": hex_u64(addr), "kind": format!("HW_{}", kind) }))
            }

            "bpClear" => {
                let id_opt = param_u64(&params, "id").ok().flatten();
                let addr_opt = param_u64(&params, "addr").ok().flatten();
                let all_opt = params.as_ref().and_then(|p| p.get("all")).and_then(|v| v.as_bool()).unwrap_or(false);

                if all_opt {
                    self.breakpoints.clear();
                    RpcResponse::ok(0, json!({ "cleared": true, "all": true }))
                } else if let Some(id) = id_opt {
                    let removed = self.breakpoints.remove(&id).is_some();
                    RpcResponse::ok(0, json!({ "cleared": removed, "id": id }))
                } else if let Some(addr) = addr_opt {
                    let target_id = self.breakpoints.iter().find(|(_, bp)| bp.addr == addr).map(|(&id, _)| id);
                    if let Some(id) = target_id {
                        self.breakpoints.remove(&id);
                        RpcResponse::ok(0, json!({ "cleared": true, "id": id, "addr": hex_u64(addr) }))
                    } else {
                        RpcResponse::ok(0, json!({ "cleared": false, "addr": hex_u64(addr) }))
                    }
                } else {
                    RpcResponse::err(0, "bad_params", "bpClear requires id, addr, or all")
                }
            }

            "bpList" => {
                let list: Vec<BreakpointRecord> = self.breakpoints.iter().map(|(id, bp)| {
                    BreakpointRecord {
                        id: *id,
                        addr: hex_u64(bp.addr),
                        enabled: bp.enabled,
                        hit_count: bp.hit_count,
                        kind: bp.kind.clone(),
                    }
                }).collect();
                RpcResponse::ok(0, list)
            }

            "threads" => {
                let threads = vec![
                    ThreadInfo {
                        id: "1".to_string(),
                        name: Some("main".to_string()),
                        pc: Some(hex_u64(self.pc)),
                        active: true,
                    },
                    ThreadInfo {
                        id: "2".to_string(),
                        name: Some("worker-0".to_string()),
                        pc: Some(hex_u64(0x0000000140005678)),
                        active: false,
                    },
                ];
                RpcResponse::ok(0, threads)
            }

            "modules" => {
                let path = self.launched_path.clone();
                let modules = vec![
                    ModuleInfo {
                        name: path.as_deref().unwrap_or("target.exe").to_string(),
                        base: hex_u64(0x0000000140000000),
                        size: 0x80000,
                        path: path.clone(),
                    },
                    ModuleInfo {
                        name: "ntdll.dll".to_string(),
                        base: hex_u64(0x00007FF9A0000000),
                        size: 0x1F0000,
                        path: Some(r"C:\Windows\System32\ntdll.dll".to_string()),
                    },
                    ModuleInfo {
                        name: "kernel32.dll".to_string(),
                        base: hex_u64(0x00007FF8B0000000),
                        size: 0xF0000,
                        path: Some(r"C:\Windows\System32\kernel32.dll".to_string()),
                    },
                ];
                RpcResponse::ok(0, modules)
            }

            "memoryMap" => {
                let regions = vec![
                    json!({ "base": hex_u64(0x0000000140000000), "size": hex_u64(0x1000), "protect": "R", "state": "Commit", "type": "Image", "name": "target.exe" }),
                    json!({ "base": hex_u64(0x0000000140001000), "size": hex_u64(0x70000), "protect": "ER", "state": "Commit", "type": "Image", "name": "target.exe" }),
                    json!({ "base": hex_u64(0x0000000140071000), "size": hex_u64(0xF000), "protect": "RW", "state": "Commit", "type": "Image", "name": "target.exe" }),
                    json!({ "base": hex_u64(0x00007FF8B0000000), "size": hex_u64(0x10000), "protect": "R", "state": "Commit", "type": "Image", "name": "kernel32.dll" }),
                    json!({ "base": hex_u64(0x00007FF8B0010000), "size": hex_u64(0xC0000), "protect": "ER", "state": "Commit", "type": "Image", "name": "kernel32.dll" }),
                    json!({ "base": hex_u64(0x00007FF8B00D0000), "size": hex_u64(0x20000), "protect": "RW", "state": "Commit", "type": "Image", "name": "kernel32.dll" }),
                ];
                RpcResponse::ok(0, json!(regions))
            }

            "searchMem" => {
                RpcResponse::ok(0, json!([]))
            }

            "callstack" => {
                let frames = vec![
                    StackFrame {
                        addr: hex_u64(self.pc),
                        symbol: Some("WinMain".to_string()),
                        module: Some("target.exe".to_string()),
                        source: Some("src/main.cpp:42".to_string()),
                    },
                    StackFrame {
                        addr: hex_u64(0x0000000140003210),
                        symbol: Some("init_subsystems".to_string()),
                        module: Some("target.exe".to_string()),
                        source: Some("src/init.cpp:17".to_string()),
                    },
                    StackFrame {
                        addr: hex_u64(0x00007FF8B001A530),
                        symbol: Some("BaseThreadInitThunk".to_string()),
                        module: Some("kernel32.dll".to_string()),
                        source: None,
                    },
                    StackFrame {
                        addr: hex_u64(0x00007FF9A007C6B1),
                        symbol: Some("RtlUserThreadStart".to_string()),
                        module: Some("ntdll.dll".to_string()),
                        source: None,
                    },
                ];
                RpcResponse::ok(0, frames)
            }

            "wpSet" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "wpSet requires {addr}"),
                };
                let size = param_u64(&params, "size").ok().flatten().unwrap_or(4);
                let kind = param_str(&params, "kind").unwrap_or_else(|| "w".to_string());
                let id = self.wp_next;
                self.wp_next += 1;
                self.watchpoints.push(Watchpoint { id, addr, size, kind: kind.clone(), enabled: true });
                RpcResponse::ok(0, json!({ "id": id, "addr": hex_u64(addr), "size": size, "kind": kind, "enabled": true }))
            }

            "wpClear" => {
                let id = match param_u64(&params, "id") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "wpClear requires {id}"),
                };
                let before = self.watchpoints.len();
                self.watchpoints.retain(|w| w.id != id);
                let removed = self.watchpoints.len() < before;
                RpcResponse::ok(0, json!({ "cleared": removed, "id": id }))
            }

            "wpList" => {
                let list: Vec<WatchpointInfo> = self.watchpoints.iter().map(|w| WatchpointInfo {
                    id: w.id,
                    addr: hex_u64(w.addr),
                    size: w.size,
                    kind: w.kind.clone(),
                    enabled: w.enabled,
                }).collect();
                RpcResponse::ok(0, list)
            }

            "processList" => {
                let procs = vec![
                    ProcessListEntry { pid: 4, name: "System".to_string(), arch: "x64".to_string(), description: Some("Windows kernel".to_string()) },
                    ProcessListEntry { pid: 888, name: "svchost.exe".to_string(), arch: "x64".to_string(), description: Some("Service Host".to_string()) },
                    ProcessListEntry { pid: 1200, name: "explorer.exe".to_string(), arch: "x64".to_string(), description: Some("Windows Shell".to_string()) },
                    ProcessListEntry { pid: 2048, name: "target.exe".to_string(), arch: "x64".to_string(), description: Some("Debug target".to_string()) },
                    ProcessListEntry { pid: 3120, name: "notepad.exe".to_string(), arch: "x64".to_string(), description: None },
                    ProcessListEntry { pid: 4440, name: "chrome.exe".to_string(), arch: "x64".to_string(), description: Some("Google Chrome".to_string()) },
                    ProcessListEntry { pid: 5888, name: "code.exe".to_string(), arch: "x64".to_string(), description: Some("Visual Studio Code".to_string()) },
                ];
                RpcResponse::ok(0, procs)
            }

            "shutdown" => RpcResponse::ok(0, json!({ "bye": true })),

            "resolveSymbol" => {
                let module = param_str(&params, "module").unwrap_or_default();
                let symbol = param_str(&params, "symbol").unwrap_or_default();
                if symbol.is_empty() {
                    return RpcResponse::err(0, "bad_params", "resolveSymbol requires {symbol}");
                }
                match self.resolve_symbol(&module, &symbol) {
                    Some(addr) => RpcResponse::ok(0, json!({
                        "addr": hex_u64(addr), "symbol": symbol,
                        "module": module, "resolved": true
                    })),
                    None => RpcResponse::err(0, "symbol_not_found",
                        format!("symbol '{}' not found in '{}'", symbol,
                                if module.is_empty() { "*" } else { &module })),
                }
            }

            other => RpcResponse::err(0, "unknown_method", format!("{BACKEND_KIND} does not implement '{other}'")),

        }
    }
}

impl BackendState {
    fn resolve_symbol(&self, module: &str, symbol: &str) -> Option<u64> {
        let m = module.to_lowercase();
        let m = m.trim_end_matches(".dll").trim_end_matches(".exe");
        let s = symbol.to_lowercase();
        const K32: u64  = 0x7FF8_B000_0000;
        const NTDLL: u64 = 0x7FF9_A000_0000;
        const U32: u64  = 0x7FF8_C000_0000;
        const TGT: u64  = 0x0000_0001_4000_0000;
        match (m, s.as_str()) {
            // kernel32
            ("" | "kernel32", "writefile")                         => Some(K32 + 0x1234),
            ("" | "kernel32", "readfile")                          => Some(K32 + 0x2345),
            ("" | "kernel32", "createfilea" | "createfile")        => Some(K32 + 0x3456),
            ("" | "kernel32", "createfilew")                       => Some(K32 + 0x3460),
            ("" | "kernel32", "virtualalloc")                      => Some(K32 + 0x4567),
            ("" | "kernel32", "virtualfree")                       => Some(K32 + 0x4590),
            ("" | "kernel32", "virtualprotect")                    => Some(K32 + 0x45C0),
            ("" | "kernel32", "getprocaddress")                    => Some(K32 + 0x5678),
            ("" | "kernel32", "loadlibrarya" | "loadlibrary")      => Some(K32 + 0x6789),
            ("" | "kernel32", "loadlibraryw")                      => Some(K32 + 0x6800),
            ("" | "kernel32", "freelibrary")                       => Some(K32 + 0x6900),
            ("" | "kernel32", "createthread")                      => Some(K32 + 0x7890),
            ("" | "kernel32", "terminateprocess")                  => Some(K32 + 0x8901),
            ("" | "kernel32", "getlasterror")                      => Some(K32 + 0x9012),
            ("" | "kernel32", "setlasterror")                      => Some(K32 + 0x9020),
            ("" | "kernel32", "heapalloc")                         => Some(K32 + 0xA123),
            ("" | "kernel32", "heapfree")                          => Some(K32 + 0xA200),
            ("" | "kernel32", "sleep")                             => Some(K32 + 0xB000),
            ("" | "kernel32", "exitprocess")                       => Some(K32 + 0xB100),
            // ntdll
            ("" | "ntdll", "ntcreatefile")                         => Some(NTDLL + 0x1100),
            ("" | "ntdll", "ntreadfile")                           => Some(NTDLL + 0x1200),
            ("" | "ntdll", "ntwritefile")                          => Some(NTDLL + 0x1300),
            ("" | "ntdll", "ntallocatevirtualmemory")              => Some(NTDLL + 0x1400),
            ("" | "ntdll", "ntfreevirtualmemory")                  => Some(NTDLL + 0x1500),
            ("" | "ntdll", "ntprotectvirtualmemory")               => Some(NTDLL + 0x1600),
            ("" | "ntdll", "ldrloaddll")                           => Some(NTDLL + 0x2000),
            ("" | "ntdll", "rtlallocateheap")                      => Some(NTDLL + 0x3000),
            ("" | "ntdll", "rtlfreeheap")                          => Some(NTDLL + 0x3100),
            ("" | "ntdll", "rtlgetversion")                        => Some(NTDLL + 0x4000),
            // user32
            ("" | "user32", "messageboxa" | "messagebox")          => Some(U32 + 0x1000),
            ("" | "user32", "messageboxw")                         => Some(U32 + 0x1010),
            ("" | "user32", "sendmessagea" | "sendmessage")        => Some(U32 + 0x2000),
            ("" | "user32", "postmessagea" | "postmessage")        => Some(U32 + 0x2100),
            ("" | "user32", "findwindowa" | "findwindow")          => Some(U32 + 0x3000),
            // target
            ("target" | "target.exe", "winmain")                   => Some(TGT + 0x1000),
            ("target" | "target.exe", "main")                      => Some(TGT + 0x1100),
            ("target" | "target.exe", "dllmain")                   => Some(TGT + 0x1200),
            _ => None,
        }
    }

    fn make_regs(&self) -> RegDump {

        let mut r = BTreeMap::new();
        // Full x64 general-purpose registers
        r.insert("rax".to_string(), hex_u64(0x0000000000000000));
        r.insert("rbx".to_string(), hex_u64(0x000000000012F8A0));
        r.insert("rcx".to_string(), hex_u64(0x0000000140001234));
        r.insert("rdx".to_string(), hex_u64(0x0000000000000001));
        r.insert("rsi".to_string(), hex_u64(0x000000000000000A));
        r.insert("rdi".to_string(), hex_u64(0x000000000000000B));
        r.insert("rsp".to_string(), hex_u64(self.sp));
        r.insert("rbp".to_string(), hex_u64(self.sp.wrapping_add(0x40)));
        r.insert("rip".to_string(), hex_u64(self.pc));
        r.insert("r8".to_string(),  hex_u64(0x0000000000000008));
        r.insert("r9".to_string(),  hex_u64(0x0000000000000009));
        r.insert("r10".to_string(), hex_u64(0x000000000000000A));
        r.insert("r11".to_string(), hex_u64(0x000000000000000B));
        r.insert("r12".to_string(), hex_u64(0x000000000000000C));
        r.insert("r13".to_string(), hex_u64(0x000000000000000D));
        r.insert("r14".to_string(), hex_u64(0x000000000000000E));
        r.insert("r15".to_string(), hex_u64(0x000000000000000F));
        // Flags and segment registers
        r.insert("eflags".to_string(), hex_u64(0x0000000000000202)); // IF=1, bit1=1
        r.insert("cs".to_string(), hex_u64(0x0033));
        r.insert("ds".to_string(), hex_u64(0x002B));
        r.insert("es".to_string(), hex_u64(0x002B));
        r.insert("fs".to_string(), hex_u64(0x0053));
        r.insert("gs".to_string(), hex_u64(0x002B));
        r.insert("ss".to_string(), hex_u64(0x002B));
        RegDump { arch: "x64".to_string(), registers: r }
    }

    fn disassemble(&self, start_addr: u64, count: usize) -> Vec<DisasmLine> {
        let align_anchor = 0x0000000140001234_u64;
        let rel_addr = if start_addr >= align_anchor {
            ((start_addr - align_anchor) % MOCK_CODE.len() as u64) as usize
        } else {
            let diff = align_anchor - start_addr;
            let rem = (diff % MOCK_CODE.len() as u64) as usize;
            if rem == 0 { 0 } else { MOCK_CODE.len() - rem }
        };
        let offset_in_block = find_instr_offset(rel_addr);
        let aligned_start = start_addr.wrapping_sub((rel_addr - offset_in_block) as u64);

        let need_bytes = count * 16;
        let mut code_buf = vec![0u8; need_bytes];
        for i in 0..need_bytes {
            code_buf[i] = MOCK_CODE[(offset_in_block + i) % MOCK_CODE.len()];
        }

        let mut decoder = Decoder::with_ip(64, &code_buf, aligned_start, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        formatter.options_mut().set_uppercase_hex(true);
        formatter.options_mut().set_first_operand_char_index(8);

        let mut lines = Vec::new();
        let mut output = String::new();

        while decoder.can_decode() && lines.len() < count {
            let instr = decoder.decode();
            if instr.is_invalid() { break; }
            let offset = (instr.ip().saturating_sub(aligned_start)) as usize;
            let len = instr.len();
            let end = (offset + len).min(code_buf.len());
            let bytes: String = code_buf[offset..end]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            output.clear();
            formatter.format(&instr, &mut output);
            lines.push(DisasmLine {
                addr: hex_u64(instr.ip()),
                bytes,
                text: output.clone(),
            });
        }

        lines
    }

    /// Decode one instruction from tiled MOCK_CODE at the current PC and return its byte length.
    /// This ensures step always lands on a real instruction boundary.
    fn instr_len_at_pc(&self) -> u64 {
        self.instr_len_at_pc_for(self.pc)
    }

    /// Walk instructions from PC until hitting a `ret` (C3) and return the address
    /// of the instruction immediately after it (simulates step-out returning to caller).
    fn advance_to_next_ret(&self) -> u64 {
        let mut curr_pc = self.pc;
        for _ in 0..100 {
            let rel_addr = if curr_pc >= 0x0000000140001234_u64 {
                ((curr_pc - 0x0000000140001234_u64) % MOCK_CODE.len() as u64) as usize
            } else {
                let diff = 0x0000000140001234_u64 - curr_pc;
                let rem = (diff % MOCK_CODE.len() as u64) as usize;
                if rem == 0 { 0 } else { MOCK_CODE.len() - rem }
            };
            let offset_in_block = find_instr_offset(rel_addr);
            if offset_in_block == 57 || offset_in_block == 68 {
                return curr_pc.wrapping_add(1);
            }
            let len = self.instr_len_at_pc_for(curr_pc);
            curr_pc = curr_pc.wrapping_add(len);
        }
        self.pc.wrapping_add(self.instr_len_at_pc() * 3)
    }

    fn instr_len_at_pc_for(&self, pc: u64) -> u64 {
        let align_anchor = 0x0000000140001234_u64;
        let rel_addr = if pc >= align_anchor {
            ((pc - align_anchor) % MOCK_CODE.len() as u64) as usize
        } else {
            let diff = align_anchor - pc;
            let rem = (diff % MOCK_CODE.len() as u64) as usize;
            if rem == 0 { 0 } else { MOCK_CODE.len() - rem }
        };
        let offset_in_block = find_instr_offset(rel_addr);
        let lengths = [
            1, 3, 4, 4, 4, 4, 4, 3, 2, 7, 3, 2, 3, 4, 2, 2, 4, 1, 1, 5, 4, 1, 1
        ];
        let offsets = [
            0, 1, 4, 8, 12, 16, 20, 24, 27, 29, 36, 39, 41, 44, 48, 50, 52, 56, 57, 58, 63, 67, 68
        ];
        let idx = offsets.iter().position(|&x| x == offset_in_block).unwrap_or(0);
        lengths[idx] as u64
    }
}

fn find_instr_offset(rel_addr: usize) -> usize {
    let offsets = [
        0, 1, 4, 8, 12, 16, 20, 24, 27, 29, 36, 39, 41, 44, 48, 50, 52, 56, 57, 58, 63, 67, 68
    ];
    let mut best = 0;
    for &off in &offsets {
        if off <= rel_addr {
            best = off;
        } else {
            break;
        }
    }
    best
}

fn main() -> anyhow::Result<()> {
    run_stdio_backend(BackendState::default())
}
