use hywdbg_backend_common::{param_str, param_u64, run_stdio_backend, BackendHandler};
use hywdbg_protocol::{
    hex_u64, BackendCapabilities, BreakpointRecord, DisasmLine, MemoryBlock, ModuleInfo,
    ProcessListEntry, RegDump, RpcResponse, StackFrame, ThreadInfo, WatchpointInfo,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

const BACKEND_KIND: &str = "dbgeng";
const BACKEND_NAME: &str = "HYWDbg DbgEng Backend";

// x64 WinDbg-style mock disassembly (realistic Windows kernel/user-mode stubs)
const MOCK_X64_INSNS: &[(&str, &str)] = &[
    ("48 89 54 24 10",       "mov     qword ptr [rsp+10h], rdx"),
    ("48 89 4c 24 08",       "mov     qword ptr [rsp+08h], rcx"),
    ("48 83 ec 38",          "sub     rsp, 38h"),
    ("48 8b 44 24 40",       "mov     rax, qword ptr [rsp+40h]"),
    ("48 85 c0",             "test    rax, rax"),
    ("74 0a",                "je      +0Ah"),
    ("48 8b c8",             "mov     rcx, rax"),
    ("ff 15 00 00 00 00",    "call    qword ptr [rip+0]"),
    ("48 83 c4 38",          "add     rsp, 38h"),
    ("c3",                   "ret"),
    ("cc",                   "int     3"),
    ("90",                   "nop"),
    ("48 8d 15 00 00 00 00", "lea     rdx, [rip+0]"),
    ("48 8b 05 00 00 00 00", "mov     rax, qword ptr [rip+0]"),
    ("ff d0",                "call    rax"),
    ("33 c0",                "xor     eax, eax"),
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
    bp_next: u64,
    breakpoints: HashMap<u64, Breakpoint>,
    wp_next: u64,
    watchpoints: Vec<Watchpoint>,
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
                "note": "DbgEng (dbgeng.dll) backend adapter; IDebugClient/IDebugControl wired here"
            })),

            "capabilities" => RpcResponse::ok(0, BackendCapabilities {
                name: BACKEND_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                backend_kind: BACKEND_KIND.to_string(),
                supported_arches: vec![
                    "x64".to_string(), "x86".to_string(),
                    "arm64".to_string(), "arm".to_string(),
                ],
                features: vec![
                    "launch".to_string(), "attach".to_string(),
                    "kernel-debug".to_string(), "minidump".to_string(),
                    "windbg-command".to_string(), "symbols".to_string(),
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
                let args = params.as_ref()
                    .and_then(|p| p.get("args"))
                    .cloned()
                    .unwrap_or(Value::Null);
                RpcResponse::ok(0, json!({
                    "launched": true, "path": path, "args": args,
                    "backend": BACKEND_KIND, "pid": 5544_u64
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
                self.pc = self.pc.wrapping_add(5);
                RpcResponse::ok(0, json!({ "running": true }))
            }

            "pause" => RpcResponse::ok(0, json!({
                "stopped": true, "reason": "pause", "pc": hex_u64(self.pc)
            })),

            "stepInto" => {
                self.pc = self.pc.wrapping_add(1);
                RpcResponse::ok(0, json!({ "stopped": true, "reason": "stepInto", "pc": hex_u64(self.pc) }))
            }

            "stepOver" => {
                self.pc = self.pc.wrapping_add(5);
                RpcResponse::ok(0, json!({ "stopped": true, "reason": "stepOver", "pc": hex_u64(self.pc) }))
            }

            "stepOut" => {
                self.pc = self.pc.wrapping_add(0x40);
                RpcResponse::ok(0, json!({ "stopped": true, "reason": "stepOut", "pc": hex_u64(self.pc) }))
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
                // x64 code-like pattern (NOP sled)
                let hex = (0..size)
                    .map(|i| format!("{:02x}", if i % 4 == 0 { 0x90u8 } else { (addr as u8).wrapping_add(i as u8) }))
                    .collect::<String>();
                RpcResponse::ok(0, MemoryBlock { addr: hex_u64(addr), size, hex })
            }

            "writeMem" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "writeMem requires {addr, hex}"),
                };
                let hex = param_str(&params, "hex").unwrap_or_default();
                RpcResponse::ok(0, json!({ "written": hex.len() / 2, "addr": hex_u64(addr) }))
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
                RpcResponse::ok(0, self.disassemble(addr, count))
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
                        name: Some("worker".to_string()),
                        pc: Some(hex_u64(0x0000000140005678)),
                        active: false,
                    },
                    ThreadInfo {
                        id: "3".to_string(),
                        name: Some("RPC server".to_string()),
                        pc: Some(hex_u64(0x00007FF9A007C6B0)),
                        active: false,
                    },
                ];
                RpcResponse::ok(0, threads)
            }

            "modules" => {
                let path = self.launched_path.clone();
                let exe_name = path.as_deref().unwrap_or("target.exe");
                let modules = vec![
                    ModuleInfo {
                        name: exe_name.to_string(),
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
                    ModuleInfo {
                        name: "kernelbase.dll".to_string(),
                        base: hex_u64(0x00007FF8A0000000),
                        size: 0x2A0000,
                        path: Some(r"C:\Windows\System32\KernelBase.dll".to_string()),
                    },
                ];
                RpcResponse::ok(0, modules)
            }

            "callstack" => {
                let frames = vec![
                    StackFrame {
                        addr: hex_u64(self.pc),
                        symbol: Some("target!WinMain".to_string()),
                        module: Some("target.exe".to_string()),
                        source: Some("src\\main.cpp:42".to_string()),
                    },
                    StackFrame {
                        addr: hex_u64(0x0000000140003210),
                        symbol: Some("target!init_subsystems".to_string()),
                        module: Some("target.exe".to_string()),
                        source: Some("src\\init.cpp:17".to_string()),
                    },
                    StackFrame {
                        addr: hex_u64(0x00007FF8B001A530),
                        symbol: Some("kernel32!BaseThreadInitThunk".to_string()),
                        module: Some("kernel32.dll".to_string()),
                        source: None,
                    },
                    StackFrame {
                        addr: hex_u64(0x00007FF9A007C6B1),
                        symbol: Some("ntdll!RtlUserThreadStart".to_string()),
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
                RpcResponse::ok(0, json!({ "cleared": self.watchpoints.len() < before, "id": id }))
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
                    ProcessListEntry { pid: 4,    name: "System".to_string(),       arch: "x64".to_string(), description: Some("Windows NT kernel".to_string()) },
                    ProcessListEntry { pid: 888,  name: "svchost.exe".to_string(),  arch: "x64".to_string(), description: Some("Service Host: RPCSS".to_string()) },
                    ProcessListEntry { pid: 1200, name: "explorer.exe".to_string(), arch: "x64".to_string(), description: Some("Windows Explorer".to_string()) },
                    ProcessListEntry { pid: 2048, name: "target.exe".to_string(),   arch: "x64".to_string(), description: Some("Debug target".to_string()) },
                    ProcessListEntry { pid: 3120, name: "notepad.exe".to_string(),  arch: "x64".to_string(), description: None },
                    ProcessListEntry { pid: 4440, name: "chrome.exe".to_string(),   arch: "x64".to_string(), description: Some("Google Chrome".to_string()) },
                    ProcessListEntry { pid: 5200, name: "windbg.exe".to_string(),   arch: "x64".to_string(), description: Some("WinDbg debugger".to_string()) },
                    ProcessListEntry { pid: 6000, name: "csrss.exe".to_string(),    arch: "x64".to_string(), description: Some("Client/Server Runtime".to_string()) },
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
        // Full x64 register file matching WinDbg output style
        r.insert("rax".to_string(),    hex_u64(0x0000000000000000));
        r.insert("rbx".to_string(),    hex_u64(0x000000000012F8A0));
        r.insert("rcx".to_string(),    hex_u64(0x0000000140001234));
        r.insert("rdx".to_string(),    hex_u64(0x0000000000000001));
        r.insert("rsi".to_string(),    hex_u64(0x000000000000000A));
        r.insert("rdi".to_string(),    hex_u64(0x000000000000000B));
        r.insert("rsp".to_string(),    hex_u64(self.sp));
        r.insert("rbp".to_string(),    hex_u64(self.sp.wrapping_add(0x40)));
        r.insert("rip".to_string(),    hex_u64(self.pc));
        r.insert("r8".to_string(),     hex_u64(0x0000000000000008));
        r.insert("r9".to_string(),     hex_u64(0x0000000000000009));
        r.insert("r10".to_string(),    hex_u64(0x000000000000000A));
        r.insert("r11".to_string(),    hex_u64(0x000000000000000B));
        r.insert("r12".to_string(),    hex_u64(0x000000000000000C));
        r.insert("r13".to_string(),    hex_u64(0x000000000000000D));
        r.insert("r14".to_string(),    hex_u64(0x000000000000000E));
        r.insert("r15".to_string(),    hex_u64(0x000000000000000F));
        r.insert("eflags".to_string(), hex_u64(0x0000000000000246)); // ZF|PF|IF|bit1
        r.insert("cs".to_string(),     hex_u64(0x0033));
        r.insert("ds".to_string(),     hex_u64(0x002B));
        r.insert("es".to_string(),     hex_u64(0x002B));
        r.insert("fs".to_string(),     hex_u64(0x0053));
        r.insert("gs".to_string(),     hex_u64(0x002B));
        r.insert("ss".to_string(),     hex_u64(0x002B));
        RegDump { arch: "x64".to_string(), registers: r }
    }

    fn disassemble(&self, start_addr: u64, count: usize) -> Vec<DisasmLine> {
        let align_anchor = 0x0000000140001234_u64;
        let cycle_len = 58usize;
        let rel_addr = if start_addr >= align_anchor {
            ((start_addr - align_anchor) % cycle_len as u64) as usize
        } else {
            let diff = align_anchor - start_addr;
            let rem = (diff % cycle_len as u64) as usize;
            if rem == 0 { 0 } else { cycle_len - rem }
        };
        let offset_in_block = find_instr_offset(rel_addr);
        let mut addr = start_addr.wrapping_sub((rel_addr - offset_in_block) as u64);

        let offsets = [
            0, 5, 10, 14, 19, 22, 24, 27, 33, 37, 38, 39, 40, 47, 54, 56
        ];
        let mut idx = offsets.iter().position(|&x| x == offset_in_block).unwrap_or(0);

        let mut lines = Vec::new();
        for _ in 0..count {
            let entry = &MOCK_X64_INSNS[idx % MOCK_X64_INSNS.len()];
            let byte_count = entry.0.split_whitespace().count() as u64;
            lines.push(DisasmLine {
                addr: hex_u64(addr),
                bytes: entry.0.replace(' ', ""),
                text: entry.1.to_string(),
            });
            addr = addr.wrapping_add(byte_count.max(1));
            idx += 1;
        }
        lines
    }

}

fn find_instr_offset(rel_addr: usize) -> usize {
    let offsets = [
        0, 5, 10, 14, 19, 22, 24, 27, 33, 37, 38, 39, 40, 47, 54, 56
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
