use hywdbg_backend_common::{param_str, param_u64, run_stdio_backend, BackendHandler};
use hywdbg_protocol::{
    hex_u64, BackendCapabilities, BreakpointRecord, DisasmLine, MemoryBlock, ModuleInfo,
    ProcessListEntry, RegDump, RpcResponse, StackFrame, ThreadInfo, WatchpointInfo,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

const BACKEND_KIND: &str = "gdbremote";
const BACKEND_NAME: &str = "HYWDbg GDB Remote Backend";

// Mock RISC-V 64-bit instructions (the default arch for GDB remote)
// GDB remote protocol often connects to embedded/RISC-V/MIPS targets
const MOCK_RISCV_INSNS: &[(&str, &str)] = &[
    ("13000000", "addi zero, zero, 0"),
    ("93080500", "addi a7, zero, 0x5"),    // li a7, 5
    ("13050000", "addi a0, zero, 0"),       // li a0, 0
    ("93052000", "addi a1, zero, 0x20"),    // li a1, 32
    ("73000000", "ecall"),
    ("6f000000", "jal zero, 0"),
    ("67800000", "jalr zero, ra, 0"),       // ret
    ("23200100", "sw ra, 0(sp)"),
    ("03200100", "lw ra, 0(sp)"),
    ("93f2f2ff", "andi t0, t0, -1"),
    ("33004000", "add zero, zero, zero"),
    ("13010100", "addi sp, sp, -16"),
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
    /// Target arch reported by the remote stub (arm64 / riscv64 / mips / x64)
    target_arch: String,
}

impl Default for BackendState {
    fn default() -> Self {
        Self {
            attached_pid: None,
            launched_path: None,
            pc: 0x0000000000010000,
            sp: 0x0000000080000000,
            bp_next: 1,
            breakpoints: HashMap::new(),
            wp_next: 1,
            watchpoints: Vec::new(),
            target_arch: "riscv64".to_string(),
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
                "note": "GDB Remote Serial Protocol adapter; connect via TCP host:port"
            })),

            "capabilities" => RpcResponse::ok(0, BackendCapabilities {
                name: BACKEND_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                backend_kind: BACKEND_KIND.to_string(),
                supported_arches: vec![
                    "x64".to_string(), "x86".to_string(),
                    "arm64".to_string(), "arm".to_string(),
                    "riscv64".to_string(), "mips".to_string(),
                    "mips64".to_string(), "powerpc".to_string(),
                ],
                features: vec![
                    "attach".to_string(), "launch".to_string(),
                    "remote".to_string(), "gdb-packets".to_string(),
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
                        "attached": true, "pid": pid, "backend": BACKEND_KIND,
                        "arch": self.target_arch
                    }))
                }
                Ok(None) => RpcResponse::err(0, "bad_params", "attach requires {pid}"),
                Err(e) => RpcResponse::err(0, "bad_params", e),
            },

            "launch" => {
                let Some(path) = param_str(&params, "path") else {
                    return RpcResponse::err(0, "bad_params", "launch requires {path}");
                };
                // Accept optional target_arch override from params
                if let Some(arch) = param_str(&params, "arch") {
                    self.target_arch = arch;
                }
                self.launched_path = Some(path.clone());
                RpcResponse::ok(0, json!({
                    "launched": true, "path": path, "backend": BACKEND_KIND,
                    "arch": self.target_arch
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
                self.pc = self.pc.wrapping_add(4);
                RpcResponse::ok(0, json!({ "running": true }))
            }

            "pause" => RpcResponse::ok(0, json!({
                "stopped": true, "reason": "signal", "signal": 2, "pc": hex_u64(self.pc)
            })),

            "stepInto" => {
                self.pc = self.pc.wrapping_add(4);
                RpcResponse::ok(0, json!({ "stopped": true, "reason": "stepInto", "pc": hex_u64(self.pc) }))
            }

            "stepOver" => {
                self.pc = self.pc.wrapping_add(4);
                RpcResponse::ok(0, json!({ "stopped": true, "reason": "stepOver", "pc": hex_u64(self.pc) }))
            }

            "stepOut" => {
                self.pc = self.pc.wrapping_add(0x20);
                RpcResponse::ok(0, json!({ "stopped": true, "reason": "stepOut", "pc": hex_u64(self.pc) }))
            }

            "regs" => RpcResponse::ok(0, self.make_regs()),

            "setReg" => {
                let name = param_str(&params, "name").unwrap_or_default().to_lowercase();
                let value = params.as_ref().and_then(|p| p.get("value"));
                if name.is_empty() || value.is_none() {
                    return RpcResponse::err(0, "bad_params", "setReg requires {name, value}");
                }
                if name == "pc" {
                    match hywdbg_protocol::parse_u64ish(value.unwrap()) {
                        Ok(v) => self.pc = v,
                        Err(e) => return RpcResponse::err(0, "bad_params", e),
                    }
                } else if name == "sp" {
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
                // RISC-V NOP: 0x00000013 (addi zero, zero, 0)
                let riscv_nop = [0x13_u8, 0x00, 0x00, 0x00];
                let hex = (0..size)
                    .map(|i| format!("{:02x}", riscv_nop[i % 4]))
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
                let lines = self.disassemble(addr, count);
                RpcResponse::ok(0, lines)
            }

            "bpSet" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "bpSet requires {addr}"),
                };
                let kind = param_str(&params, "kind").unwrap_or_else(|| "SW".to_string());
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
                        id: "p1.t1".to_string(),
                        name: Some("main".to_string()),
                        pc: Some(hex_u64(self.pc)),
                        active: true,
                    },
                    ThreadInfo {
                        id: "p1.t2".to_string(),
                        name: Some("irq-handler".to_string()),
                        pc: Some(hex_u64(0x0000000000020000)),
                        active: false,
                    },
                    ThreadInfo {
                        id: "p1.t3".to_string(),
                        name: Some("idle".to_string()),
                        pc: Some(hex_u64(0x0000000000030000)),
                        active: false,
                    },
                ];
                RpcResponse::ok(0, threads)
            }

            "modules" => {
                let path = self.launched_path.clone();
                let modules = vec![
                    ModuleInfo {
                        name: path.as_deref().unwrap_or("firmware.elf").to_string(),
                        base: hex_u64(0x0000000000010000),
                        size: 0x40000,
                        path: path.clone(),
                    },
                    ModuleInfo {
                        name: "libc.a".to_string(),
                        base: hex_u64(0x0000000000060000),
                        size: 0x8000,
                        path: Some("/opt/riscv/sysroot/lib/libc.a".to_string()),
                    },
                    ModuleInfo {
                        name: "rom.bin".to_string(),
                        base: hex_u64(0x0000000020000000),
                        size: 0x100000,
                        path: Some("/flash/rom.bin".to_string()),
                    },
                ];
                RpcResponse::ok(0, modules)
            }

            "callstack" => {
                let frames = vec![
                    StackFrame {
                        addr: hex_u64(self.pc),
                        symbol: Some("main".to_string()),
                        module: Some("firmware.elf".to_string()),
                        source: Some("src/main.c:88".to_string()),
                    },
                    StackFrame {
                        addr: hex_u64(0x0000000000014200),
                        symbol: Some("hal_init".to_string()),
                        module: Some("firmware.elf".to_string()),
                        source: Some("hal/init.c:23".to_string()),
                    },
                    StackFrame {
                        addr: hex_u64(0x0000000000063800),
                        symbol: Some("__libc_start_main".to_string()),
                        module: Some("libc.a".to_string()),
                        source: None,
                    },
                    StackFrame {
                        addr: hex_u64(0x0000000000010480),
                        symbol: Some("_start".to_string()),
                        module: Some("firmware.elf".to_string()),
                        source: Some("crt0.S:14".to_string()),
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
                let kind = param_str(&params, "kind").unwrap_or_else(|| "rw".to_string());
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
                // GDB remote often talks to embedded targets with no OS process list,
                // or to QEMU/OpenOCD. Return a reasonable mock.
                let procs = vec![
                    ProcessListEntry { pid: 1, name: "firmware.elf".to_string(), arch: self.target_arch.clone(), description: Some("Bare metal target".to_string()) },
                    ProcessListEntry { pid: 2, name: "qemu-riscv64".to_string(), arch: "x64".to_string(), description: Some("QEMU emulator host".to_string()) },
                    ProcessListEntry { pid: 3, name: "openocd".to_string(), arch: "x64".to_string(), description: Some("OpenOCD debug adapter".to_string()) },
                    ProcessListEntry { pid: 100, name: "kernel".to_string(), arch: self.target_arch.clone(), description: Some("Linux kernel (kgdb)".to_string()) },
                    ProcessListEntry { pid: 200, name: "init".to_string(), arch: self.target_arch.clone(), description: Some("PID 1 init process".to_string()) },
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
        let m = m.trim_end_matches(".elf").trim_end_matches(".bin");
        let s = symbol.to_lowercase();
        const BASE_FW: u64 = 0x0000000000010000;
        match (m, s.as_str()) {
            ("" | "firmware", "_start") => Some(BASE_FW),
            ("" | "firmware", "main") => Some(BASE_FW + 0x100),
            ("" | "firmware", "uart_write") => Some(BASE_FW + 0x500),
            ("" | "firmware", "uart_read") => Some(BASE_FW + 0x600),
            ("" | "firmware", "irq_handler") => Some(BASE_FW + 0x1000),
            ("" | "firmware", "memset") => Some(BASE_FW + 0x2000),
            ("" | "firmware", "malloc") => Some(BASE_FW + 0x3000),
            _ => None,
        }
    }

    fn make_regs(&self) -> RegDump {
        let mut r = BTreeMap::new();
        // RISC-V 64 ABI register file
        r.insert("pc".to_string(),   hex_u64(self.pc));
        r.insert("ra".to_string(),   hex_u64(0x0000000000010480)); // x1
        r.insert("sp".to_string(),   hex_u64(self.sp));             // x2
        r.insert("gp".to_string(),   hex_u64(0x0000000000068000)); // x3 global pointer
        r.insert("tp".to_string(),   hex_u64(0x0000000000000000)); // x4 thread pointer
        r.insert("t0".to_string(),   hex_u64(0x0000000000000000)); // x5
        r.insert("t1".to_string(),   hex_u64(0x0000000000000000)); // x6
        r.insert("t2".to_string(),   hex_u64(0x0000000000000000)); // x7
        r.insert("s0".to_string(),   hex_u64(self.sp.wrapping_add(0x10))); // x8 / fp
        r.insert("s1".to_string(),   hex_u64(0x0000000000000001)); // x9
        r.insert("a0".to_string(),   hex_u64(0x0000000000000000)); // x10
        r.insert("a1".to_string(),   hex_u64(0x0000000000000001)); // x11
        r.insert("a2".to_string(),   hex_u64(0x0000000000000002)); // x12
        r.insert("a3".to_string(),   hex_u64(0x0000000000000003)); // x13
        r.insert("a4".to_string(),   hex_u64(0x0000000000000004)); // x14
        r.insert("a5".to_string(),   hex_u64(0x0000000000000005)); // x15
        r.insert("a6".to_string(),   hex_u64(0x0000000000000006)); // x16
        r.insert("a7".to_string(),   hex_u64(0x0000000000000007)); // x17 (syscall number)
        r.insert("s2".to_string(),   hex_u64(0x0000000000000000)); // x18
        r.insert("s3".to_string(),   hex_u64(0x0000000000000000)); // x19
        r.insert("s4".to_string(),   hex_u64(0x0000000000000000)); // x20
        r.insert("s5".to_string(),   hex_u64(0x0000000000000000)); // x21
        r.insert("s6".to_string(),   hex_u64(0x0000000000000000)); // x22
        r.insert("s7".to_string(),   hex_u64(0x0000000000000000)); // x23
        r.insert("s8".to_string(),   hex_u64(0x0000000000000000)); // x24
        r.insert("s9".to_string(),   hex_u64(0x0000000000000000)); // x25
        r.insert("s10".to_string(),  hex_u64(0x0000000000000000)); // x26
        r.insert("s11".to_string(),  hex_u64(0x0000000000000000)); // x27
        r.insert("t3".to_string(),   hex_u64(0x0000000000000000)); // x28
        r.insert("t4".to_string(),   hex_u64(0x0000000000000000)); // x29
        r.insert("t5".to_string(),   hex_u64(0x0000000000000000)); // x30
        r.insert("t6".to_string(),   hex_u64(0x0000000000000000)); // x31
        RegDump { arch: self.target_arch.clone(), registers: r }
    }

    fn disassemble(&self, start_addr: u64, count: usize) -> Vec<DisasmLine> {
        let aligned_start = start_addr & !3;
        (0..count).map(|i| {
            let addr = aligned_start.wrapping_add(i as u64 * 4);
            let idx = ((addr / 4) % MOCK_RISCV_INSNS.len() as u64) as usize;
            let entry = &MOCK_RISCV_INSNS[idx];
            DisasmLine {
                addr: hex_u64(addr),
                bytes: entry.0.to_string(),
                text: entry.1.to_string(),
            }
        }).collect()
    }
}

fn main() -> anyhow::Result<()> {
    run_stdio_backend(BackendState::default())
}
