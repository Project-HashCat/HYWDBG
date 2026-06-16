use hywdbg_backend_common::{param_str, param_u64, run_stdio_backend, BackendHandler};
use hywdbg_protocol::{
    hex_u64, BackendCapabilities, BreakpointRecord, DisasmLine, MemoryBlock, ModuleInfo,
    ProcessListEntry, RegDump, RpcResponse, StackFrame, ThreadInfo, WatchpointInfo,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

const BACKEND_KIND: &str = "frida";
const BACKEND_NAME: &str = "HYWDbg Frida Backend";

// ARM64 mock instructions: realistic-looking function prologue
// stp x29, x30, [sp, #-0x10]!
// mov x29, sp
// sub sp, sp, #0x20
// ldr x8, [x0]
// blr x8
// ldp x29, x30, [sp], #0x10
// ret
const MOCK_ARM64: &[(&str, &str, &str)] = &[
    ("fda10fbf", "a9be7bfd", "stp x29, x30, [sp, #-0x10]!"),
    ("fd030091", "910003fd", "mov x29, sp"),
    ("ff830091", "d10083ff", "sub sp, sp, #0x20"),
    ("080040f9", "f9400008", "ldr x8, [x0]"),
    ("00013fd6", "d63f0100", "blr x8"),
    ("fda107a8", "a8c17bfd", "ldp x29, x30, [sp], #0x10"),
    ("c0035fd6", "d65f03c0", "ret"),
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
            pc: 0x0000000100004567,
            sp: 0x000000016FDFF000,
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
                "note": "Frida backend adapter; frida-core bindings wired here"
            })),

            "capabilities" => RpcResponse::ok(0, BackendCapabilities {
                name: BACKEND_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                backend_kind: BACKEND_KIND.to_string(),
                supported_arches: vec![
                    "arm64".to_string(), "arm".to_string(),
                    "x64".to_string(), "x86".to_string(),
                    "mips".to_string(),
                ],
                features: vec![
                    "attach".to_string(), "spawn".to_string(),
                    "breakpoints".to_string(), "watchpoints".to_string(),
                    "memory".to_string(), "registers".to_string(),
                    "threads".to_string(), "modules".to_string(),
                    "callstack".to_string(), "disasm".to_string(),
                    "processList".to_string(), "hooks".to_string(),
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
                RpcResponse::ok(0, json!({
                    "launched": true, "path": path, "backend": BACKEND_KIND, "pid": 1234_u64
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
                "stopped": true, "reason": "pause", "pc": hex_u64(self.pc)
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
                self.pc = self.pc.wrapping_add(0x30);
                RpcResponse::ok(0, json!({ "stopped": true, "reason": "stepOut", "pc": hex_u64(self.pc) }))
            }

            "regs" => RpcResponse::ok(0, self.make_regs()),

            "setReg" => {
                let name = param_str(&params, "name").unwrap_or_default().to_lowercase();
                let value = params.as_ref().and_then(|p| p.get("value"));
                if name.is_empty() || value.is_none() {
                    return RpcResponse::err(0, "bad_params", "setReg requires {name, value}");
                }
                if name == "pc" || name == "x32" {
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
                // ARM64 NOP pattern: 1f 20 03 d5
                let arm64_nop = [0x1f_u8, 0x20, 0x03, 0xd5];
                let hex = (0..size)
                    .map(|i| format!("{:02x}", arm64_nop[i % 4]))
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
                        id: "1".to_string(),
                        name: Some("main".to_string()),
                        pc: Some(hex_u64(self.pc)),
                        active: true,
                    },
                    ThreadInfo {
                        id: "2".to_string(),
                        name: Some("com.apple.libdispatch-manager".to_string()),
                        pc: Some(hex_u64(0x000000018012A840)),
                        active: false,
                    },
                ];
                RpcResponse::ok(0, threads)
            }

            "modules" => {
                let path = self.launched_path.clone();
                let app_name = path.as_deref().unwrap_or("TargetApp");
                let modules = vec![
                    ModuleInfo {
                        name: app_name.to_string(),
                        base: hex_u64(0x0000000100000000),
                        size: 0x80000,
                        path: path.clone().or_else(|| Some(format!("/Applications/{app_name}.app/MacOS/{app_name}"))),
                    },
                    ModuleInfo {
                        name: "libSystem.B.dylib".to_string(),
                        base: hex_u64(0x00000001803A0000),
                        size: 0x3C000,
                        path: Some("/usr/lib/libSystem.B.dylib".to_string()),
                    },
                    ModuleInfo {
                        name: "libobjc.A.dylib".to_string(),
                        base: hex_u64(0x0000000180200000),
                        size: 0x28000,
                        path: Some("/usr/lib/libobjc.A.dylib".to_string()),
                    },
                ];
                RpcResponse::ok(0, modules)
            }

            "callstack" => {
                let frames = vec![
                    StackFrame {
                        addr: hex_u64(self.pc),
                        symbol: Some("-[AppDelegate applicationDidFinishLaunching:]".to_string()),
                        module: Some("TargetApp".to_string()),
                        source: Some("AppDelegate.m:58".to_string()),
                    },
                    StackFrame {
                        addr: hex_u64(0x000000010000B210),
                        symbol: Some("_UIApplicationMain".to_string()),
                        module: Some("UIKit".to_string()),
                        source: None,
                    },
                    StackFrame {
                        addr: hex_u64(0x0000000180201A40),
                        symbol: Some("_objc_msgSend".to_string()),
                        module: Some("libobjc.A.dylib".to_string()),
                        source: None,
                    },
                    StackFrame {
                        addr: hex_u64(0x00000001803B5C10),
                        symbol: Some("_dispatch_main".to_string()),
                        module: Some("libSystem.B.dylib".to_string()),
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
                    ProcessListEntry { pid: 1, name: "launchd".to_string(), arch: "arm64".to_string(), description: Some("System init".to_string()) },
                    ProcessListEntry { pid: 85, name: "WindowServer".to_string(), arch: "arm64".to_string(), description: Some("macOS GUI compositor".to_string()) },
                    ProcessListEntry { pid: 312, name: "SpringBoard".to_string(), arch: "arm64".to_string(), description: Some("iOS home screen".to_string()) },
                    ProcessListEntry { pid: 1024, name: "TargetApp".to_string(), arch: "arm64".to_string(), description: Some("Debug target".to_string()) },
                    ProcessListEntry { pid: 2201, name: "MobileSafari".to_string(), arch: "arm64".to_string(), description: None },
                    ProcessListEntry { pid: 3400, name: "pkd".to_string(), arch: "arm64".to_string(), description: Some("Plugin kit daemon".to_string()) },
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
        let m = m.trim_end_matches(".dylib").trim_end_matches(".framework");
        let s = symbol.to_lowercase();
        const BASE_OBJC: u64 = 0x0000000180120000;
        const BASE_SYS: u64  = 0x0000000180050000;
        const BASE_UI: u64   = 0x0000000190100000;
        const BASE_FND: u64  = 0x0000000195200000;
        match (m, s.as_str()) {
            ("libobjc" | "libobjc.a", "objc_msgsend") => Some(BASE_OBJC + 0x1000),
            ("libobjc" | "libobjc.a", "objc_retain") => Some(BASE_OBJC + 0x2000),
            ("libobjc" | "libobjc.a", "objc_release") => Some(BASE_OBJC + 0x2100),
            ("libsystem" | "libsystem.b", "malloc") => Some(BASE_SYS + 0x3000),
            ("libsystem" | "libsystem.b", "free") => Some(BASE_SYS + 0x3200),
            ("libsystem" | "libsystem.b", "memcpy") => Some(BASE_SYS + 0x3400),
            ("foundation", "nslog") => Some(BASE_FND + 0x1000),
            ("uikit", "uiapplicationmain") => Some(BASE_UI + 0x1500),
            ("libsystem" | "libsystem.b", "dispatch_async") => Some(BASE_SYS + 0x4000),
            _ => None,
        }
    }

    fn make_regs(&self) -> RegDump {
        let mut r = BTreeMap::new();
        // ARM64 general-purpose registers
        r.insert("pc".to_string(),  hex_u64(self.pc));
        r.insert("sp".to_string(),  hex_u64(self.sp));
        r.insert("x0".to_string(),  hex_u64(0x0000000000000000));
        r.insert("x1".to_string(),  hex_u64(0x0000000100004567));
        r.insert("x2".to_string(),  hex_u64(0x0000000000000002));
        r.insert("x3".to_string(),  hex_u64(0x0000000000000003));
        r.insert("x4".to_string(),  hex_u64(0x0000000000000004));
        r.insert("x5".to_string(),  hex_u64(0x0000000000000005));
        r.insert("x6".to_string(),  hex_u64(0x0000000000000006));
        r.insert("x7".to_string(),  hex_u64(0x0000000000000007));
        r.insert("x8".to_string(),  hex_u64(0x0000000100008000));
        r.insert("x9".to_string(),  hex_u64(0x0000000000000000));
        r.insert("x10".to_string(), hex_u64(0x0000000000000000));
        r.insert("x11".to_string(), hex_u64(0x0000000000000000));
        r.insert("x12".to_string(), hex_u64(0x0000000000000000));
        r.insert("x13".to_string(), hex_u64(0x0000000000000000));
        r.insert("x14".to_string(), hex_u64(0x0000000000000000));
        r.insert("x15".to_string(), hex_u64(0x0000000000000000));
        r.insert("x16".to_string(), hex_u64(0x0000000180012345)); // ip0 (intra-proc linker)
        r.insert("x17".to_string(), hex_u64(0x0000000180012346)); // ip1
        r.insert("x18".to_string(), hex_u64(0x0000000000000000)); // platform reserved
        r.insert("x19".to_string(), hex_u64(0x0000000000000001));
        r.insert("x20".to_string(), hex_u64(0x0000000100004000));
        r.insert("x21".to_string(), hex_u64(0x0000000000000000));
        r.insert("x22".to_string(), hex_u64(0x0000000000000000));
        r.insert("x23".to_string(), hex_u64(0x0000000000000000));
        r.insert("x24".to_string(), hex_u64(0x0000000000000000));
        r.insert("x25".to_string(), hex_u64(0x0000000000000000));
        r.insert("x26".to_string(), hex_u64(0x0000000000000000));
        r.insert("x27".to_string(), hex_u64(0x0000000000000000));
        r.insert("x28".to_string(), hex_u64(0x0000000000000000));
        r.insert("x29".to_string(), hex_u64(0x000000016FDFF100)); // frame pointer
        r.insert("x30".to_string(), hex_u64(0x0000000100005678)); // link register
        r.insert("cpsr".to_string(), hex_u64(0x0000000060000000)); // nzcv=0110
        RegDump { arch: "arm64".to_string(), registers: r }
    }

    fn disassemble(&self, start_addr: u64, count: usize) -> Vec<DisasmLine> {
        let mut lines = Vec::new();
        let mock = MOCK_ARM64;
        let aligned_start = start_addr & !3;
        for i in 0..count {
            let addr = aligned_start.wrapping_add(i as u64 * 4);
            let idx = ((addr / 4) % mock.len() as u64) as usize;
            let entry = &mock[idx];
            lines.push(DisasmLine {
                addr: hex_u64(addr),
                bytes: entry.1.to_string(),
                text: entry.2.to_string(),
            });
        }
        lines
    }
}

fn main() -> anyhow::Result<()> {
    run_stdio_backend(BackendState::default())
}
