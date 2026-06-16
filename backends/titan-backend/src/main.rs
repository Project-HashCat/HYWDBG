use hywdbg_backend_common::{param_str, run_stdio_backend, BackendHandler};
use hywdbg_protocol::{
    hex_u64, BackendCapabilities, RegDump, RpcResponse
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::thread;

// TitanEngine sys crate
use titanengine_sys::*;

const BACKEND_KIND: &str = "titan";
const BACKEND_NAME: &str = "HYWDbg TitanEngine Backend (Real)";

lazy_static::lazy_static! {
    static ref EVENT_TX: Mutex<Option<Sender<RpcResponse>>> = Mutex::new(None);
    static ref CMD_RX: Mutex<Option<Receiver<String>>> = Mutex::new(None);
    static ref CMD_TX: Mutex<Option<Sender<String>>> = Mutex::new(None);
}

// Ensure string is null-terminated for C FFI
fn c_str(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

extern "system" fn cb_entry_point() {
    // Reached entry point
    send_event_and_wait(json!({
        "stopped": true,
        "event": "breakpoint",
        "reason": "entry",
        "pc": hex_u64(get_rip())
    }));
}

extern "system" fn cb_system_breakpoint() {
    send_event_and_wait(json!({
        "stopped": true,
        "event": "breakpoint",
        "reason": "system_bp",
        "pc": hex_u64(get_rip())
    }));
}

extern "system" fn cb_custom_handler() {
    // A breakpoint set by us
    send_event_and_wait(json!({
        "stopped": true,
        "event": "breakpoint",
        "reason": "go",
        "pc": hex_u64(get_rip())
    }));
}

fn get_rip() -> u64 {
    unsafe { GetContextData(16) as u64 } // 16 = UE_RIP
}

fn send_event_and_wait(value: Value) {
    if let Some(tx) = EVENT_TX.lock().unwrap().as_ref() {
        let _ = tx.send(RpcResponse::ok(0, value));
    }
    
    // Block until we receive a continue command
    if let Some(rx) = CMD_RX.lock().unwrap().as_ref() {
        while let Ok(cmd) = rx.recv() {
            if cmd == "go" {
                break;
            } else if cmd == "detach" || cmd == "kill" {
                unsafe { StopDebug() };
                break;
            }
            // Other commands like regs/mem are handled by the main thread directly
        }
    }
}

struct BackendState {
    attached_pid: Option<u64>,
    launched_path: Option<String>,
    ev_rx: Option<Receiver<RpcResponse>>,
}

impl Default for BackendState {
    fn default() -> Self {
        Self {
            attached_pid: None,
            launched_path: None,
            ev_rx: None,
        }
    }
}

impl BackendHandler for BackendState {
    fn handle(&mut self, method: &str, params: Option<Value>) -> RpcResponse {
        match method {
            "hello" => RpcResponse::ok(0, json!({
                "name": BACKEND_NAME,
                "version": "1.0",
                "kind": BACKEND_KIND,
                "arch": "x64",
                "os": "windows"
            })),
            
            "capabilities" => RpcResponse::ok(0, serde_json::to_value(BackendCapabilities {
                name: BACKEND_NAME.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                backend_kind: BACKEND_KIND.into(),
                supported_arches: vec!["x64".into()],
                features: vec![
                    "launch".into(),
                    "attach".into(),
                    "go".into(),
                    "regs".into(),
                ],
            }).unwrap()),

            "launch" => {
                let path = param_str(&params, "path").unwrap_or_default();
                if path.is_empty() {
                    return RpcResponse::err(0, "bad_params", "Missing 'path'");
                }

                let (ev_tx, ev_rx) = channel();
                let (cmd_tx, cmd_rx) = channel();
                
                *EVENT_TX.lock().unwrap() = Some(ev_tx);
                *CMD_RX.lock().unwrap() = Some(cmd_rx);
                *CMD_TX.lock().unwrap() = Some(cmd_tx);

                self.launched_path = Some(path.clone());
                self.ev_rx = Some(ev_rx);

                thread::spawn(move || {
                    unsafe {
                        let path_c = c_str(&path);
                        InitDebugEx(path_c.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), cb_entry_point as *mut _);
                        SetCustomHandler(0x80000003, cb_system_breakpoint as *mut _); // EXCEPTION_BREAKPOINT
                        DebugLoop();
                    }
                });

                if let Some(rx) = self.ev_rx.as_ref() {
                    if let Ok(resp) = rx.recv() {
                        self.attached_pid = Some(0);
                        return resp;
                    }
                }
                RpcResponse::err(0, "launch_failed", "DebugLoop terminated early")
            }

            "go" | "stepInto" | "stepOver" | "stepOut" => {
                if let Some(tx) = CMD_TX.lock().unwrap().as_ref() {
                    let _ = tx.send("go".to_string());
                }
                
                if let Some(rx) = self.ev_rx.as_ref() {
                    if let Ok(resp) = rx.recv() {
                        return resp;
                    }
                }
                RpcResponse::ok(0, json!({ "stopped": true, "event": "exit_process", "exitCode": 0 }))
            }

            "kill" | "detach" => {
                if let Some(tx) = CMD_TX.lock().unwrap().as_ref() {
                    let _ = tx.send(method.to_string());
                }
                self.attached_pid = None;
                self.launched_path = None;
                RpcResponse::ok(0, json!({ "success": true }))
            }

            "regs" => {
                // Get Context
                unsafe {
                    let rax = GetContextData(0);
                    let rcx = GetContextData(1);
                    let rdx = GetContextData(2);
                    let rbx = GetContextData(3);
                    let rsp = GetContextData(4);
                    let rbp = GetContextData(5);
                    let rsi = GetContextData(6);
                    let rdi = GetContextData(7);
                    let r8 = GetContextData(8);
                    let r9 = GetContextData(9);
                    let r10 = GetContextData(10);
                    let r11 = GetContextData(11);
                    let r12 = GetContextData(12);
                    let r13 = GetContextData(13);
                    let r14 = GetContextData(14);
                    let r15 = GetContextData(15);
                    let rip = GetContextData(16);

                    let mut r = RegDump {
                        gpr: HashMap::new(),
                        fpr: HashMap::new(),
                        flags: HashMap::new(),
                    };
                    r.gpr.insert("rax".into(), hex_u64(rax as u64));
                    r.gpr.insert("rcx".into(), hex_u64(rcx as u64));
                    r.gpr.insert("rdx".into(), hex_u64(rdx as u64));
                    r.gpr.insert("rbx".into(), hex_u64(rbx as u64));
                    r.gpr.insert("rsp".into(), hex_u64(rsp as u64));
                    r.gpr.insert("rbp".into(), hex_u64(rbp as u64));
                    r.gpr.insert("rsi".into(), hex_u64(rsi as u64));
                    r.gpr.insert("rdi".into(), hex_u64(rdi as u64));
                    r.gpr.insert("r8".into(), hex_u64(r8 as u64));
                    r.gpr.insert("r9".into(), hex_u64(r9 as u64));
                    r.gpr.insert("r10".into(), hex_u64(r10 as u64));
                    r.gpr.insert("r11".into(), hex_u64(r11 as u64));
                    r.gpr.insert("r12".into(), hex_u64(r12 as u64));
                    r.gpr.insert("r13".into(), hex_u64(r13 as u64));
                    r.gpr.insert("r14".into(), hex_u64(r14 as u64));
                    r.gpr.insert("r15".into(), hex_u64(r15 as u64));
                    r.gpr.insert("rip".into(), hex_u64(rip as u64));
                    
                    RpcResponse::ok(0, serde_json::to_value(r).unwrap())
                }
            }

            "disasm" => {
                RpcResponse::ok(0, json!({ "lines": [] }))
            }
            
            "shutdown" => {
                std::process::exit(0);
            }

            _ => RpcResponse::err(0, "not_implemented", format!("method {} not implemented in titan", method)),
        }
    }
}

fn main() {
    let state = BackendState::default();
    if let Err(e) = run_stdio_backend(state) {
        eprintln!("Backend error: {e}");
    }
}
