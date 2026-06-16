use hywdbg_backend_common::{param_str, run_stdio_backend, BackendHandler};
use hywdbg_protocol::{
    hex_u64, BackendCapabilities, RegDump, RpcResponse
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::ffi::CString;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::thread;

// TitanEngine sys crate
use titanengine_sys::*;

const BACKEND_KIND: &str = "titan";
const BACKEND_NAME: &str = "HYWDbg TitanEngine Backend (Real)";

use lazy_static::lazy_static;
use windows_sys::Win32::System::Diagnostics::Debug::DebugBreakProcess;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use windows_sys::Win32::Foundation::HANDLE;

lazy_static! {
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
            } else if cmd == "stepInto" {
                unsafe { StepInto(cb_custom_handler as *mut _) };
                break;
            } else if cmd == "stepOver" {
                unsafe { StepOver(cb_custom_handler as *mut _) };
                break;
            } else if cmd == "stepOut" {
                unsafe { StepOut(cb_custom_handler as *mut _, false) };
                break;
            } else if cmd == "detach" || cmd == "kill" {
                unsafe { StopDebug() };
                break;
            }
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
                        // TitanEngine may be picky about backslashes
                        let dos_path = path.replace("/", "\\");
                        let path_c = c_str(&dos_path);
                        
                        let folder = std::path::Path::new(&path).parent().unwrap_or(std::path::Path::new("")).to_string_lossy().into_owned().replace("/", "\\");
                        let folder_c = c_str(&folder);

                        eprintln!("[TITAN] Calling InitDebugEx with path: {} and folder: {}", dos_path, folder);
                        // pass path_c.as_ptr() for command line, and folder_c.as_ptr() for current folder
                        let pe = InitDebugEx(path_c.as_ptr(), path_c.as_ptr(), folder_c.as_ptr(), cb_entry_point as *mut _);
                        eprintln!("[TITAN] InitDebugEx returned {:p}", pe);
                        if pe.is_null() {
                            eprintln!("[TITAN] InitDebugEx failed!");
                        } else {
                            SetCustomHandler(0x80000003, cb_system_breakpoint as *mut _); // EXCEPTION_BREAKPOINT
                            eprintln!("[TITAN] Calling DebugLoop...");
                            DebugLoop();
                        }
                        eprintln!("[TITAN] DebugLoop exited or InitDebugEx failed!");
                        // send an error event so the main thread wakes up
                        if let Some(tx) = EVENT_TX.lock().unwrap().as_ref() {
                            let _ = tx.send(RpcResponse::err(0, "launch_failed", "DebugLoop exited immediately"));
                        }
                    }
                });

                if let Some(rx) = self.ev_rx.as_ref() {
                    eprintln!("[TITAN] Main thread waiting for rx.recv()...");
                    if let Ok(resp) = rx.recv_timeout(std::time::Duration::from_secs(10)) {
                        eprintln!("[TITAN] rx.recv() got response!");
                        self.attached_pid = Some(0);
                        return resp;
                    } else {
                        eprintln!("[TITAN] rx.recv() TIMED OUT!");
                    }
                }
                RpcResponse::err(0, "launch_failed", "DebugLoop terminated early or timed out")
            }

            "attach" => {
                let pid = param_u64(&params, "pid").unwrap_or(0) as u32;
                if pid == 0 {
                    return RpcResponse::err(0, "bad_params", "attach requires pid");
                }
                
                let (ev_tx, ev_rx) = channel();
                let (cmd_tx, cmd_rx) = channel();
                
                *EVENT_TX.lock().unwrap() = Some(ev_tx);
                *CMD_RX.lock().unwrap() = Some(cmd_rx);
                *CMD_TX.lock().unwrap() = Some(cmd_tx);
                
                self.attached_pid = Some(pid as u64);
                self.launched_path = None;
                self.ev_rx = Some(ev_rx);
                
                let pid_clone = pid;
                std::thread::spawn(move || {
                    unsafe {
                        eprintln!("[TITAN] Calling AttachDebugger with pid: {}", pid_clone);
                        if AttachDebugger(pid_clone, false, std::ptr::null_mut(), cb_system_breakpoint as *mut _) {
                            eprintln!("[TITAN] Calling DebugLoop for attach...");
                            DebugLoop();
                        } else {
                            eprintln!("[TITAN] AttachDebugger failed!");
                            if let Some(tx) = EVENT_TX.lock().unwrap().as_ref() {
                                let _ = tx.send(RpcResponse::err(0, "attach_failed", "AttachDebugger failed"));
                            }
                        }
                    }
                });

                if let Some(rx) = self.ev_rx.as_ref() {
                    if let Ok(resp) = rx.recv_timeout(std::time::Duration::from_secs(10)) {
                        return resp;
                    }
                }
                RpcResponse::err(0, "attach_failed", "Attach timeout")
            }

            "pause" => {
                let pid = self.attached_pid.unwrap_or(0);
                if pid > 0 {
                    unsafe {
                        let h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid as u32);
                        if h != 0 {
                            DebugBreakProcess(h);
                            windows_sys::Win32::Foundation::CloseHandle(h);
                        }
                    }
                }
                RpcResponse::ok(0, json!({ "success": true }))
            }

            "go" => {
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

            "stepInto" | "stepOver" | "stepOut" => {
                if let Some(tx) = CMD_TX.lock().unwrap().as_ref() {
                    let _ = tx.send(method.to_string());
                }
                
                if let Some(rx) = self.ev_rx.as_ref() {
                    if let Ok(resp) = rx.recv() {
                        return resp;
                    }
                }
                RpcResponse::ok(0, json!({ "stopped": true, "event": "exit_process", "exitCode": 0 }))
            }

            "bpSet" => {
                let addr_str = param_str(&params, "addr").unwrap_or_default();
                let addr = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                if addr > 0 {
                    unsafe { SetBPX(addr, 0, cb_custom_handler as *mut _) }; // UE_BREAKPOINT = 0
                }
                RpcResponse::ok(0, json!({ "success": true }))
            }

            "bpClear" => {
                let addr_str = param_str(&params, "addr").unwrap_or_default();
                let addr = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                if addr > 0 {
                    unsafe { DeleteBPX(addr) };
                }
                RpcResponse::ok(0, json!({ "success": true }))
            }
            
            "bpList" => {
                RpcResponse::ok(0, json!([]))
            }

            "readMem" => {
                let addr_str = param_str(&params, "addr").unwrap_or_default();
                let addr = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                let size = param_u64(&params, "size").unwrap_or(0) as u32;
                
                let mut buf = vec![0u8; size as usize];
                let mut bytes_read: u64 = 0;
                unsafe {
                    let pi = TitanGetProcessInformation();
                    if !pi.is_null() && !(*pi).hProcess.is_null() {
                        MemoryReadSafe((*pi).hProcess, addr as *mut _, buf.as_mut_ptr() as *mut _, size as u64, &mut bytes_read);
                    }
                }
                
                let hex = buf[..bytes_read as usize].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
                RpcResponse::ok(0, json!(hex))
            }

            "writeMem" => {
                let addr_str = param_str(&params, "addr").unwrap_or_default();
                let addr = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                let hex_str = param_str(&params, "hex").unwrap_or_default();
                
                let mut bytes = Vec::new();
                for i in (0..hex_str.len()).step_by(2) {
                    if i + 2 <= hex_str.len() {
                        if let Ok(b) = u8::from_str_radix(&hex_str[i..i+2], 16) {
                            bytes.push(b);
                        }
                    }
                }
                
                let mut bytes_written: u64 = 0;
                unsafe {
                    let pi = TitanGetProcessInformation();
                    if !pi.is_null() && !(*pi).hProcess.is_null() {
                        MemoryWriteSafe((*pi).hProcess, addr as *mut _, bytes.as_mut_ptr() as *mut _, bytes.len() as u64, &mut bytes_written);
                    }
                }
                RpcResponse::ok(0, json!({ "success": bytes_written > 0 }))
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
                        arch: "x64".to_string(),
                        registers: BTreeMap::new(),
                    };
                    r.registers.insert("rax".into(), hex_u64(rax as u64));
                    r.registers.insert("rcx".into(), hex_u64(rcx as u64));
                    r.registers.insert("rdx".into(), hex_u64(rdx as u64));
                    r.registers.insert("rbx".into(), hex_u64(rbx as u64));
                    r.registers.insert("rsp".into(), hex_u64(rsp as u64));
                    r.registers.insert("rbp".into(), hex_u64(rbp as u64));
                    r.registers.insert("rsi".into(), hex_u64(rsi as u64));
                    r.registers.insert("rdi".into(), hex_u64(rdi as u64));
                    r.registers.insert("r8".into(), hex_u64(r8 as u64));
                    r.registers.insert("r9".into(), hex_u64(r9 as u64));
                    r.registers.insert("r10".into(), hex_u64(r10 as u64));
                    r.registers.insert("r11".into(), hex_u64(r11 as u64));
                    r.registers.insert("r12".into(), hex_u64(r12 as u64));
                    r.registers.insert("r13".into(), hex_u64(r13 as u64));
                    r.registers.insert("r14".into(), hex_u64(r14 as u64));
                    r.registers.insert("r15".into(), hex_u64(r15 as u64));
                    r.registers.insert("rip".into(), hex_u64(rip as u64));
                    
                    RpcResponse::ok(0, serde_json::to_value(r).unwrap())
                }
            }

            "disasm" => {
                let mut addr_str = param_str(&params, "addr").unwrap_or_default();
                let mut addr = get_rip();
                if !addr_str.is_empty() {
                    let clean = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                    if let Ok(a) = u64::from_str_radix(clean, 16) {
                        addr = a;
                    }
                }
                
                let lines_req = params.as_ref()
                    .and_then(|p| p.get("lines"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;

                let mut lines_out = Vec::new();

                // Read a chunk of memory (lines * 15 bytes max per x86 instruction)
                let read_size = lines_req * 15;
                let mut buf = vec![0u8; read_size];
                let mut bytes_read: u64 = 0;

                unsafe {
                    let pi = TitanGetProcessInformation();
                    if !pi.is_null() && !(*pi).hProcess.is_null() {
                        MemoryReadSafe((*pi).hProcess, addr as *mut _, buf.as_mut_ptr() as *mut _, read_size as u64, &mut bytes_read);
                    }
                }

                let bytes_read_usize = bytes_read as usize;
                if bytes_read_usize > 0 {
                    use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter, Instruction};
                    let actual_bytes = &buf[..bytes_read_usize];
                    let mut decoder = Decoder::with_ip(64, actual_bytes, addr, DecoderOptions::NONE);
                    let mut formatter = NasmFormatter::new();
                    let mut instruction = Instruction::default();
                    let mut output = String::new();

                    while decoder.can_decode() && lines_out.len() < lines_req {
                        decoder.decode_out(&mut instruction);
                        output.clear();
                        formatter.format(&instruction, &mut output);
                        
                        let start_idx = (instruction.ip() - addr) as usize;
                        let end_idx = start_idx + instruction.len();
                        
                        let hex_str = if end_idx <= actual_bytes.len() {
                            actual_bytes[start_idx..end_idx]
                                .iter()
                                .map(|b| format!("{:02X}", b))
                                .collect::<Vec<_>>()
                                .join(" ")
                        } else {
                            "??".to_string()
                        };

                        lines_out.push(json!({
                            "addr": hex_u64(instruction.ip()),
                            "bytes": hex_str,
                            "text": output.clone()
                        }));
                    }
                }

                RpcResponse::ok(0, json!({ "lines": lines_out }))
            }
            
            "processList" => {
                let mut sys = sysinfo::System::new_all();
                sys.refresh_processes();
                
                let mut procs = Vec::new();
                for (pid, process) in sys.processes() {
                    procs.push(json!({
                        "pid": pid.as_u32(),
                        "name": process.name().to_string_lossy(),
                        "arch": "x64",
                        "path": process.exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
                    }));
                }
                RpcResponse::ok(0, json!(procs))
            }

            "threads" => {
                let pid = self.attached_pid.unwrap_or(0) as u32;
                let mut threads = Vec::new();
                if pid > 0 {
                    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
                    unsafe {
                        let h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                        if h != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                            let mut te: THREADENTRY32 = std::mem::zeroed();
                            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                            if Thread32First(h, &mut te) != 0 {
                                loop {
                                    if te.th32OwnerProcessID == pid {
                                        threads.push(json!({
                                            "id": te.th32ThreadID.to_string(),
                                            "name": None::<String>,
                                            "pc": None::<String>,
                                            "active": true
                                        }));
                                    }
                                    if Thread32Next(h, &mut te) == 0 {
                                        break;
                                    }
                                }
                            }
                            windows_sys::Win32::Foundation::CloseHandle(h);
                        }
                    }
                }
                RpcResponse::ok(0, json!(threads))
            }

            "modules" => {
                let pid = self.attached_pid.unwrap_or(0) as u32;
                let mut modules = Vec::new();
                if pid > 0 {
                    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
                    unsafe {
                        let h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
                        if h != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                            let mut me: MODULEENTRY32 = std::mem::zeroed();
                            me.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
                            if Module32First(h, &mut me) != 0 {
                                loop {
                                    let name = String::from_utf8_lossy(&me.szModule).trim_matches('\0').to_string();
                                    let path = String::from_utf8_lossy(&me.szExePath).trim_matches('\0').to_string();
                                    modules.push(json!({
                                        "name": name,
                                        "base": format!("{:X}", me.modBaseAddr as usize),
                                        "size": me.modBaseSize,
                                        "path": path
                                    }));
                                    if Module32Next(h, &mut me) == 0 {
                                        break;
                                    }
                                }
                            }
                            windows_sys::Win32::Foundation::CloseHandle(h);
                        }
                    }
                }
                RpcResponse::ok(0, json!(modules))
            }

            "callstack" => {
                let rip = get_rip();
                RpcResponse::ok(0, json!([
                    {
                        "addr": hex_u64(rip),
                        "name": "RIP",
                        "module": "",
                        "file": "",
                        "line": 0
                    }
                ]))
            }

            "memoryMap" => {
                let mut regions = Vec::new();
                unsafe {
                    let pi = TitanGetProcessInformation();
                    if !pi.is_null() && !(*pi).hProcess.is_null() {
                        let h_process = (*pi).hProcess;
                        use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
                        let mut addr = 0usize;
                        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                        while VirtualQueryEx(h_process, addr as *const _, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
                            let protect = mbi.Protect;
                            let state = mbi.State;
                            let mut perms = String::new();
                            if state == 0x1000 { // MEM_COMMIT
                                perms.push(if (protect & 0x04) != 0 || (protect & 0x20) != 0 || (protect & 0x40) != 0 { 'r' } else { '-' });
                                perms.push(if (protect & 0x04) != 0 || (protect & 0x40) != 0 { 'w' } else { '-' });
                                perms.push(if (protect & 0x20) != 0 || (protect & 0x40) != 0 || (protect & 0x10) != 0 { 'x' } else { '-' });
                                regions.push(json!({
                                    "addr": format!("{:X}", mbi.BaseAddress as usize),
                                    "size": mbi.RegionSize,
                                    "perms": perms,
                                    "desc": ""
                                }));
                            }
                            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
                        }
                    }
                }
                RpcResponse::ok(0, json!(regions))
            }
            
            "hwBpSet" => {
                let addr_str = param_str(&params, "addr").unwrap_or_default();
                let addr = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                if addr > 0 {
                    unsafe { SetHardwareBreakPoint(addr, 0, 0, 1, cb_custom_handler as *mut _) };
                }
                RpcResponse::ok(0, json!({ "success": true }))
            }

            "resolveSymbol" => {
                let module = param_str(&params, "module").unwrap_or_default();
                let symbol = param_str(&params, "symbol").unwrap_or_default();
                if symbol.is_empty() {
                    return RpcResponse::err(0, "bad_params", "resolveSymbol requires symbol");
                }
                unsafe {
                    let dll_name = if module.is_empty() { String::new() }
                        else if module.to_lowercase().ends_with(".dll") || module.to_lowercase().ends_with(".exe") {
                            module.clone()
                        } else {
                            format!("{}.dll", module)
                        };
                    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
                    use std::ffi::CString;
                    use std::os::windows::ffi::OsStrExt;
                    let wide_dll: Vec<u16> = std::ffi::OsStr::new(&dll_name).encode_wide().chain(std::iter::once(0)).collect();
                    let h = if dll_name.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        GetModuleHandleW(wide_dll.as_ptr())
                    };
                    if let Ok(sym_c) = CString::new(symbol.as_str()) {
                        let addr = GetProcAddress(h, sym_c.as_ptr() as *const _);
                        if let Some(f) = addr {
                            return RpcResponse::ok(0, json!(hex_u64(f as u64)));
                        }
                    }
                }
                RpcResponse::err(0, "not_found", "symbol not found")
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
