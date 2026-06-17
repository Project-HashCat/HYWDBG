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
    static ref LAST_CONTEXT: Mutex<RegDump> = Mutex::new(RegDump { arch: "x64".into(), registers: BTreeMap::new() });
}

// Ensure string is null-terminated for C FFI
fn c_str(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

extern "system" fn cb_entry_point() {
    update_last_context();
    let mut pid = 0;
    let mut h_process = 0;
    unsafe {
        let pi = TitanGetProcessInformation();
        if !pi.is_null() {
            pid = (*pi).dwProcessId;
            h_process = (*pi).hProcess as usize;
        }
    }
    send_event_and_wait(json!({
        "pid": pid,
        "hProcess": h_process,
        "stopped": true,
        "event": "breakpoint",
        "reason": "entry",
        "pc": hex_u64(get_rip())
    }));
}

extern "system" fn cb_system_breakpoint() {
    update_last_context();
    let mut pid = 0;
    let mut h_process = 0;
    unsafe {
        let pi = TitanGetProcessInformation();
        if !pi.is_null() {
            pid = (*pi).dwProcessId;
            h_process = (*pi).hProcess as usize;
        }
    }
    send_event_and_wait(json!({
        "pid": pid,
        "hProcess": h_process,
        "stopped": true,
        "event": "breakpoint",
        "reason": "system_bp",
        "pc": hex_u64(get_rip())
    }));
}

extern "system" fn cb_custom_handler() {
    update_last_context();
    let mut pid = 0;
    let mut h_process = 0;
    unsafe {
        let pi = TitanGetProcessInformation();
        if !pi.is_null() {
            pid = (*pi).dwProcessId;
            h_process = (*pi).hProcess as usize;
        }
    }
    send_event_and_wait(json!({
        "pid": pid,
        "hProcess": h_process,
        "stopped": true,
        "event": "breakpoint",
        "reason": "go",
        "pc": hex_u64(get_rip())
    }));
}

fn get_rip() -> u64 {
    let ctx = LAST_CONTEXT.lock().unwrap();
    if let Some(rip_str) = ctx.registers.get("rip") {
        u64::from_str_radix(rip_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0)
    } else {
        0
    }
}

fn update_last_context() {
    let mut r = RegDump {
        arch: "x64".into(),
        registers: BTreeMap::new(),
    };
    unsafe {
        r.registers.insert("rax".into(), hex_u64(GetContextData(17) as u64)); // UE_RAX = 17
        r.registers.insert("rcx".into(), hex_u64(GetContextData(19) as u64)); // UE_RCX = 19
        r.registers.insert("rdx".into(), hex_u64(GetContextData(20) as u64)); // UE_RDX = 20
        r.registers.insert("rbx".into(), hex_u64(GetContextData(18) as u64)); // UE_RBX = 18
        r.registers.insert("rsp".into(), hex_u64(GetContextData(24) as u64)); // UE_RSP = 24
        r.registers.insert("rbp".into(), hex_u64(GetContextData(23) as u64)); // UE_RBP = 23
        r.registers.insert("rsi".into(), hex_u64(GetContextData(22) as u64)); // UE_RSI = 22
        r.registers.insert("rdi".into(), hex_u64(GetContextData(21) as u64)); // UE_RDI = 21
        r.registers.insert("r8".into(), hex_u64(GetContextData(27) as u64));  // UE_R8 = 27
        r.registers.insert("r9".into(), hex_u64(GetContextData(28) as u64));  // UE_R9 = 28
        r.registers.insert("r10".into(), hex_u64(GetContextData(29) as u64)); // UE_R10 = 29
        r.registers.insert("r11".into(), hex_u64(GetContextData(30) as u64)); // UE_R11 = 30
        r.registers.insert("r12".into(), hex_u64(GetContextData(31) as u64)); // UE_R12 = 31
        r.registers.insert("r13".into(), hex_u64(GetContextData(32) as u64)); // UE_R13 = 32
        r.registers.insert("r14".into(), hex_u64(GetContextData(33) as u64)); // UE_R14 = 33
        r.registers.insert("r15".into(), hex_u64(GetContextData(34) as u64)); // UE_R15 = 34
        r.registers.insert("rip".into(), hex_u64(GetContextData(25) as u64)); // UE_RIP = 25
        r.registers.insert("rflags".into(), hex_u64(GetContextData(26) as u64)); // UE_RFLAGS = 26
    }
    *LAST_CONTEXT.lock().unwrap() = r;
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
    attached_hprocess: Option<windows_sys::Win32::Foundation::HANDLE>,
    launched_path: Option<String>,
    ev_rx: Option<Receiver<RpcResponse>>,
}

impl Default for BackendState {
    fn default() -> Self {
        Self {
            attached_pid: None,
            attached_hprocess: None,
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
                        if let Some(tx) = EVENT_TX.lock().unwrap().as_ref() {
                            let _ = tx.send(RpcResponse::ok(0, serde_json::json!({
                                "stopped": true,
                                "event": "exit_process",
                                "exitCode": 0
                            })));
                        }
                    }
                });

                if let Some(rx) = self.ev_rx.as_ref() {
                    eprintln!("[TITAN] Main thread waiting for rx.recv()...");
                    if let Ok(resp) = rx.recv_timeout(std::time::Duration::from_secs(10)) {
                        eprintln!("[TITAN] rx.recv() got response!");
                        if let Some(val) = resp.result.as_ref() {
                            if let Some(pid_val) = val.get("pid") {
                                if let Some(pid) = pid_val.as_u64() {
                                    self.attached_pid = Some(pid);
                                }
                            }
                            if let Some(hproc_val) = val.get("hProcess") {
                                if let Some(hproc) = hproc_val.as_u64() {
                                    if hproc != 0 {
                                        self.attached_hprocess = Some(hproc as windows_sys::Win32::Foundation::HANDLE);
                                    }
                                }
                            }
                        }
                        return resp;
                    } else {
                        eprintln!("[TITAN] rx.recv() TIMED OUT!");
                    }
                }
                RpcResponse::err(0, "launch_failed", "DebugLoop terminated early or timed out")
            }

            "attach" => {
                let pid = params.as_ref().and_then(|p| p.get("pid")).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
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
                        if !h.is_null() {
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
                let size = params.as_ref().and_then(|p| p.get("size")).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                
                let mut buf = vec![0u8; size as usize];
                let mut bytes_read: usize = 0;
                if let Some(h) = self.attached_hprocess {
                    unsafe {
                        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(h, addr as *const _, buf.as_mut_ptr() as *mut _, size as usize, &mut bytes_read);
                    }
                }
                if bytes_read == 0 {
                    if let Some(pid) = self.attached_pid {
                        unsafe {
                            let h = windows_sys::Win32::System::Threading::OpenProcess(windows_sys::Win32::System::Threading::PROCESS_VM_READ, 0, pid as u32);
                            if h != 0 {
                                windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(h, addr as *const _, buf.as_mut_ptr() as *mut _, size as usize, &mut bytes_read);
                                windows_sys::Win32::Foundation::CloseHandle(h);
                            }
                        }
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
                
                let mut bytes_written: usize = 0;
                if let Some(h) = self.attached_hprocess {
                    unsafe {
                        windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(h, addr as *const _, bytes.as_ptr() as *const _, bytes.len() as usize, &mut bytes_written);
                    }
                }
                if bytes_written == 0 {
                    if let Some(pid) = self.attached_pid {
                        unsafe {
                            let h = windows_sys::Win32::System::Threading::OpenProcess(windows_sys::Win32::System::Threading::PROCESS_VM_WRITE | windows_sys::Win32::System::Threading::PROCESS_VM_OPERATION, 0, pid as u32);
                            if h != 0 {
                                windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(h, addr as *const _, bytes.as_ptr() as *const _, bytes.len() as usize, &mut bytes_written);
                                windows_sys::Win32::Foundation::CloseHandle(h);
                            }
                        }
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
                let ctx = LAST_CONTEXT.lock().unwrap();
                RpcResponse::ok(0, serde_json::to_value(&*ctx).unwrap())
            }

            "disasm" => {
                let addr_str = param_str(&params, "addr").unwrap_or_default();
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
                let mut bytes_read: usize = 0;

                if let Some(h) = self.attached_hprocess {
                    unsafe {
                        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(h, addr as *const _, buf.as_mut_ptr() as *mut _, read_size as usize, &mut bytes_read);
                    }
                }
                if bytes_read == 0 {
                    if let Some(pid) = self.attached_pid {
                        unsafe {
                            let h = windows_sys::Win32::System::Threading::OpenProcess(windows_sys::Win32::System::Threading::PROCESS_VM_READ, 0, pid as u32);
                            if h != 0 {
                                windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(h, addr as *const _, buf.as_mut_ptr() as *mut _, read_size as usize, &mut bytes_read);
                                windows_sys::Win32::Foundation::CloseHandle(h);
                            }
                        }
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
                        "name": process.name().to_string(),
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
                                    let name_bytes = std::slice::from_raw_parts(me.szModule.as_ptr() as *const u8, 256);
                                    let path_bytes = std::slice::from_raw_parts(me.szExePath.as_ptr() as *const u8, 260);
                                    let name = String::from_utf8_lossy(name_bytes).trim_matches('\0').to_string();
                                    let path = String::from_utf8_lossy(path_bytes).trim_matches('\0').to_string();
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
                if let Some(pid) = self.attached_pid {
                    unsafe {
                        let h_process = OpenProcess(windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION, 0, pid as u32);
                        if !h_process.is_null() {
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
                            windows_sys::Win32::Foundation::CloseHandle(h_process);
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

fn main() -> anyhow::Result<()> {
    let (stdin_tx, stdin_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in std::io::BufRead::lines(stdin.lock()) {
            if let Ok(l) = line {
                if !l.trim().is_empty() {
                    let _ = stdin_tx.send(l);
                }
            }
        }
    });

    let mut state = BackendState::default();
    let mut stdout = std::io::stdout();
    let mut pending_cmd: Option<u64> = None;

    loop {
        if let Ok(line) = stdin_rx.try_recv() {
            if let Ok(req) = serde_json::from_str::<hywdbg_protocol::RpcRequest>(&line) {
                if req.method == "go" || req.method == "stepInto" || req.method == "stepOver" || req.method == "stepOut" {
                    if let Some(tx) = CMD_TX.lock().unwrap().as_ref() {
                        let _ = tx.send(req.method.clone());
                    }
                    pending_cmd = Some(req.id);
                } else {
                    use hywdbg_backend_common::BackendHandler;
                    let mut resp = state.handle(&req.method, req.params);
                    resp.id = req.id;
                    if let Ok(encoded) = serde_json::to_string(&resp) {
                        use std::io::Write;
                        let _ = writeln!(stdout, "{encoded}");
                        let _ = stdout.flush();
                    }
                }
            }
        }

        if let Some(rx) = state.ev_rx.as_ref() {
            if let Ok(mut resp) = rx.try_recv() {
                if let Some(val) = resp.result.as_ref() {
                    if let Some(pid_val) = val.get("pid") {
                        if let Some(pid) = pid_val.as_u64() {
                            state.attached_pid = Some(pid);
                        }
                    }
                    if let Some(hproc_val) = val.get("hProcess") {
                        if let Some(hproc) = hproc_val.as_u64() {
                            if hproc != 0 {
                                state.attached_hprocess = Some(hproc as windows_sys::Win32::Foundation::HANDLE);
                            }
                        }
                    }
                }

                if let Some(id) = pending_cmd.take() {
                    resp.id = id;
                    if let Ok(encoded) = serde_json::to_string(&resp) {
                        use std::io::Write;
                        let _ = writeln!(stdout, "{encoded}");
                        let _ = stdout.flush();
                    }
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
