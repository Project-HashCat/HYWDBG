use hywdbg_backend_common::{param_str, param_u64, run_stdio_backend, BackendHandler};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use hywdbg_protocol::{
    hex_u64, BackendCapabilities, DisasmLine, MemoryBlock, ModuleInfo, RegDump, RpcResponse,
    ThreadInfo,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, DBG_CONTINUE, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugBreakProcess,
    DebugSetProcessKillOnExit, FlushInstructionCache, GetThreadContext, ReadProcessMemory,
    SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT,
    CONTEXT_ALL_AMD64 as CONTEXT_ALL, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
    DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, UNLOAD_DLL_DEBUG_EVENT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Thread32First, Thread32Next,
    MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, OpenProcess, OpenThread, CREATE_NEW_CONSOLE, DEBUG_ONLY_THIS_PROCESS, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    STARTUPINFOW, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RESERVE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};


const BACKEND_KIND: &str = "winapi";
const BACKEND_NAME: &str = "HYWDbg WinAPI Backend";

fn last_error() -> String {
    unsafe { format!("GetLastError={}", GetLastError()) }
}

fn wide_z(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn wide_buf_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let clean = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if clean.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        out.push(u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

struct Breakpoint {
    addr: u64,
    original: u8,
}

struct BackendState {
    pid: Option<u32>,
    process: HANDLE,
    main_thread: HANDLE,
    active_tid: Option<u32>,
    threads: HashMap<u32, HANDLE>,
    last_event: Option<(u32, u32)>,
    next_bp: u64,
    bps: HashMap<u64, Breakpoint>,
}

impl Default for BackendState {
    fn default() -> Self {
        Self {
            pid: None,
            process: null_mut(),
            main_thread: null_mut(),
            active_tid: None,
            threads: HashMap::new(),
            last_event: None,
            next_bp: 1,
            bps: HashMap::new(),
        }
    }
}

impl Drop for BackendState {
    fn drop(&mut self) {
        self.close_all();
    }
}

impl BackendState {
    fn close_all(&mut self) {
        unsafe {
            for (_, h) in self.threads.drain() {
                if !h.is_null() {
                    CloseHandle(h);
                }
            }
            if !self.main_thread.is_null() {
                CloseHandle(self.main_thread);
                self.main_thread = null_mut();
            }
            if !self.process.is_null() {
                CloseHandle(self.process);
                self.process = null_mut();
            }
        }
        self.pid = None;
        self.active_tid = None;
        self.last_event = None;
        self.bps.clear();
    }

    fn ensure_process(&self) -> Result<HANDLE, String> {
        if self.process.is_null() {
            Err("no debuggee; call launch or attach first".into())
        } else {
            Ok(self.process)
        }
    }

    fn open_thread_handle(tid: u32) -> Option<HANDLE> {
        unsafe {
            let h = OpenThread(
                THREAD_GET_CONTEXT
                    | THREAD_SET_CONTEXT
                    | THREAD_SUSPEND_RESUME
                    | THREAD_QUERY_INFORMATION,
                0,
                tid,
            );
            if h.is_null() {
                None
            } else {
                Some(h)
            }
        }
    }

    fn refresh_threads(&mut self) {
        let Some(pid) = self.pid else {
            return;
        };
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return;
            }

            let mut seen = std::collections::HashSet::new();
            let mut te: THREADENTRY32 = zeroed();
            te.dwSize = size_of::<THREADENTRY32>() as u32;
            if Thread32First(snap, &mut te) != 0 {
                loop {
                    if te.th32OwnerProcessID == pid {
                        seen.insert(te.th32ThreadID);
                        if !self.threads.contains_key(&te.th32ThreadID) {
                            if let Some(h) = Self::open_thread_handle(te.th32ThreadID) {
                                self.threads.insert(te.th32ThreadID, h);
                            }
                        }
                    }
                    if Thread32Next(snap, &mut te) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);

            let stale = self
                .threads
                .keys()
                .copied()
                .filter(|tid| !seen.contains(tid))
                .collect::<Vec<_>>();
            for tid in stale {
                if let Some(h) = self.threads.remove(&tid) {
                    CloseHandle(h);
                }
            }

            if self.active_tid.is_none() {
                self.active_tid = self.threads.keys().next().copied();
            }
        }
    }

    fn active_thread_handle(&mut self) -> Result<HANDLE, String> {
        self.refresh_threads();
        if let Some(tid) = self.active_tid {
            if let Some(&h) = self.threads.get(&tid) {
                return Ok(h);
            }
        }
        if !self.main_thread.is_null() {
            return Ok(self.main_thread);
        }
        Err("no active thread handle".into())
    }

    fn wait_event(&mut self) -> Result<Value, String> {
        unsafe {
            let mut ev: DEBUG_EVENT = zeroed();
            if WaitForDebugEvent(&mut ev, u32::MAX) == 0 {
                return Err(format!("WaitForDebugEvent failed: {}", last_error()));
            }
            self.pid = Some(ev.dwProcessId);
            self.active_tid = Some(ev.dwThreadId);
            self.last_event = Some((ev.dwProcessId, ev.dwThreadId));

            let mut kind = "unknown".to_string();
            let mut extra = json!({});

            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    kind = "create_process".into();
                    let info = ev.u.CreateProcessInfo;
                    if self.process.is_null() {
                        self.process = info.hProcess;
                    }
                    if self.main_thread.is_null() {
                        self.main_thread = info.hThread;
                    }
                    self.threads.insert(ev.dwThreadId, info.hThread);
                    extra = json!({"image_base": hex_u64(info.lpBaseOfImage as u64)});
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    kind = "create_thread".into();
                    let info = ev.u.CreateThread;
                    self.threads.insert(ev.dwThreadId, info.hThread);
                    let start = info.lpStartAddress.map(|f| f as usize as u64).unwrap_or(0);
                    extra = json!({"start": hex_u64(start)});
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    kind = "exit_thread".into();
                    if let Some(h) = self.threads.remove(&ev.dwThreadId) {
                        CloseHandle(h);
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    kind = "exit_process".into();
                    extra = json!({"exit_code": ev.u.ExitProcess.dwExitCode});
                }
                LOAD_DLL_DEBUG_EVENT => {
                    kind = "load_dll".into();
                    let base = ev.u.LoadDll.lpBaseOfDll as u64;
                    let dll_name = if !self.process.is_null() {
                        let mut buf = [0u16; 512];
                        let n = GetModuleFileNameExW(
                            self.process,
                            ev.u.LoadDll.lpBaseOfDll as _,
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                        );
                        if n > 0 { wide_buf_to_string(&buf[..n as usize]) } else { String::new() }
                    } else { String::new() };
                    let basename = dll_name.rsplit(['\\','/']).next().unwrap_or("").to_string();
                    extra = json!({"base": hex_u64(base), "name": basename, "path": dll_name});
                }
                UNLOAD_DLL_DEBUG_EVENT => {
                    kind = "unload_dll".into();
                    extra = json!({"base": hex_u64(ev.u.UnloadDll.lpBaseOfDll as u64)});
                }
                OUTPUT_DEBUG_STRING_EVENT => {
                    kind = "debug_string".into();
                }
                RIP_EVENT => {
                    kind = "rip".into();
                }
                EXCEPTION_DEBUG_EVENT => {
                    let ex = ev.u.Exception.ExceptionRecord;
                    let code = ex.ExceptionCode;
                    kind = match code {
                        EXCEPTION_BREAKPOINT  => "breakpoint".into(),
                        EXCEPTION_SINGLE_STEP => "single_step".into(),
                        _                     => "exception".into(),
                    };
                    let desc = match code as u32 {
                        0x80000001 => "GUARD_PAGE_VIOLATION",
                        0x80000002 => "DATATYPE_MISALIGNMENT",
                        0x80000003 => "BREAKPOINT",
                        0x80000004 => "SINGLE_STEP",
                        0xC0000005 => "ACCESS_VIOLATION",
                        0xC0000006 => "IN_PAGE_ERROR",
                        0xC0000008 => "INVALID_HANDLE",
                        0xC000000D => "INVALID_PARAMETER",
                        0xC0000017 => "NO_MEMORY",
                        0xC000001D => "ILLEGAL_INSTRUCTION",
                        0xC0000025 => "NONCONTINUABLE_EXCEPTION",
                        0xC0000029 => "INVALID_UNWIND_TARGET",
                        0xC000002A => "ARRAY_BOUNDS_EXCEEDED",
                        0xC000008C => "ARRAY_BOUNDS_EXCEEDED",
                        0xC0000094 => "INT_DIVIDE_BY_ZERO",
                        0xC0000095 => "INT_OVERFLOW",
                        0xC0000096 => "PRIVILEGED_INSTRUCTION",
                        0xC00000FD => "STACK_OVERFLOW",
                        0xC0000135 => "DLL_NOT_FOUND",
                        0xC0000138 => "ORDINAL_NOT_FOUND",
                        0xC0000139 => "ENTRYPOINT_NOT_FOUND",
                        0xC000013A => "CTRL_C_EXIT",
                        0xC0000142 => "DLL_INIT_FAILED",
                        0xE06D7363 => "CXX_EXCEPTION (thrown C++ exception)",
                        0x406D1388 => "THREAD_NAME_EXCEPTION (debug)",
                        _ => "",
                    };

                    extra = json!({
                        "code": format!("0x{code:08X}"),
                        "address": hex_u64(ex.ExceptionAddress as u64),
                        "first_chance": ev.u.Exception.dwFirstChance != 0,
                        "description": desc,
                    });
                }
                _ => {}
            }

            let mut res = json!({"stopped": true, "event": kind, "pid": ev.dwProcessId, "tid": ev.dwThreadId});
            if let Some(map) = res.as_object_mut() {
                if let Some(extra_map) = extra.as_object() {
                    for (k, v) in extra_map {
                        map.insert(k.clone(), v.clone());
                    }
                }
            }
            Ok(res)
        }
    }

    fn continue_last_and_wait(&mut self) -> Result<Value, String> {
        unsafe {
            if let Some((pid, tid)) = self.last_event.take() {
                if ContinueDebugEvent(pid, tid, DBG_CONTINUE) == 0 {
                    return Err(format!("ContinueDebugEvent failed: {}", last_error()));
                }
            }
        }
        self.wait_event()
    }

    fn get_context(&mut self) -> Result<CONTEXT, String> {
        unsafe {
            let h = self.active_thread_handle()?;
            let mut ctx: CONTEXT = zeroed();
            ctx.ContextFlags = CONTEXT_ALL;
            if GetThreadContext(h, &mut ctx) == 0 {
                return Err(format!("GetThreadContext failed: {}", last_error()));
            }
            Ok(ctx)
        }
    }

    fn set_context(&mut self, ctx: &CONTEXT) -> Result<(), String> {
        unsafe {
            let h = self.active_thread_handle()?;
            if SetThreadContext(h, ctx) == 0 {
                return Err(format!("SetThreadContext failed: {}", last_error()));
            }
            Ok(())
        }
    }

    fn read_bytes(&self, addr: u64, size: usize) -> Result<Vec<u8>, String> {
        unsafe {
            let process = self.ensure_process()?;
            let mut buf = vec![0u8; size];
            let mut read = 0usize;
            if ReadProcessMemory(process, addr as _, buf.as_mut_ptr() as _, size, &mut read) == 0 {
                return Err(format!(
                    "ReadProcessMemory failed at {}: {}",
                    hex_u64(addr),
                    last_error()
                ));
            }
            buf.truncate(read);
            Ok(buf)
        }
    }

    fn write_bytes(&self, addr: u64, bytes: &[u8]) -> Result<usize, String> {
        unsafe {
            let process = self.ensure_process()?;
            let mut written = 0usize;
            if WriteProcessMemory(
                process,
                addr as _,
                bytes.as_ptr() as _,
                bytes.len(),
                &mut written,
            ) == 0
            {
                return Err(format!(
                    "WriteProcessMemory failed at {}: {}",
                    hex_u64(addr),
                    last_error()
                ));
            }
            FlushInstructionCache(process, addr as _, bytes.len());
            Ok(written)
        }
    }

    fn regs(&mut self) -> Result<RegDump, String> {
        let ctx = self.get_context()?;
        let mut r = BTreeMap::new();
        macro_rules! reg {
            ($name:literal, $field:ident) => {
                r.insert($name.to_string(), hex_u64(ctx.$field));
            };
        }
        reg!("rax", Rax);
        reg!("rbx", Rbx);
        reg!("rcx", Rcx);
        reg!("rdx", Rdx);
        reg!("rsi", Rsi);
        reg!("rdi", Rdi);
        reg!("rbp", Rbp);
        reg!("rsp", Rsp);
        reg!("r8", R8);
        reg!("r9", R9);
        reg!("r10", R10);
        reg!("r11", R11);
        reg!("r12", R12);
        reg!("r13", R13);
        reg!("r14", R14);
        reg!("r15", R15);
        reg!("rip", Rip);
        r.insert("eflags".to_string(), format!("0x{:08x}", ctx.EFlags));
        Ok(RegDump {
            arch: "x64".into(),
            registers: r,
        })
    }

    fn set_reg(&mut self, name: &str, value: u64) -> Result<(), String> {
        let mut ctx = self.get_context()?;
        match name.to_ascii_lowercase().as_str() {
            "rax" => ctx.Rax = value,
            "rbx" => ctx.Rbx = value,
            "rcx" => ctx.Rcx = value,
            "rdx" => ctx.Rdx = value,
            "rsi" => ctx.Rsi = value,
            "rdi" => ctx.Rdi = value,
            "rbp" => ctx.Rbp = value,
            "rsp" => ctx.Rsp = value,
            "r8" => ctx.R8 = value,
            "r9" => ctx.R9 = value,
            "r10" => ctx.R10 = value,
            "r11" => ctx.R11 = value,
            "r12" => ctx.R12 = value,
            "r13" => ctx.R13 = value,
            "r14" => ctx.R14 = value,
            "r15" => ctx.R15 = value,
            "rip" | "pc" => ctx.Rip = value,
            _ => return Err(format!("unknown x64 register {name}")),
        }
        self.set_context(&ctx)
    }

    fn set_single_step(&mut self) -> Result<(), String> {
        let mut ctx = self.get_context()?;
        ctx.EFlags |= 0x100;
        self.set_context(&ctx)
    }

    fn modules(&self) -> Vec<ModuleInfo> {
        let mut out = Vec::new();
        let Some(pid) = self.pid else {
            return out;
        };
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut me: MODULEENTRY32W = zeroed();
            me.dwSize = size_of::<MODULEENTRY32W>() as u32;
            if Module32FirstW(snap, &mut me) != 0 {
                loop {
                    out.push(ModuleInfo {
                        name: wide_buf_to_string(&me.szModule),
                        base: hex_u64(me.modBaseAddr as u64),
                        size: me.modBaseSize as u64,
                        path: Some(wide_buf_to_string(&me.szExePath)),
                    });
                    if Module32NextW(snap, &mut me) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        out
    }
}

impl BackendHandler for BackendState {
    fn handle(&mut self, method: &str, params: Option<Value>) -> RpcResponse {
        macro_rules! rpc_try {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(e) => return RpcResponse::err(0, "winapi_error", e),
                }
            };
        }

        let result: Result<Value, String> = match method {
            "hello" => Ok(
                json!({"name":BACKEND_NAME,"kind":BACKEND_KIND,"mode":"stdio-backend","real":true,"debug_api":"Windows Debug API"}),
            ),
            "capabilities" => {
                return RpcResponse::ok(
                    0,
                    BackendCapabilities {
                        name: BACKEND_NAME.into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        backend_kind: BACKEND_KIND.into(),
                        supported_arches: vec!["x64".into()],
                        features: vec![
                            "real-winapi-debugloop".into(),
                            "launch".into(),
                            "attach".into(),
                            "go".into(),
                            "pause".into(),
                            "single-step".into(),
                            "read-process-memory".into(),
                            "write-process-memory".into(),
                            "get-thread-context".into(),
                            "set-thread-context".into(),
                            "software-breakpoint-int3".into(),
                            "threads".into(),
                            "modules".into(),
                        ],
                    },
                )
            }
            "launch" => {
                let Some(path) = param_str(&params, "path") else {
                    return RpcResponse::err(0, "bad_params", "launch requires {path}");
                };
                self.close_all();
                unsafe {
                    let mut si: STARTUPINFOW = zeroed();
                    let mut pi: PROCESS_INFORMATION = zeroed();
                    si.cb = size_of::<STARTUPINFOW>() as u32;
                    let mut cmd = wide_z(&path);
                    if CreateProcessW(
                        null(),
                        cmd.as_mut_ptr(),
                        null(),
                        null(),
                        0,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                        null(),
                        null(),
                        &si,
                        &mut pi,
                    ) == 0
                    {
                        return RpcResponse::err(0, "launch_failed", last_error());
                    }
                    self.pid = Some(pi.dwProcessId);
                    self.process = pi.hProcess;
                    self.main_thread = pi.hThread;
                    self.active_tid = Some(pi.dwThreadId);
                    self.threads.insert(pi.dwThreadId, pi.hThread);
                }
                self.wait_event()
            }
            "attach" => {
                let pid = match param_u64(&params, "pid") {
                    Ok(Some(x)) => x as u32,
                    _ => return RpcResponse::err(0, "bad_params", "attach requires {pid}"),
                };
                self.close_all();
                unsafe {
                    let process = OpenProcess(
                        PROCESS_QUERY_INFORMATION
                            | PROCESS_VM_READ
                            | PROCESS_VM_WRITE
                            | PROCESS_VM_OPERATION,
                        0,
                        pid,
                    );
                    if process.is_null() {
                        return RpcResponse::err(0, "open_process_failed", last_error());
                    }
                    if DebugActiveProcess(pid) == 0 {
                        CloseHandle(process);
                        return RpcResponse::err(0, "attach_failed", last_error());
                    }
                    DebugSetProcessKillOnExit(0);
                    self.pid = Some(pid);
                    self.process = process;
                }
                self.refresh_threads();
                self.wait_event()
            }
            "detach" => {
                if let Some(pid) = self.pid {
                    unsafe {
                        DebugActiveProcessStop(pid);
                    }
                }
                self.close_all();
                Ok(json!({"detached":true}))
            }
            "shutdown" => {
                if let Some(pid) = self.pid {
                    unsafe {
                        DebugActiveProcessStop(pid);
                    }
                }
                self.close_all();
                Ok(json!({"bye":true}))
            }
            "pause" => {
                unsafe {
                    let process = rpc_try!(self.ensure_process());
                    if DebugBreakProcess(process) == 0 {
                        return RpcResponse::err(0, "pause_failed", last_error());
                    }
                }
                self.wait_event()
            }
            "go" => self.continue_last_and_wait(),
            "stepInto" | "stepOver" | "stepOut" => {
                rpc_try!(self.set_single_step());
                self.continue_last_and_wait()
            }
            "regs" => {
                return match self.regs() {
                    Ok(x) => RpcResponse::ok(0, x),
                    Err(e) => RpcResponse::err(0, "regs_failed", e),
                }
            }
            "setReg" => {
                let Some(name) = param_str(&params, "name") else {
                    return RpcResponse::err(0, "bad_params", "setReg requires {name,value}");
                };
                let Some(value) = params.as_ref().and_then(|p| p.get("value")) else {
                    return RpcResponse::err(0, "bad_params", "setReg requires {name,value}");
                };
                let value = rpc_try!(hywdbg_protocol::parse_u64ish(value));
                rpc_try!(self.set_reg(&name, value));
                Ok(json!({"set":true,"name":name,"value":hex_u64(value)}))
            }
            "readMem" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "readMem requires {addr,size}"),
                };
                let size = match param_u64(&params, "size") {
                    Ok(Some(x)) => x.min(65536) as usize,
                    _ => return RpcResponse::err(0, "bad_params", "readMem requires {addr,size}"),
                };
                let bytes = rpc_try!(self.read_bytes(addr, size));
                Ok(serde_json::to_value(MemoryBlock {
                    addr: hex_u64(addr),
                    size: bytes.len(),
                    hex: bytes.iter().map(|b| format!("{b:02x}")).collect(),
                })
                .unwrap())
            }
            "writeMem" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "writeMem requires {addr,hex}"),
                };
                let hex = param_str(&params, "hex").unwrap_or_default();
                let bytes = rpc_try!(parse_hex_bytes(&hex));
                let written = rpc_try!(self.write_bytes(addr, &bytes));
                Ok(json!({"written":written,"addr":hex_u64(addr)}))
            }
            "disasm" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => self.get_context().map(|c| c.Rip).unwrap_or(0),
                };
                let count = match param_u64(&params, "count") {
                    Ok(Some(x)) => x.min(96) as usize,
                    _ => 32,
                };

                let bytes = self.read_bytes(addr, count * 16).unwrap_or_default();
                let mut decoder = Decoder::with_ip(64, &bytes, addr, DecoderOptions::NONE);
                let mut formatter = NasmFormatter::new();
                formatter.options_mut().set_digit_separator("`");
                formatter.options_mut().set_first_operand_char_index(8);

                let mut lines = Vec::new();
                while decoder.can_decode() && lines.len() < count {
                    let start_ip = decoder.ip();
                    let offset = (start_ip.saturating_sub(addr)) as usize;
                    let instr = decoder.decode();
                    if instr.is_invalid() {
                        break;
                    }
                    let len = instr.len() as usize;
                    let raw = if offset < bytes.len() {
                        &bytes[offset..bytes.len().min(offset + len)]
                    } else {
                        &[]
                    };
                    let mut formatted = String::new();
                    formatter.format(&instr, &mut formatted);
                    lines.push(DisasmLine {
                        addr: hex_u64(start_ip),
                        bytes: raw.iter().map(|b| format!("{b:02x}")).collect(),
                        text: formatted,
                    });
                }

                return RpcResponse::ok(0, lines);
            }
            "bpList" => {
                let list: Vec<_> = self.bps.iter().map(|(&id, bp)| {
                    json!({
                        "id": id,
                        "addr": hex_u64(bp.addr),
                        "kind": "int3",
                        "enabled": true,
                        "hit_count": 0
                    })
                }).collect();
                Ok(json!({"breakpoints": list}))
            }
            "bpSet" => {
                let addr = match param_u64(&params, "addr") {
                    Ok(Some(x)) => x,
                    _ => return RpcResponse::err(0, "bad_params", "bpSet requires {addr}"),
                };
                let old = rpc_try!(self.read_bytes(addr, 1).and_then(|bytes| bytes
                     .first()
                     .copied()
                     .ok_or_else(|| "cannot read original byte".to_string())));
                rpc_try!(self.write_bytes(addr, &[0xcc]));
                let id = self.next_bp;
                self.next_bp += 1;
                self.bps.insert(
                    id,
                    Breakpoint {
                        addr,
                        original: old,
                    },
                );
                Ok(
                    json!({"id":id,"addr":hex_u64(addr),"enabled":true,"kind":"software-int3","original":format!("0x{old:02x}")}),
                )
            }
            "bpClear" => {
                let id_opt = param_u64(&params, "id").ok().flatten();
                let addr_opt = param_u64(&params, "addr").ok().flatten();
                let all_opt = params.as_ref().and_then(|p| p.get("all")).and_then(|v| v.as_bool()).unwrap_or(false);

                if all_opt {
                    let mut cleared_count = 0;
                    let ids: Vec<u64> = self.bps.keys().copied().collect();
                    for id in ids {
                        if let Some(bp) = self.bps.remove(&id) {
                            let _ = self.write_bytes(bp.addr, &[bp.original]);
                            cleared_count += 1;
                        }
                    }
                    Ok(json!({"cleared": true, "count": cleared_count, "all": true}))
                } else if let Some(id) = id_opt {
                    if let Some(bp) = self.bps.remove(&id) {
                        let _ = self.write_bytes(bp.addr, &[bp.original]);
                        Ok(json!({"cleared":true,"id":id,"addr":hex_u64(bp.addr)}))
                    } else {
                        Ok(json!({"cleared":false,"id":id}))
                    }
                } else if let Some(addr) = addr_opt {
                    let target_id = self.bps.iter().find(|(_, bp)| bp.addr == addr).map(|(&id, _)| id);
                    if let Some(id) = target_id {
                        let bp = self.bps.remove(&id).unwrap();
                        let _ = self.write_bytes(bp.addr, &[bp.original]);
                        Ok(json!({"cleared":true,"id":id,"addr":hex_u64(bp.addr)}))
                    } else {
                        Ok(json!({"cleared":false,"addr":hex_u64(addr)}))
                    }
                } else {
                    return RpcResponse::err(0, "bad_params", "bpClear requires id, addr, or all");
                }
            }
            "callstack" => {
                Ok(json!([]))
            }
            "memoryMap" => {
                unsafe {
                    let process = rpc_try!(self.ensure_process());
                    let mut regions = Vec::new();
                    let mut addr: usize = 0;
                    let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
                    while VirtualQueryEx(process, addr as _, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
                        let state = match mbi.State {
                            MEM_COMMIT => "Commit",
                            MEM_FREE => "Free",
                            MEM_RESERVE => "Reserve",
                            _ => "Unknown"
                        };
                        let protect = match mbi.Protect {
                            PAGE_EXECUTE => "E",
                            PAGE_EXECUTE_READ => "ER",
                            PAGE_EXECUTE_READWRITE => "ERW",
                            PAGE_EXECUTE_WRITECOPY => "ERWC",
                            PAGE_NOACCESS => "---",
                            PAGE_READONLY => "R",
                            PAGE_READWRITE => "RW",
                            PAGE_WRITECOPY => "RWC",
                            _ => ""
                        };
                        let type_ = match mbi.Type {
                            0x20000 => "Private", // MEM_PRIVATE
                            0x40000 => "Mapped",  // MEM_MAPPED
                            0x1000000 => "Image", // MEM_IMAGE
                            _ => ""
                        };
                        
                        let mut name = String::new();
                        if state == "Commit" {
                            let mut buf = [0u16; 512];
                            if GetModuleFileNameExW(process, mbi.AllocationBase as _, buf.as_mut_ptr(), buf.len() as u32) > 0 {
                                name = wide_buf_to_string(&buf).rsplit(['\\','/']).next().unwrap_or("").to_string();
                            }
                        }

                        regions.push(json!({
                            "base": hex_u64(mbi.BaseAddress as u64),
                            "size": hex_u64(mbi.RegionSize as u64),
                            "protect": protect,
                            "state": state,
                            "type": type_,
                            "name": name
                        }));
                        
                        let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize as usize);
                        if next_addr <= addr { break; } // overflow or error
                        addr = next_addr;
                    }
                    Ok(json!(regions))
                }
            }
            "searchMem" => {
                let pattern_str = param_str(&params, "pattern").unwrap_or_default();
                let start_addr = param_u64(&params, "start").ok().flatten().unwrap_or(0);
                let end_addr = param_u64(&params, "end").ok().flatten().unwrap_or(u64::MAX);

                let mut pattern = Vec::new();
                for p in pattern_str.split_whitespace() {
                    if p == "?" || p == "??" {
                        pattern.push(None);
                    } else if let Ok(b) = u8::from_str_radix(p, 16) {
                        pattern.push(Some(b));
                    } else {
                        return RpcResponse::err(0, "bad_params", format!("Invalid pattern byte: {}", p));
                    }
                }

                if pattern.is_empty() {
                    return RpcResponse::err(0, "bad_params", "Empty pattern");
                }

                let mut results = Vec::new();
                unsafe {
                    let process = rpc_try!(self.ensure_process());
                    let mut addr: usize = start_addr as usize;
                    let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
                    while VirtualQueryEx(process, addr as _, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
                        let base = mbi.BaseAddress as usize;
                        let size = mbi.RegionSize as usize;
                        let next_addr = base.saturating_add(size);
                        
                        if (base as u64) >= end_addr { break; }

                        if mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_NOACCESS) == 0 {
                            let overlap_start = (base as u64).max(start_addr);
                            let overlap_end = (next_addr as u64).min(end_addr);
                            
                            if overlap_start < overlap_end {
                                let mut buf = vec![0u8; (overlap_end - overlap_start) as usize];
                                let mut read = 0;
                                if ReadProcessMemory(process, overlap_start as _, buf.as_mut_ptr() as _, buf.len(), &mut read) != 0 {
                                    buf.truncate(read);
                                    let pat_len = pattern.len();
                                    if buf.len() >= pat_len {
                                        for i in 0..=(buf.len() - pat_len) {
                                            let mut matched = true;
                                            for j in 0..pat_len {
                                                if let Some(b) = pattern[j] {
                                                    if buf[i + j] != b {
                                                        matched = false;
                                                        break;
                                                    }
                                                }
                                            }
                                            if matched {
                                                results.push(hex_u64(overlap_start + i as u64));
                                                if results.len() >= 1000 { break; }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if results.len() >= 1000 { break; }
                        if next_addr <= addr { break; }
                        addr = next_addr;
                    }
                }
                Ok(json!(results))
            }
            "processList" => {
                Ok(json!([]))
            }
            "threads" => {
                self.refresh_threads();
                let active = self.active_tid;
                return RpcResponse::ok(
                    0,
                    self.threads
                        .keys()
                        .copied()
                        .map(|tid| ThreadInfo {
                            id: tid.to_string(),
                            name: None,
                            pc: None,
                            active: Some(tid) == active,
                        })
                        .collect::<Vec<_>>(),
                );
            }
            "modules" => return RpcResponse::ok(0, self.modules()),
            "resolveSymbol" => {
                let module = param_str(&params, "module").unwrap_or_default();
                let symbol = param_str(&params, "symbol").unwrap_or_default();
                if symbol.is_empty() {
                    return RpcResponse::err(0, "bad_params", "resolveSymbol requires {symbol}");
                }
                unsafe {
                    let dll_name = if module.is_empty() { String::new() }
                        else if module.to_lowercase().ends_with(".dll") || module.to_lowercase().ends_with(".exe") {
                            module.clone()
                        } else {
                            format!("{}.dll", module)
                        };
                    let h = if dll_name.is_empty() {
                        null_mut()
                    } else {
                        GetModuleHandleW(wide_z(&dll_name).as_ptr())
                    };
                    let sym_c = match std::ffi::CString::new(symbol.as_str()) {
                        Ok(c) => c,
                        Err(_) => return RpcResponse::err(0, "bad_params", "invalid symbol name"),
                    };
                    match GetProcAddress(h, sym_c.as_ptr() as _) {
                        Some(f) => {
                            let addr = f as u64;
                            return RpcResponse::ok(0, json!({
                                "addr": hex_u64(addr),
                                "symbol": symbol,
                                "module": module,
                                "resolved": true
                            }));
                        }
                        None => return RpcResponse::err(0, "symbol_not_found",
                            format!("symbol '{}' not found in '{}'" , symbol,
                                    if module.is_empty() { "process" } else { &module })),
                    }
                }
            }
            other => {
                return RpcResponse::err(
                    0,
                    "unknown_method",
                    format!("{BACKEND_KIND} backend does not implement {other}"),
                )
            }
        };

        match result {
            Ok(v) => RpcResponse::ok(0, v),
            Err(e) => RpcResponse::err(0, "winapi_error", e),
        }
    }
}

pub fn main_impl() -> anyhow::Result<()> {
    run_stdio_backend(BackendState::default())
}
