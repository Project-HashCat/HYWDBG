use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use slint::{ComponentHandle, SharedString, Weak};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

slint::include_modules!();

const RPC_ADDR: &str = "127.0.0.1:31338";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct UiPatch {
    status: Option<String>,
    core: Option<String>,
    backend: Option<String>,
    pid: Option<String>,
    tid: Option<String>,
    arch: Option<String>,
    target: Option<String>,
    processes: Option<String>,
    modules: Option<String>,
    threads: Option<String>,
    breakpoints: Option<String>,
    memory_map: Option<String>,
    pc: Option<String>,
    disasm_addr: Option<String>,
    disasm_bytes: Option<String>,
    disasm_mnemonic: Option<String>,
    disasm_operand: Option<String>,
    disasm_comment: Option<String>,
    regs: Option<String>,
    flags: Option<String>,
    stack: Option<String>,
    hex: Option<String>,
    log: Option<String>,
}

fn now_tag() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 86400;
    format!("[{:02}:{:02}:{:02}]", s / 3600, (s / 60) % 60, s % 60)
}

fn append_log(current: &str, msg: impl AsRef<str>) -> String {
    let mut lines = current.lines().map(str::to_string).collect::<Vec<_>>();
    for line in msg.as_ref().lines() {
        lines.push(format!("{} {}", now_tag(), line));
    }
    if lines.len() > 120 {
        lines = lines.split_off(lines.len() - 120);
    }
    lines.join("\n")
}

fn apply(ui: &MainWindow, p: UiPatch) {
    if let Some(v) = p.status { ui.set_status_text(v.into()); }
    if let Some(v) = p.core { ui.set_core_state(v.into()); }
    if let Some(v) = p.backend { ui.set_backend_state(v.into()); }
    if let Some(v) = p.pid { ui.set_pid_text(v.into()); }
    if let Some(v) = p.tid { ui.set_tid_text(v.into()); }
    if let Some(v) = p.arch { ui.set_arch_text(v.into()); }
    if let Some(v) = p.target { ui.set_target_text(v.into()); }
    if let Some(v) = p.processes { ui.set_processes_text(v.into()); }
    if let Some(v) = p.modules { ui.set_modules_text(v.into()); }
    if let Some(v) = p.threads { ui.set_threads_text(v.into()); }
    if let Some(v) = p.breakpoints { ui.set_breakpoints_text(v.into()); }
    if let Some(v) = p.memory_map { ui.set_memory_map_text(v.into()); }
    if let Some(v) = p.pc { ui.set_pc_text(v.into()); }
    if let Some(v) = p.disasm_addr { ui.set_disasm_addr_text(v.into()); }
    if let Some(v) = p.disasm_bytes { ui.set_disasm_bytes_text(v.into()); }
    if let Some(v) = p.disasm_mnemonic { ui.set_disasm_mnemonic_text(v.into()); }
    if let Some(v) = p.disasm_operand { ui.set_disasm_operand_text(v.into()); }
    if let Some(v) = p.disasm_comment { ui.set_disasm_comment_text(v.into()); }
    if let Some(v) = p.regs { ui.set_regs_text(v.into()); }
    if let Some(v) = p.flags { ui.set_flags_text(v.into()); }
    if let Some(v) = p.stack { ui.set_stack_text(v.into()); }
    if let Some(v) = p.hex { ui.set_hex_text(v.into()); }
    if let Some(v) = p.log { ui.set_log_text(v.into()); }
}

fn with_ui<F>(weak: Weak<MainWindow>, work: F)
where
    F: FnOnce() -> UiPatch + Send + 'static,
{
    thread::spawn(move || {
        let patch = work();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                let mut patch = patch;
                if let Some(add) = patch.log.take() {
                    let old = ui.get_log_text().to_string();
                    patch.log = Some(append_log(&old, add));
                }
                apply(&ui, patch);
            }
        });
    });
}

fn rpc(method: &str, params: Value) -> Result<Value> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let body = json!({"id": id, "method": method, "params": params}).to_string();

    let mut stream = TcpStream::connect(RPC_ADDR)
        .map_err(|e| anyhow!("core HTTP offline at http://{RPC_ADDR}/rpc: {e}"))?;
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: {RPC_ADDR}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.as_bytes().len(),
        body
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (_, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("bad HTTP response"))?;
    let obj: Value = serde_json::from_str(body)?;
    if obj.get("ok").and_then(Value::as_bool) != Some(true) {
        let msg = obj
            .get("error")
            .and_then(|e| e.get("message").or(Some(e)))
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown error".into());
        return Err(anyhow!("{method} failed: {msg}"));
    }
    Ok(obj.get("result").cloned().unwrap_or(Value::Null))
}

fn rpc_ignore_already_active(method: &str, params: Value) -> Result<Value> {
    match rpc(method, params) {
        Ok(v) => Ok(v),
        Err(e) if e.to_string().contains("already active") => Ok(json!({"already_active": true})),
        Err(e) => Err(e),
    }
}

fn ensure_winapi() -> Result<()> {
    rpc_ignore_already_active("core.startBackend", json!({"kind":"winapi"}))?;
    Ok(())
}

fn parse_u64(s: &str) -> Result<u64> {
    let s = s.trim().trim_matches('"');
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(rest, 16)?)
    } else {
        Ok(s.parse()?)
    }
}

fn pretty_addr(s: &str) -> String {
    let Ok(v) = parse_u64(s) else { return s.to_string(); };
    let hi = (v >> 32) as u32;
    let lo = (v & 0xffff_ffff) as u32;
    format!("{:08X}`{:08X}", hi, lo)
}

fn spaced_hex(hex: &str) -> String {
    let clean = hex.trim();
    let mut out = String::new();
    for i in (0..clean.len()).step_by(2) {
        if i > 0 { out.push(' '); }
        out.push_str(&clean[i..clean.len().min(i + 2)].to_uppercase());
    }
    out
}

fn hex_to_lines(addr: &str, hex: &str) -> String {
    let base = parse_u64(addr).unwrap_or(0);
    let bytes = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..hex.len().min(i + 2)], 16).ok())
        .collect::<Vec<_>>();
    let mut out = String::new();
    out.push_str("Address             00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII\n");
    for (row, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{}  ", pretty_addr(&format!("0x{:x}", base + (row * 16) as u64))));
        for b in chunk {
            out.push_str(&format!("{b:02X} "));
        }
        for _ in chunk.len()..16 { out.push_str("   "); }
        out.push(' ');
        for b in chunk {
            out.push(if (0x20..=0x7e).contains(b) { *b as char } else { '.' });
        }
        out.push('\n');
    }
    out
}

fn format_regs(v: &Value) -> (String, String, String, String, String) {
    let arch = v.get("arch").and_then(Value::as_str).unwrap_or("x64").to_string();
    let regs = v.get("registers").and_then(Value::as_object);

    let names = [
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip","r8","r9","r10","r11","r12","r13","r14","r15",
    ];
    let mut out = String::new();
    let mut rip = "0x0000000000000000".to_string();
    let mut rsp = "0x0000000000000000".to_string();
    for n in names {
        let val = regs
            .and_then(|m| m.get(n))
            .and_then(Value::as_str)
            .unwrap_or("0x0000000000000000");
        if n == "rip" { rip = val.to_string(); }
        if n == "rsp" { rsp = val.to_string(); }
        out.push_str(&format!("{:<4}  {}\n", n.to_uppercase(), pretty_addr(val)));
    }
    let flags = format!(
        "RFLAGS {}\nCF 0 PF 0 AF 0 ZF 0 SF 0\nTF 0 IF 1 DF 0 OF 0 NT 0",
        regs.and_then(|m| m.get("eflags").or_else(|| m.get("rflags")))
            .and_then(Value::as_str)
            .unwrap_or("0x0000000000000000")
    );
    (arch, out, flags, rip, rsp)
}

fn format_modules(v: &Value) -> (String, String) {
    let mut out = String::from("Base               Module                  Size\n");
    let mut first = "debuggee".to_string();
    if let Some(arr) = v.as_array() {
        for (idx, m) in arr.iter().take(64).enumerate() {
            let name = m.get("name").and_then(Value::as_str).unwrap_or("-");
            if idx == 0 { first = name.to_string(); }
            out.push_str(&format!(
                "{:<18} {:<23} {:08X}\n",
                pretty_addr(m.get("base").and_then(Value::as_str).unwrap_or("0x0")).replace("00000000`", ""),
                name,
                m.get("size").and_then(Value::as_u64).unwrap_or(0)
            ));
        }
    }
    (out, first)
}

fn format_threads(v: &Value) -> (String, String) {
    let mut out = String::from("TID      PC                State\n");
    let mut tid = "----".to_string();
    if let Some(arr) = v.as_array() {
        for t in arr.iter().take(64) {
            let id = t.get("id").and_then(Value::as_str).unwrap_or("-");
            let pc = t.get("pc").and_then(Value::as_str).unwrap_or("-");
            let active = t.get("active").and_then(Value::as_bool).unwrap_or(false);
            if active { tid = id.to_string(); }
            out.push_str(&format!("{:<8} {:<17} {}\n", id, pc, if active { "Active" } else { "Ready" }));
        }
        if tid == "----" {
            tid = arr.first().and_then(|t| t.get("id")).and_then(Value::as_str).unwrap_or("----").to_string();
        }
    }
    (out, tid)
}

#[derive(Default)]
struct DisasmColumns {
    pc: String,
    addr: String,
    bytes: String,
    mnemonic: String,
    operand: String,
    comment: String,
}

fn split_instruction(text: &str) -> (String, String, String) {
    let text = text.replace(" ; real target bytes, decoder not linked yet", " ; raw bytes");
    let (ins, comment) = match text.split_once(';') {
        Some((a, b)) => (a.trim(), format!(";{}", b)),
        None => (text.trim(), String::new()),
    };
    let mut parts = ins.splitn(2, char::is_whitespace);
    let mnemonic = parts.next().unwrap_or("").to_string();
    let operands = parts.next().unwrap_or("").trim().to_string();
    (mnemonic, operands, comment)
}

fn format_disasm(v: &Value) -> DisasmColumns {
    let mut c = DisasmColumns::default();
    if let Some(arr) = v.as_array() {
        for d in arr.iter().take(64) {
            let addr_raw = d.get("addr").and_then(Value::as_str).unwrap_or("-");
            let bytes_raw = d.get("bytes").and_then(Value::as_str).unwrap_or("-");
            let text = d.get("text").and_then(Value::as_str).unwrap_or("-");
            let (mnem, op, comment) = split_instruction(text);
            if c.pc.is_empty() { c.pc = pretty_addr(addr_raw); }
            c.addr.push_str(&format!("{}\n", pretty_addr(addr_raw).replace("00000000`", "")));
            c.bytes.push_str(&format!("{}\n", spaced_hex(bytes_raw)));
            c.mnemonic.push_str(&format!("{}\n", mnem));
            c.operand.push_str(&format!("{}\n", op));
            c.comment.push_str(&format!("{}\n", comment));
        }
    }
    if c.pc.is_empty() { c.pc = "00000000`00000000".into(); }
    c
}

fn refresh_all(pid_hint: Option<String>) -> Result<UiPatch> {
    let regs_v = rpc("dbg.regs", Value::Null)?;
    let (arch, regs, flags, rip, rsp) = format_regs(&regs_v);

    let mods_v = rpc("dbg.modules", Value::Null).unwrap_or(Value::Array(vec![]));
    let th_v = rpc("dbg.threads", Value::Null).unwrap_or(Value::Array(vec![]));
    let (threads, tid) = format_threads(&th_v);

    let dis_v = rpc("dbg.disasm", json!({"addr": rip, "count": 48})).unwrap_or(Value::Array(vec![]));
    let dis = format_disasm(&dis_v);
    let mem_v = rpc("dbg.readMem", json!({"addr": rsp, "size": 160})).unwrap_or(Value::Null);
    let hex = hex_to_lines(
        mem_v.get("addr").and_then(Value::as_str).unwrap_or("0x0"),
        mem_v.get("hex").and_then(Value::as_str).unwrap_or(""),
    );

    let stack = hex.lines().skip(1).take(10).collect::<Vec<_>>().join("\n");
    let (modules, process_name) = format_modules(&mods_v);
    let pid = pid_hint.unwrap_or_else(|| "----".to_string());

    Ok(UiPatch {
        status: Some("Stopped".into()),
        core: Some("online".into()),
        backend: Some("winapi".into()),
        pid: Some(pid.clone()),
        tid: Some(tid),
        arch: Some(arch),
        target: Some(process_name.clone()),
        processes: Some(format!("PID      Process Name           Arch   Status\n{:<8} {:<22} x64    stopped", pid, process_name)),
        modules: Some(modules),
        threads: Some(threads),
        breakpoints: Some("Address             Type   Hits\n<none>".into()),
        memory_map: Some("Base               Size       Protect\n<not queried yet>".into()),
        pc: Some(dis.pc),
        disasm_addr: Some(dis.addr),
        disasm_bytes: Some(dis.bytes),
        disasm_mnemonic: Some(dis.mnemonic),
        disasm_operand: Some(dis.operand),
        disasm_comment: Some(dis.comment),
        regs: Some(regs),
        flags: Some(flags),
        stack: Some(stack),
        hex: Some(hex),
        log: None,
    })
}

fn set_initial(ui: &MainWindow) {
    apply(ui, UiPatch {
        status: Some("Idle".into()),
        core: Some("unknown".into()),
        backend: Some("none".into()),
        target: Some("no target".into()),
        processes: Some("Core offline\n\nClick Core, WinAPI, then Open EXE.".into()),
        modules: Some("No target".into()),
        threads: Some("No target".into()),
        breakpoints: Some("Address             Type   Hits\n<none>".into()),
        memory_map: Some("No target".into()),
        pc: Some("00000000`00000000".into()),
        disasm_addr: Some("".into()),
        disasm_bytes: Some("".into()),
        disasm_mnemonic: Some("".into()),
        disasm_operand: Some("<open an executable to begin>".into()),
        disasm_comment: Some("".into()),
        stack: Some("No target".into()),
        hex: Some("No target".into()),
        ..Default::default()
    });
}

fn main() -> Result<()> {
    let ui = MainWindow::new()?;
    set_initial(&ui);

    {
        let weak = ui.as_weak();
        ui.on_core_clicked(move || {
            with_ui(weak.clone(), || match rpc("core.hello", Value::Null) {
                Ok(v) => UiPatch {
                    core: Some("online".into()),
                    status: Some("Core online".into()),
                    log: Some(format!("core online: {}", v.get("name").and_then(Value::as_str).unwrap_or("hywdbg-core"))),
                    ..Default::default()
                },
                Err(e) => UiPatch { core: Some("offline".into()), status: Some("Core offline".into()), log: Some(format!("core error: {e}")), ..Default::default() }
            });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_winapi_clicked(move || {
            with_ui(weak.clone(), || match ensure_winapi() {
                Ok(_) => UiPatch { core: Some("online".into()), backend: Some("winapi".into()), status: Some("WinAPI backend active".into()), log: Some("backend winapi ready".into()), ..Default::default() },
                Err(e) => UiPatch { status: Some("Backend error".into()), log: Some(format!("{e}")), ..Default::default() }
            });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_stop_clicked(move || {
            with_ui(weak.clone(), || match rpc("core.stopBackend", Value::Null) {
                Ok(_) => UiPatch { backend: Some("none".into()), status: Some("Backend stopped".into()), log: Some("backend stopped".into()), ..Default::default() },
                Err(e) => UiPatch { log: Some(format!("{e}")), ..Default::default() }
            });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_open_exe_clicked(move || {
            let Some(path) = rfd::FileDialog::new()
                .set_title("Open executable")
                .add_filter("Windows executable", &["exe"])
                .pick_file()
            else { return; };
            let path = path.display().to_string();
            with_ui(weak.clone(), move || {
                let result = (|| -> Result<UiPatch> {
                    ensure_winapi()?;
                    let event = rpc("dbg.launch", json!({"path": path}))?;
                    let pid = event.get("pid").map(|v| v.to_string());
                    let mut patch = refresh_all(pid)?;
                    patch.status = Some(event.get("event").and_then(Value::as_str).unwrap_or("create_process").to_string());
                    patch.log = Some("launched debuggee".into());
                    Ok(patch)
                })();
                result.unwrap_or_else(|e| UiPatch { status: Some("Launch failed".into()), log: Some(format!("{e}")), ..Default::default() })
            });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_attach_clicked(move || {
            with_ui(weak.clone(), || UiPatch { log: Some("attach via console: attach <pid>".into()), ..Default::default() });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_run_clicked(move || {
            with_ui(weak.clone(), || match rpc("dbg.go", Value::Null) {
                Ok(ev) => {
                    let mut p = refresh_all(ev.get("pid").map(|v| v.to_string())).unwrap_or_default();
                    p.status = Some(ev.get("event").and_then(Value::as_str).unwrap_or("stopped").to_string());
                    p.log = Some("go / wait event".into());
                    p
                }
                Err(e) => UiPatch { log: Some(format!("{e}")), status: Some("Run failed".into()), ..Default::default() }
            });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_pause_clicked(move || {
            with_ui(weak.clone(), || match rpc("dbg.pause", Value::Null) {
                Ok(ev) => {
                    let mut p = refresh_all(ev.get("pid").map(|v| v.to_string())).unwrap_or_default();
                    p.status = Some(ev.get("event").and_then(Value::as_str).unwrap_or("paused").to_string());
                    p.log = Some("pause".into());
                    p
                }
                Err(e) => UiPatch { log: Some(format!("{e}")), status: Some("Pause failed".into()), ..Default::default() }
            });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_step_clicked(move || {
            with_ui(weak.clone(), || match rpc("dbg.stepInto", Value::Null) {
                Ok(ev) => {
                    let mut p = refresh_all(ev.get("pid").map(|v| v.to_string())).unwrap_or_default();
                    p.status = Some(ev.get("event").and_then(Value::as_str).unwrap_or("single_step").to_string());
                    p.log = Some("step into".into());
                    p
                }
                Err(e) => UiPatch { log: Some(format!("{e}")), status: Some("Step failed".into()), ..Default::default() }
            });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_bp_clicked(move || {
            with_ui(weak.clone(), || {
                let rip = rpc("dbg.regs", Value::Null)
                    .ok()
                    .and_then(|v| v.get("registers").and_then(Value::as_object).and_then(|r| r.get("rip")).and_then(Value::as_str).map(str::to_string))
                    .unwrap_or_else(|| "0x0".into());
                match rpc("dbg.bpSet", json!({"addr": rip})) {
                    Ok(v) => UiPatch { breakpoints: Some(format!("Address             Type   Hits\n{} INT3   0", pretty_addr(v.get("addr").and_then(Value::as_str).unwrap_or("rip")))), log: Some("breakpoint set".into()), ..Default::default() },
                    Err(e) => UiPatch { log: Some(format!("{e}")), ..Default::default() }
                }
            });
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_command_clicked(move |line: SharedString| {
            let line = line.to_string();
            with_ui(weak.clone(), move || run_command(&line));
        });
    }

    ui.run()?;
    Ok(())
}

fn run_command(line: &str) -> UiPatch {
    let line = line.trim();
    if line.is_empty() { return UiPatch::default(); }

    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("").to_lowercase();
    let args = parts.collect::<Vec<_>>();

    let result = (|| -> Result<UiPatch> {
        match cmd.as_str() {
            "help" => Ok(UiPatch { log: Some("commands: backend winapi | launch <exe> | attach <pid> | regs/r | modules | threads | u [rip] | db <addr> [size] | bp [addr] | g | t | pause | stop".into()), ..Default::default() }),
            "backend" => { ensure_winapi()?; Ok(UiPatch { backend: Some("winapi".into()), log: Some("backend winapi ready".into()), ..Default::default() }) }
            "stop" => { rpc("core.stopBackend", Value::Null)?; Ok(UiPatch { backend: Some("none".into()), log: Some("backend stopped".into()), ..Default::default() }) }
            "launch" | "open" => {
                ensure_winapi()?;
                let path = line[cmd.len()..].trim();
                if path.is_empty() { return Err(anyhow!("launch requires path")); }
                let ev = rpc("dbg.launch", json!({"path": path}))?;
                let mut p = refresh_all(ev.get("pid").map(|v| v.to_string()))?;
                p.log = Some(format!("launch {path}"));
                Ok(p)
            }
            "attach" => {
                ensure_winapi()?;
                let pid = args.first().ok_or_else(|| anyhow!("attach requires pid"))?.parse::<u64>()?;
                rpc("dbg.attach", json!({"pid": pid}))?;
                let mut p = refresh_all(Some(pid.to_string()))?;
                p.pid = Some(pid.to_string());
                p.log = Some(format!("attach {pid}"));
                Ok(p)
            }
            "regs" | "r" | "modules" | "threads" => refresh_all(None),
            "u" => {
                let addr = args.first().copied().unwrap_or("rip");
                let addr = if addr.eq_ignore_ascii_case("rip") {
                    let regs = rpc("dbg.regs", Value::Null)?;
                    regs.get("registers").and_then(Value::as_object).and_then(|r| r.get("rip")).and_then(Value::as_str).unwrap_or("0x0").to_string()
                } else { addr.to_string() };
                let d = rpc("dbg.disasm", json!({"addr": addr, "count": 48}))?;
                let dis = format_disasm(&d);
                Ok(UiPatch { pc: Some(dis.pc), disasm_addr: Some(dis.addr), disasm_bytes: Some(dis.bytes), disasm_mnemonic: Some(dis.mnemonic), disasm_operand: Some(dis.operand), disasm_comment: Some(dis.comment), log: Some("disasm refreshed".into()), ..Default::default() })
            }
            "db" => {
                let addr = args.first().copied().unwrap_or("0x0");
                let size = args.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(128);
                let m = rpc("dbg.readMem", json!({"addr": addr, "size": size}))?;
                Ok(UiPatch { hex: Some(hex_to_lines(m.get("addr").and_then(Value::as_str).unwrap_or("0x0"), m.get("hex").and_then(Value::as_str).unwrap_or(""))), log: Some("memory refreshed".into()), ..Default::default() })
            }
            "bp" => {
                let addr = args.first().copied().unwrap_or("rip");
                let addr = if addr.eq_ignore_ascii_case("rip") {
                    let regs = rpc("dbg.regs", Value::Null)?;
                    regs.get("registers").and_then(Value::as_object).and_then(|r| r.get("rip")).and_then(Value::as_str).unwrap_or("0x0").to_string()
                } else { addr.to_string() };
                rpc("dbg.bpSet", json!({"addr": addr}))?;
                Ok(UiPatch { breakpoints: Some("Address             Type   Hits\n<set at current address>".into()), log: Some("breakpoint set".into()), ..Default::default() })
            }
            "g" => { let ev = rpc("dbg.go", Value::Null)?; let mut p = refresh_all(ev.get("pid").map(|v| v.to_string()))?; p.log = Some("go".into()); Ok(p) }
            "t" | "step" => { let ev = rpc("dbg.stepInto", Value::Null)?; let mut p = refresh_all(ev.get("pid").map(|v| v.to_string()))?; p.log = Some("step".into()); Ok(p) }
            "pause" => { let ev = rpc("dbg.pause", Value::Null)?; let mut p = refresh_all(ev.get("pid").map(|v| v.to_string()))?; p.log = Some("pause".into()); Ok(p) }
            _ => Ok(UiPatch { log: Some(format!("unknown command: {cmd}")), ..Default::default() }),
        }
    })();

    match result {
        Ok(mut p) => { let old = p.log.take().unwrap_or_else(|| "ok".into()); p.log = Some(format!("hyw> {line}\n{old}")); p }
        Err(e) => UiPatch { log: Some(format!("hyw> {line}\nerror: {e}")), status: Some("Command failed".into()), ..Default::default() },
    }
}
