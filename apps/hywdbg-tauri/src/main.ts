import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import "./style.css";

type Json = any;

type RpcResult = {
  id?: number;
  ok: boolean;
  result?: Json;
  error?: { code?: string; message?: string } | string;
};

type RegDump = {
  arch?: string;
  registers?: Record<string, string>;
};

type ModuleInfo = {
  name?: string;
  base?: string;
  size?: number;
  path?: string | null;
};

type ThreadInfo = {
  id?: string;
  name?: string | null;
  pc?: string | null;
  active?: boolean;
};

type DisasmLine = {
  addr?: string;
  bytes?: string;
  text?: string;
};

type MemoryBlock = {
  addr?: string;
  size?: number;
  hex?: string;
};

type BreakpointInfo = {
  address: string;
  type: string;
  hits: number;
};

type LogKind = "info" | "ok" | "cmd" | "warn" | "err";

type LogItem = {
  text: string;
  kind: LogKind;
};

const HTTP_RPC_URL = "http://127.0.0.1:31338/rpc";
let nextRpcId = 1;
let offlineNoticeShown = false;
let backendEnsureInFlight: Promise<boolean> | null = null;

const app = document.querySelector<HTMLDivElement>("#app")!;

app.innerHTML = `
<div class="dbg-shell">
  <header class="topbar">
    <div class="brand"><strong>HYWDbg</strong></div>
    <nav class="menubar"><span>File</span><span>View</span><span>Debug</span><span>Plugins</span><span>Window</span><span>Help</span></nav>
    <div class="win-controls"><span>—</span><span>□</span><span>×</span></div>
  </header>

  <section class="actionbar">
    <button class="tool primary" id="runBtn"><span class="ico green">▶</span> Run <em>F5</em></button>
    <button class="tool" id="pauseBtn"><span class="ico blue">Ⅱ</span> Pause <em>F6</em></button>
    <button class="tool" id="stepBtn"><span class="ico blue">↧</span> Step Into <em>F11</em></button>
    <button class="tool" id="stepOverBtn"><span class="ico blue">↪</span> Step Over <em>F10</em></button>
    <button class="tool" id="bpBtn"><span class="ico red">●</span> Breakpoint</button>
    <button class="tool" id="launchBtn"><span class="ico yellow">📂</span> Open EXE</button>
    <button class="tool" id="attachBtn"><span class="ico muted">🔗</span> Attach</button>
    <div class="spacer"></div>
    <button class="tool backend" id="helloBtn">Core</button>
    <button class="tool backend" id="startWinapiBtn">WinAPI</button>
    <button class="tool backend danger" id="stopBackendBtn">Stop</button>
  </section>

  <main class="workspace">
    <aside class="left-dock">
      <section class="dock-panel processes">
        <div class="panel-title">Processes <span>⌁</span></div>
        <table>
          <thead><tr><th>PID</th><th>Process Name</th><th>Arch</th><th>Status</th></tr></thead>
          <tbody id="processRows"></tbody>
        </table>
      </section>

      <section class="dock-panel modules">
        <div class="panel-title">Modules <span>⌁</span></div>
        <table>
          <thead><tr><th>Base</th><th>Module</th><th>Size</th></tr></thead>
          <tbody id="moduleRows"></tbody>
        </table>
      </section>

      <section class="dock-panel threads">
        <div class="panel-title">Threads <span>⌁</span></div>
        <table>
          <thead><tr><th>TID</th><th>PC</th><th>State</th></tr></thead>
          <tbody id="threadRows"></tbody>
        </table>
      </section>

      <section class="dock-panel breakpoints">
        <div class="panel-title">Breakpoints <span>⌁</span></div>
        <table>
          <thead><tr><th>Address</th><th>Type</th><th>Hits</th></tr></thead>
          <tbody id="bpRows"></tbody>
        </table>
      </section>

      <section class="dock-panel memory-map">
        <div class="panel-title">Memory Map <span>⌁</span></div>
        <table>
          <thead><tr><th>Base</th><th>Size</th><th>Protect</th></tr></thead>
          <tbody id="mapRows"></tbody>
        </table>
        <input class="filter" placeholder="Filter..." />
      </section>
    </aside>

    <section class="center-dock">
      <section class="dock-panel disasm-panel">
        <div class="tabbar"><div class="tab active">Disassembly - Thread <span id="activeTid">----</span> <b>×</b></div><div class="tab plus">+</div></div>
        <div class="subline">RIP: <span id="ripLine">00000000</span> <span id="symbolLine">(no target)</span></div>
        <table class="disasm-table">
          <thead><tr><th></th><th>Address</th><th>Bytes</th><th>Instruction</th><th>Comment</th></tr></thead>
          <tbody id="disasmRows"></tbody>
        </table>
      </section>

      <section class="bottom-grid">
        <section class="dock-panel stack-panel">
          <div class="tabbar small"><div class="tab active">Stack <b>×</b></div><div class="tab">Watch 1</div></div>
          <div class="subline">RSP: <span id="rspLine">00000000</span></div>
          <table>
            <thead><tr><th>Address</th><th>Value</th><th>Comment</th></tr></thead>
            <tbody id="stackRows"></tbody>
          </table>
        </section>

        <section class="dock-panel hex-panel">
          <div class="tabbar small"><div class="tab active">Hex View 1 <b>×</b></div></div>
          <div class="subline">Address: <input id="addrBox" class="addr-input" placeholder="0x..." /> <button id="readMemBtn" class="micro">read</button></div>
          <table class="hex-table">
            <thead id="hexHead"></thead>
            <tbody id="hexRows"></tbody>
          </table>
        </section>
      </section>

      <section class="dock-panel log-panel">
        <div class="tabbar small"><div class="tab active">Log / Console <b>×</b></div></div>
        <pre id="logView"></pre>
        <div class="cmdline"><span>hyw&gt;</span><input id="commandBox" spellcheck="false" placeholder="launch C:\\Windows\\System32\\notepad.exe | attach 1234 | regs | u rip | db rsp 80 | bp rip | g | t | pause" /></div>
      </section>
    </section>

    <aside class="right-dock">
      <section class="dock-panel registers-panel">
        <div class="panel-title">Registers <span id="refreshRegs">⟳</span></div>
        <div class="reg-group">General (<span id="archName">x64</span>)</div>
        <div id="registerRows" class="register-list"></div>
        <div class="flags-title">Flags</div>
        <div id="flagRows" class="flags"></div>
      </section>
    </aside>
  </main>

  <footer class="statusbar">
    <span id="statusText">Status: Idle</span>
    <span>PID: <b id="statusPid">----</b></span>
    <span>TID: <b id="statusTid">----</b></span>
    <span>Arch: <b id="statusArch">x64</b></span>
    <span>Backend: <b id="statusBackend">none</b></span>
    <span>Transport: <b id="transportState">detecting</b></span>
    <span class="right">Core: <b id="coreState">unknown</b></span>
  </footer>
</div>
`;

const $ = <T extends HTMLElement>(sel: string) => document.querySelector<T>(sel)!;

const state = {
  coreOnline: false,
  backend: "none",
  pid: "----",
  tid: "----",
  arch: "x64",
  status: "Idle",
  regs: {} as Record<string, string>,
  modules: [] as ModuleInfo[],
  threads: [] as ThreadInfo[],
  disasm: [] as DisasmLine[],
  memory: { addr: "", size: 0, hex: "" } as MemoryBlock,
  breakpoints: [] as BreakpointInfo[],
  log: [] as LogItem[],
};

function nowStamp() {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}

function normalizeLogKind(text: string, kind: LogKind = "info"): LogKind {
  if (kind !== "info") return kind;
  if (/failed|exception|error|denied|timeout/i.test(text)) return "err";
  if (/warn|already active|no active backend|no debuggee/i.test(text)) return "warn";
  if (/online|started|attached|launched|refreshed|loaded|ready|ok/i.test(text)) return "ok";
  return "info";
}

function renderLog() {
  const view = $("#logView");
  view.innerHTML = state.log
    .map((x) => `<span class="log-line log-${x.kind}">${escapeHtml(x.text)}</span>`)
    .join("\n");
  view.scrollTop = view.scrollHeight;
}

function log(text: string, kind: LogKind = "info") {
  const item = {
    text: `[${nowStamp()}] ${text}`,
    kind: normalizeLogKind(text, kind),
  };
  state.log.push(item);
  if (state.log.length > 300) state.log.shift();
  renderLog();
}

function escapeHtml(s: string) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function compactHex(s?: string) {
  if (!s) return "";
  return s.replace(/^0x/i, "").replace(/^0+/, "") || "0";
}

function tickHex(addr?: string) {
  const raw = compactHex(addr).padStart(16, "0").slice(-16).toUpperCase();
  return `${raw.slice(0, 8)}\`${raw.slice(8)}`;
}

function parseNumish(v: string | undefined): number {
  if (!v) return 0;
  const s = v.trim();
  if (s.toLowerCase() === "rip") return Number.parseInt(state.regs.rip || "0", 16);
  if (s.toLowerCase() === "rsp") return Number.parseInt(state.regs.rsp || "0", 16);
  if (s.toLowerCase() in state.regs) return Number.parseInt(state.regs[s.toLowerCase()].replace(/^0x/i, ""), 16);
  return s.startsWith("0x") || s.startsWith("0X") ? Number.parseInt(s.slice(2), 16) : Number.parseInt(s, 10);
}

function parseBigIntish(v: string | undefined): bigint | null {
  if (!v) return null;
  const s = v.trim();
  const resolved = s.toLowerCase() in state.regs ? state.regs[s.toLowerCase()] : s;
  if (!resolved) return null;
  try {
    return resolved.startsWith("0x") || resolved.startsWith("0X") ? BigInt(resolved) : BigInt(resolved);
  } catch {
    return null;
  }
}

function hex64(v: bigint) {
  return `0x${v.toString(16).padStart(16, "0")}`;
}

function asAddr(v: string | undefined) {
  const n = parseNumish(v);
  if (!Number.isFinite(n) || Number.isNaN(n)) return v || "0x0";
  return `0x${Math.trunc(n).toString(16)}`;
}

function hasTauriBridge() {
  const w = globalThis as any;
  return typeof w.__TAURI_INTERNALS__?.invoke === "function" || typeof w.__TAURI__?.core?.invoke === "function";
}

async function pickExePath(): Promise<string | null> {
  if (hasTauriBridge()) {
    try {
      const selected = await openDialog({
        title: "Open executable",
        multiple: false,
        directory: false,
        filters: [
          { name: "Windows executable", extensions: ["exe"] },
          { name: "All files", extensions: ["*"] },
        ],
      });

      if (typeof selected === "string") return selected;
      if (Array.isArray(selected) && typeof selected[0] === "string") return selected[0];
      return null;
    } catch (e) {
      log(`native file picker failed: ${String(e)}`, "warn");
    }
  }

  return prompt("EXE path", "C:\\Windows\\System32\\notepad.exe");
}

function transportName() {
  return hasTauriBridge() ? "tauri" : "http";
}

async function requestCore(method: string, params: Json): Promise<string> {
  const w = globalThis as any;
  if (hasTauriBridge()) {
    const bridgeInvoke = w.__TAURI__?.core?.invoke;
    if (typeof bridgeInvoke === "function") {
      return bridgeInvoke("core_request", { method, params });
    }
    return tauriInvoke<string>("core_request", { method, params });
  }

  const response = await fetch(HTTP_RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ id: nextRpcId++, method, params }),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${text.slice(0, 240)}`);
  }
  return text;
}

function explainCoreError(e: unknown) {
  const raw = e instanceof Error ? e.message : String(e);
  if (!hasTauriBridge() && /fetch|network|load failed/i.test(raw)) {
    return `core HTTP bridge offline at ${HTTP_RPC_URL}; start run-core.ps1 or use npm run tauri dev`;
  }
  if (/__TAURI|invoke|undefined/i.test(raw)) {
    return "Tauri invoke bridge is unavailable; run the shell with npm run tauri dev, or use browser mode with the core HTTP bridge";
  }
  return raw;
}

function isOfflineError(message: string) {
  return /core HTTP bridge offline|connect core failed|connection refused|failed to fetch|network|load failed/i.test(message);
}

function tableMessage(colspan: number, text: string) {
  return `<tr class="empty-row"><td colspan="${colspan}">${escapeHtml(text)}</td></tr>`;
}

function emptyReason() {
  return state.coreOnline ? "No target" : "Core offline";
}

function clearDebugState(status = state.status) {
  state.pid = "----";
  state.tid = "----";
  state.regs = {};
  state.modules = [];
  state.threads = [];
  state.disasm = [];
  state.memory = { addr: "", size: 0, hex: "" };
  state.breakpoints = [];
  state.status = status;
}

function setCoreOnline(online: boolean) {
  state.coreOnline = online;
  $("#coreState").textContent = online ? "online" : "offline";
  if (!online) {
    state.backend = "none";
    clearDebugState("Core offline");
  }
}

async function core(method: string, params: Json = null): Promise<RpcResult> {
  try {
    const text = await requestCore(method, params);
    const obj = JSON.parse(text) as RpcResult;
    setCoreOnline(true);
    offlineNoticeShown = false;
    if (!obj.ok) {
      const msg = typeof obj.error === "string" ? obj.error : obj.error?.message || JSON.stringify(obj.error);
      log(`${method} failed: ${msg}`, /no active backend|no debuggee/i.test(msg) ? "warn" : "err");
      if (method.startsWith("dbg.") && /no active backend|no debuggee/i.test(msg)) {
        clearDebugState(state.coreOnline ? "Idle" : "Core offline");
      }
    }
    return obj;
  } catch (e) {
    const msg = explainCoreError(e);
    const offline = isOfflineError(msg);
    if (offline) {
      setCoreOnline(false);
      render();
    }
    if (!offline || !offlineNoticeShown) {
      log(`${method} exception: ${msg}`, "err");
    }
    offlineNoticeShown ||= offline;
    return { ok: false, error: msg };
  }
}

function setStatus(text: string) {
  state.status = text;
  renderStatus();
}

function render() {
  renderProcesses();
  renderModules();
  renderThreads();
  renderBreakpoints();
  renderMemoryMap();
  renderDisasm();
  renderRegs();
  renderStack();
  renderHex();
  renderStatus();
}

function renderProcesses() {
  if (!state.coreOnline || state.pid === "----") {
    $("#processRows").innerHTML = tableMessage(4, emptyReason());
    return;
  }

  const name = state.modules[0]?.name || "debuggee";
  $("#processRows").innerHTML = `<tr class="sel"><td>${escapeHtml(state.pid)}</td><td>${escapeHtml(name)}</td><td>${state.arch}</td><td>${escapeHtml(state.status)}</td></tr>`;
}

function renderModules() {
  if (!state.modules.length) {
    $("#moduleRows").innerHTML = tableMessage(3, emptyReason());
    return;
  }
  $("#moduleRows").innerHTML = state.modules.slice(0, 8).map((m, i) => `<tr class="${i === 0 ? "soft" : ""}"><td>${tickHex(m.base)}</td><td>${escapeHtml(m.name || "?")}</td><td>0x${(m.size || 0).toString(16).toUpperCase()}</td></tr>`).join("");
}

function renderThreads() {
  if (!state.threads.length) {
    $("#threadRows").innerHTML = tableMessage(3, emptyReason());
    return;
  }
  $("#threadRows").innerHTML = state.threads.slice(0, 8).map((t) => `<tr class="${t.active ? "sel" : ""}"><td>${escapeHtml(t.id || "?")}</td><td>${t.pc ? tickHex(t.pc) : ""}</td><td>${t.active ? "Active" : "Ready"}</td></tr>`).join("");
}

function renderBreakpoints() {
  if (!state.breakpoints.length) {
    $("#bpRows").innerHTML = tableMessage(3, emptyReason());
    return;
  }
  $("#bpRows").innerHTML = state.breakpoints.map((b) => `<tr><td>${tickHex(b.address)}</td><td>${escapeHtml(b.type)}</td><td>${b.hits}</td></tr>`).join("");
}

function renderMemoryMap() {
  const rows = state.modules.slice(0, 5).map((m) => {
    const size = m.size || 0;
    return `<tr><td>${tickHex(m.base)}</td><td>0x${size.toString(16).toUpperCase()}</td><td></td></tr>`;
  });
  if (!rows.length) rows.push(tableMessage(3, emptyReason()));
  $("#mapRows").innerHTML = rows.join("");
}

function renderDisasm() {
  $("#activeTid").textContent = state.tid;
  $("#ripLine").textContent = state.regs.rip ? tickHex(state.regs.rip) : "----";
  $("#symbolLine").textContent = state.modules[0]?.name ? `(${state.modules[0].name})` : "(no target)";
  if (!state.disasm.length) {
    $("#disasmRows").innerHTML = tableMessage(5, emptyReason());
    return;
  }
  const rip = compactHex(state.regs.rip).toLowerCase();
  $("#disasmRows").innerHTML = state.disasm.map((l, i) => {
    const isRip = !!rip && compactHex(l.addr).toLowerCase() === rip;
    const parts = splitInstr(cleanInstrText(l.text || ""));
    return `<tr class="${isRip ? "current" : ""}"><td class="arrow">${isRip ? "➜" : ""}</td><td>${tickHex(l.addr)}</td><td class="bytes">${formatBytes(l.bytes || "")}</td><td class="instr"><span class="mnemonic">${escapeHtml(parts.mnemonic)}</span>${escapeHtml(parts.rest)}</td><td class="comment">${escapeHtml(parts.comment)}</td></tr>`;
  }).join("");
}

function cleanInstrText(text: string) {
  return text
    .replace(/;\s*real target bytes, decoder not linked yet/gi, "; raw bytes")
    .replace(/;\s*decoder not linked yet/gi, "; raw bytes");
}

function splitInstr(text: string) {
  const [body, ...commentParts] = text.split(";");
  const comment = commentParts.length ? `;${commentParts.join(";")}` : "";
  const m = body.trim().match(/^(\S+)(.*)$/);
  return { mnemonic: m?.[1] || "db", rest: m?.[2] || ` ${body}`, comment };
}

function formatBytes(hex: string) {
  return hex.replace(/[^0-9a-f]/gi, "").match(/.{1,2}/g)?.join(" ").toUpperCase() || "";
}

function renderRegs() {
  const order = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
  $("#archName").textContent = state.arch;
  if (!Object.keys(state.regs).length) {
    $("#registerRows").innerHTML = `<div class="empty-panel">${escapeHtml(emptyReason())}</div>`;
    renderFlags();
    return;
  }
  $("#registerRows").innerHTML = order.map((name) => {
    const value = state.regs[name];
    return `<div class="reg-row ${name === "rip" ? "hot" : ""}"><span>${name.toUpperCase()}</span><code>${value ? tickHex(value) : ""}</code></div>`;
  }).join("");
  renderFlags();
}

function renderFlags() {
  if (!Object.keys(state.regs).length) {
    $("#flagRows").innerHTML = `<div class="empty-panel">${escapeHtml(emptyReason())}</div>`;
    return;
  }
  const flagsRaw = state.regs.eflags;
  if (!flagsRaw) {
    $("#flagRows").innerHTML = `<div class="empty-panel">No flags</div>`;
    return;
  }
  const flags = Number.parseInt(flagsRaw.replace(/^0x/i, ""), 16) || 0;
  const bits = [
    ["CF", 0], ["PF", 2], ["AF", 4], ["ZF", 6], ["SF", 7],
    ["TF", 8], ["IF", 9], ["DF", 10], ["OF", 11], ["NT", 14],
  ];
  $("#flagRows").innerHTML = `<div class="rflags">RFLAGS <code>${tickHex(flagsRaw)}</code></div>` + bits.map(([name, bit]) => {
    const on = (flags & (1 << Number(bit))) !== 0;
    return `<span class="flag ${on ? "on" : ""}">${name} ${on ? 1 : 0}</span>`;
  }).join("");
}

function renderStack() {
  const rsp = parseBigIntish(state.regs.rsp);
  const memoryBase = parseBigIntish(state.memory.addr);
  const bytes = (state.memory.hex || "").replace(/[^0-9a-f]/gi, "").match(/.{1,2}/g)?.map((x) => Number.parseInt(x, 16)) || [];

  if (rsp === null) {
    $("#rspLine").textContent = "----";
    $("#stackRows").innerHTML = tableMessage(3, emptyReason());
    return;
  }
  $("#rspLine").textContent = tickHex(state.regs.rsp);

  if (memoryBase === null || !bytes.length || rsp < memoryBase) {
    $("#stackRows").innerHTML = tableMessage(3, "No stack memory");
    return;
  }

  const offset = Number(rsp - memoryBase);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= bytes.length) {
    $("#stackRows").innerHTML = tableMessage(3, "No stack memory");
    return;
  }

  const rows = [];
  for (let i = 0; i < 8; i += 1) {
    const start = offset + i * 8;
    const chunk = bytes.slice(start, start + 8);
    if (chunk.length < 8) break;
    let value = 0n;
    for (let b = 0; b < chunk.length; b += 1) {
      value |= BigInt(chunk[b]) << BigInt(b * 8);
    }
    rows.push(`<tr><td>${tickHex(hex64(rsp + BigInt(i * 8)))}</td><td>${tickHex(hex64(value))}</td><td class="comment"></td></tr>`);
  }

  if (!rows.length) rows.push(tableMessage(3, "No stack memory"));
  $("#stackRows").innerHTML = rows.join("");
}

function renderHex() {
  $("#addrBox").setAttribute("value", state.memory.addr || "");
  const header = ["Address", ...Array.from({ length: 16 }, (_, i) => i.toString(16).padStart(2, "0").toUpperCase()), "ASCII"];
  $("#hexHead").innerHTML = `<tr>${header.map((h) => `<th>${h}</th>`).join("")}</tr>`;
  const bytes = (state.memory.hex || "").replace(/[^0-9a-f]/gi, "").match(/.{1,2}/g)?.map((x) => Number.parseInt(x, 16)) || [];
  const base = parseNumish(state.memory.addr) || 0;
  const rows = [];
  if (!bytes.length) {
    $("#hexRows").innerHTML = tableMessage(18, emptyReason());
    return;
  }
  for (let off = 0; off < Math.min(bytes.length, 160); off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const cells = chunk.map((b) => `<td>${b.toString(16).padStart(2, "0").toUpperCase()}</td>`).join("") + Array.from({ length: 16 - chunk.length }, () => "<td></td>").join("");
    const ascii = chunk.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
    rows.push(`<tr><td class="addr">${tickHex(`0x${(base + off).toString(16)}`)}</td>${cells}<td class="ascii">${escapeHtml(ascii)}</td></tr>`);
  }
  $("#hexRows").innerHTML = rows.join("");
}

function renderStatus() {
  $("#statusText").textContent = `Status: ${state.status}`;
  $("#statusPid").textContent = state.pid;
  $("#statusTid").textContent = state.tid;
  $("#statusArch").textContent = state.arch;
  $("#statusBackend").textContent = state.backend;
  $("#transportState").textContent = transportName();
}

function applyEventResult(obj: RpcResult) {
  const r = obj.result || {};
  if (r.pid) state.pid = String(r.pid);
  if (r.tid) {
    const tidNum = Number(r.tid);
    state.tid = Number.isFinite(tidNum) ? tidNum.toString(16).toUpperCase() : String(r.tid);
  }
  if (r.event) {
    state.status = r.event === "breakpoint" ? "Breakpoint Hit" : String(r.event);
    log(`event: ${r.event} pid=${r.pid || state.pid} tid=${r.tid || state.tid}`);
  }
}

async function refreshAll() {
  await refreshRegs();
  await refreshModules();
  await refreshThreads();
  await refreshDisasm();
  await refreshMem(state.regs.rsp || state.regs.rip || "0x0", 128);
  render();
}

async function refreshRegs() {
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.regs");
  if (obj.ok && obj.result) {
    const dump = obj.result as RegDump;
    state.arch = dump.arch || state.arch;
    state.regs = { ...state.regs, ...(dump.registers || {}) };
    log("registers refreshed");
  }
  render();
}

async function refreshModules() {
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.modules");
  if (obj.ok && Array.isArray(obj.result)) {
    state.modules = obj.result;
    log(`modules: ${state.modules.length}`);
  }
  render();
}

async function refreshThreads() {
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.threads");
  if (obj.ok && Array.isArray(obj.result)) {
    state.threads = obj.result;
    const active = state.threads.find((t) => t.active) || state.threads[0];
    if (active?.id) state.tid = active.id;
    log(`threads: ${state.threads.length}`);
  }
  render();
}

async function refreshDisasm(addr = state.regs.rip || "0x0") {
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.disasm", { addr: asAddr(addr), count: 24 });
  if (obj.ok && Array.isArray(obj.result)) {
    state.disasm = obj.result;
    log(`disasm ${asAddr(addr)}`);
  }
  render();
}

async function refreshMem(addr = state.memory.addr || "0x0", size = 128) {
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.readMem", { addr: asAddr(addr), size });
  if (obj.ok && obj.result) {
    state.memory = obj.result as MemoryBlock;
    log(`read memory ${state.memory.addr} size=${state.memory.size}`);
  }
  render();
}

async function syncBackendStatus(announce = false) {
  const obj = await core("core.backendStatus");
  if (obj.ok && obj.result) {
    if (obj.result.active) {
      state.backend = obj.result.kind || state.backend || "unknown";
      if (announce) log(`backend active: ${state.backend}`, "ok");
    } else {
      state.backend = "none";
      if (announce) log("backend inactive", "warn");
    }
    renderStatus();
  }
  return state.backend !== "none";
}

async function ensureBackend(kind: "winapi" | "titan" = "winapi") {
  if (state.backend !== "none") return true;

  if (backendEnsureInFlight) return backendEnsureInFlight;

  backendEnsureInFlight = (async () => {
    await syncBackendStatus(false);
    if (state.backend !== "none") return true;

    log(`no active backend, auto starting ${kind}`, "warn");
    const obj = await core("core.startBackend", { kind });
    if (obj.ok) {
      clearDebugState("Backend Ready");
      state.backend = kind;
      log(`backend started: ${kind}`, "ok");
      render();
      return true;
    }

    await syncBackendStatus(false);
    return state.backend !== "none";
  })();

  try {
    return await backendEnsureInFlight;
  } finally {
    backendEnsureInFlight = null;
  }
}

async function startBackend(kind: "winapi" | "titan") {
  const obj = await core("core.startBackend", { kind });
  if (obj.ok) {
    clearDebugState("Backend Ready");
    state.backend = kind;
    log(`backend started: ${kind}`, "ok");
  }
  render();
}

async function stopBackend() {
  const obj = await core("core.stopBackend");
  if (obj.ok) {
    state.backend = "none";
    clearDebugState("Idle");
    log("backend stopped", "warn");
  }
  render();
}

async function launchTarget(pathArg?: string) {
  const path = pathArg || await pickExePath();
  if (!path) return;

  if (!(await ensureBackend("winapi"))) return;

  log(`launching: ${path}`, "cmd");
  const obj = await core("dbg.launch", { path });

  if (obj.ok) {
    clearDebugState("Launching");
    applyEventResult(obj);
    log(`process launched: ${path}`, "ok");
    await refreshAll();
  }
}

async function attachTarget() {
  const pid = prompt("PID", "1234");
  if (!pid) return;
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.attach", { pid: Number(pid) });
  if (obj.ok) {
    clearDebugState("Attaching");
    state.pid = pid;
    applyEventResult(obj);
    log(`process attached: pid=${pid}`);
    await refreshAll();
  }
}

async function go() {
  if (!(await ensureBackend("winapi"))) return;
  const previousStatus = state.status;
  setStatus("Running");
  render();
  const obj = await core("dbg.go");
  if (obj.ok) {
    applyEventResult(obj);
    await refreshAll();
  } else if (state.coreOnline) {
    setStatus(previousStatus);
    render();
  }
}

async function stepInto() {
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.stepInto");
  if (obj.ok) {
    applyEventResult(obj);
    await refreshAll();
  }
}

async function pause() {
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.pause");
  if (obj.ok) {
    applyEventResult(obj);
    await refreshAll();
  }
}

async function setBreakpoint() {
  const addr = prompt("Breakpoint address", state.regs.rip || "0x0");
  if (!addr) return;
  if (!(await ensureBackend("winapi"))) return;
  const obj = await core("dbg.bpSet", { addr: asAddr(addr) });
  if (obj.ok && obj.result) {
    state.breakpoints.push({ address: obj.result.addr || asAddr(addr), type: "INT3", hits: 0 });
    log(`breakpoint set at ${obj.result.addr || addr}`);
  }
  render();
}

async function checkCore() {
  const obj = await core("core.hello");
  if (obj.ok) {
    setCoreOnline(true);
    log(`core online: ${obj.result?.name || "hywdbg-core"}`, "ok");
    await syncBackendStatus(false);
  } else {
    setCoreOnline(false);
    render();
  }
}

async function runCommand(raw: string) {
  const line = raw.trim();
  if (!line) return;
  log(`hyw> ${line}`, "cmd");
  const [cmd, ...args] = line.split(/\s+/);
  try {
    switch (cmd.toLowerCase()) {
      case "help":
        log("commands: backend winapi|titan, launch <exe>, attach <pid>, regs, modules, threads, u [addr], db <addr> [size], bp <addr>, g, t, pause, stop, rpc <method> <json>");
        break;
      case "backend":
        await startBackend((args[0] as "winapi" | "titan") || "winapi");
        break;
      case "stop":
        await stopBackend();
        break;
      case "launch":
      case "open":
        if (!args.length) return await launchTarget();
        await launchTarget(line.slice(cmd.length).trim());
        break;
      case "attach":
        if (!args[0]) return await attachTarget();
        {
          if (!(await ensureBackend("winapi"))) return;
          const obj = await core("dbg.attach", { pid: Number(args[0]) });
          if (obj.ok) { clearDebugState("Attaching"); state.pid = args[0]; applyEventResult(obj); await refreshAll(); }
        }
        break;
      case "regs":
      case "r":
        await refreshRegs();
        break;
      case "modules":
      case "lm":
        await refreshModules();
        break;
      case "threads":
        await refreshThreads();
        break;
      case "u":
        await refreshDisasm(args[0] || state.regs.rip || "0x0");
        break;
      case "db":
        await refreshMem(args[0] || state.regs.rsp || "0x0", Number(args[1] || "128"));
        break;
      case "bp":
        {
          if (!(await ensureBackend("winapi"))) return;
          const addr = args[0] || state.regs.rip;
          const obj = await core("dbg.bpSet", { addr: asAddr(addr) });
          if (obj.ok && obj.result) state.breakpoints.push({ address: obj.result.addr || asAddr(addr), type: "INT3", hits: 0 });
          render();
        }
        break;
      case "g":
      case "run":
        await go();
        break;
      case "t":
      case "step":
        await stepInto();
        break;
      case "pause":
        await pause();
        break;
      case "rpc":
        {
          const method = args[0];
          const jsonStart = line.indexOf(method) + method.length;
          const paramsText = line.slice(jsonStart).trim();
          const params = paramsText ? JSON.parse(paramsText) : null;
          const obj = await core(method, params);
          log(JSON.stringify(obj, null, 2));
        }
        break;
      default:
        log(`unknown command: ${cmd}`, "err");
    }
  } catch (e) {
    log(`command failed: ${String(e)}`, "err");
  }
}

$("#helloBtn").addEventListener("click", checkCore);
$("#startWinapiBtn").addEventListener("click", () => startBackend("winapi"));
$("#stopBackendBtn").addEventListener("click", stopBackend);
$("#launchBtn").addEventListener("click", launchTarget);
$("#attachBtn").addEventListener("click", attachTarget);
$("#runBtn").addEventListener("click", go);
$("#pauseBtn").addEventListener("click", pause);
$("#stepBtn").addEventListener("click", stepInto);
$("#stepOverBtn").addEventListener("click", stepInto);
$("#bpBtn").addEventListener("click", setBreakpoint);
$("#refreshRegs").addEventListener("click", refreshRegs);
$("#readMemBtn").addEventListener("click", () => refreshMem((document.querySelector("#addrBox") as HTMLInputElement).value || state.memory.addr, 128));

$("#commandBox").addEventListener("keydown", async (ev) => {
  if (ev.key !== "Enter") return;
  const box = ev.currentTarget as HTMLInputElement;
  const value = box.value;
  box.value = "";
  await runCommand(value);
});

document.addEventListener("keydown", (ev) => {
  if ((ev.target as HTMLElement).tagName === "INPUT") return;
  if (ev.key === "F5") { ev.preventDefault(); void go(); }
  if (ev.key === "F6") { ev.preventDefault(); void pause(); }
  if (ev.key === "F11") { ev.preventDefault(); void stepInto(); }
});

log("HYWDbg 0.1.0 UI loaded");
log(`RPC transport: ${transportName()}${hasTauriBridge() ? "" : ` (${HTTP_RPC_URL})`}`);
log("Run core-daemon. WinAPI backend auto-starts on launch/attach/debug commands. Use console: help", "ok");
render();
void checkCore();
