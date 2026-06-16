use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type RequestId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub id: RequestId,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub id: RequestId,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEvent {
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WireFrame {
    Request(RpcRequest),
    Response(RpcResponse),
    Event(RpcEvent),
}

impl RpcResponse {
    pub fn ok(id: RequestId, result: impl Serialize) -> Self {
        Self {
            id,
            ok: true,
            result: Some(serde_json::to_value(result).unwrap_or(Value::Null)),
            error: None,
        }
    }

    pub fn ok_null(id: RequestId) -> Self {
        Self { id, ok: true, result: Some(Value::Null), error: None }
    }

    pub fn err(id: RequestId, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(RpcError { code: code.into(), message: message.into() }),
        }
    }
}

pub fn hex_u64(v: u64) -> String {
    format!("0x{v:016x}")
}

pub fn parse_u64ish(value: &Value) -> Result<u64, String> {
    match value {
        Value::Number(n) => n.as_u64().ok_or_else(|| "number is not u64".to_string()),
        Value::String(s) => parse_u64_str(s),
        _ => Err("expected integer or string".to_string()),
    }
}

pub fn parse_u64_str(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(x) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(x, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

// ─── Core types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub name: String,
    pub version: String,
    pub backend_kind: String,
    pub supported_arches: Vec<String>,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegDump {
    pub arch: String,
    pub registers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBlock {
    pub addr: String,
    pub size: usize,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmLine {
    pub addr: String,
    pub bytes: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub id: String,
    pub name: Option<String>,
    pub pc: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: String,
    pub size: u64,
    pub path: Option<String>,
}

// ─── New types added in refactor ────────────────────────────────────────────

/// A single frame in a call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    /// Instruction pointer for this frame.
    pub addr: String,
    /// Resolved symbol name, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Module that contains this frame.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Source line info (file:line), if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// A hardware or software watchpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchpointInfo {
    pub id: u64,
    pub addr: String,
    /// Byte width: 1, 2, 4, or 8.
    pub size: u64,
    /// Access kind: "r", "w", or "rw".
    pub kind: String,
    pub enabled: bool,
}

/// An entry in the running process list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessListEntry {
    pub pid: u64,
    pub name: String,
    pub arch: String,
    /// Optional session description (e.g. "Wine x86" or "native").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A tracked breakpoint (used by bpList response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointRecord {
    pub id: u64,
    pub addr: String,
    pub enabled: bool,
    pub hit_count: u64,
    /// "INT3", "HW", "one-shot", etc.
    pub kind: String,
}

/// An asynchronous event pushed by a backend (future use once event loop is wired).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendEvent {
    Breakpoint { id: u64, addr: String, tid: String },
    Exception { addr: String, code: u64, tid: String },
    Exited { exit_code: i32 },
    ModuleLoad { name: String, base: String, size: u64 },
    ModuleUnload { name: String },
    ThreadCreate { tid: String },
    ThreadExit { tid: String, exit_code: i32 },
}
