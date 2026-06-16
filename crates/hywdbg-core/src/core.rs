use crate::backend_process::BackendProcess;
use anyhow::{anyhow, Result};
use hywdbg_protocol::RpcResponse;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Winapi,
    Titan,
    Dbgeng,
    Lldb,
    Gdbremote,
    Frida,
}

impl BackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendKind::Winapi => "winapi",
            BackendKind::Titan => "titan",
            BackendKind::Dbgeng => "dbgeng",
            BackendKind::Lldb => "lldb",
            BackendKind::Gdbremote => "gdbremote",
            BackendKind::Frida => "frida",
        }
    }

    pub fn exe_name(&self) -> &'static str {
        if cfg!(windows) {
            match self {
                BackendKind::Winapi => "winapi-backend.exe",
                BackendKind::Titan => "titan-backend.exe",
                BackendKind::Dbgeng => "dbgeng-backend.exe",
                BackendKind::Lldb => "lldb-backend.exe",
                BackendKind::Gdbremote => "gdbremote-backend.exe",
                BackendKind::Frida => "frida-backend.exe",
            }
        } else {
            match self {
                BackendKind::Winapi => "winapi-backend",
                BackendKind::Titan => "titan-backend",
                BackendKind::Dbgeng => "dbgeng-backend",
                BackendKind::Lldb => "lldb-backend",
                BackendKind::Gdbremote => "gdbremote-backend",
                BackendKind::Frida => "frida-backend",
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub backend_dir: PathBuf,
}

#[derive(Clone)]
pub struct CoreHandle {
    inner: Arc<Mutex<CoreState>>,
    config: CoreConfig,
}

struct CoreState {
    backend: Option<Arc<BackendProcess>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StartBackendParams {
    kind: BackendKind,
    #[serde(default)]
    path: Option<PathBuf>,
}

impl CoreHandle {
    pub fn new(config: CoreConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CoreState { backend: None })),
            config,
        }
    }

    pub async fn handle_frontend_request(&self, id: u64, method: &str, params: Option<Value>) -> RpcResponse {
        match self.handle_frontend_request_inner(id, method, params).await {
            Ok(resp) => resp,
            Err(e) => RpcResponse::err(id, "core_error", e.to_string()),
        }
    }

    async fn handle_frontend_request_inner(&self, id: u64, method: &str, params: Option<Value>) -> Result<RpcResponse> {
        match method {
            "core.hello" => Ok(RpcResponse::ok(id, json!({
                "name":"hywdbg-core",
                "version": env!("CARGO_PKG_VERSION"),
                "protocol":"ndjson-jsonrpc-ish",
                "listen_default":"127.0.0.1:31337"
            }))),
            "core.backendStatus" => {
                let state = self.inner.lock().await;
                let result = match &state.backend {
                    Some(b) => json!({"active":true,"kind":b.kind}),
                    None => json!({"active":false}),
                };
                Ok(RpcResponse::ok(id, result))
            }
            "core.startBackend" => self.start_backend(id, params).await,
            "core.stopBackend" => self.stop_backend(id).await,
            m if m.starts_with("dbg.") => {
                let backend_method = m.trim_start_matches("dbg.");
                self.forward_to_backend(id, backend_method, params).await
            }
            _ => Ok(RpcResponse::err(id, "unknown_method", format!("unknown method {method}"))),
        }
    }

    async fn start_backend(&self, id: u64, params: Option<Value>) -> Result<RpcResponse> {
        let params: StartBackendParams = serde_json::from_value(params.unwrap_or(Value::Null))?;

        let mut state = self.inner.lock().await;
        if let Some(existing) = &state.backend {
            return Ok(RpcResponse::err(
                id,
                "backend_already_active",
                format!("backend {} is already active; call core.stopBackend first", existing.kind),
            ));
        }

        let path = params.path.unwrap_or_else(|| self.config.backend_dir.join(params.kind.exe_name()));
        let kind = params.kind.as_str().to_string();
        let backend = Arc::new(BackendProcess::spawn(kind.clone(), path).await?);

        let hello = backend.request("hello", None).await?;
        if !hello.ok {
            return Ok(RpcResponse::err(id, "backend_hello_failed", format!("backend returned {hello:?}")));
        }

        state.backend = Some(backend);
        Ok(RpcResponse::ok(id, json!({"started":true,"kind":kind,"hello":hello.result})))
    }

    async fn stop_backend(&self, id: u64) -> Result<RpcResponse> {
        let backend = {
            let mut state = self.inner.lock().await;
            state.backend.take()
        };

        if let Some(backend) = backend {
            let _ = backend.request("shutdown", None).await;
            let _ = backend.kill().await;
            Ok(RpcResponse::ok(id, json!({"stopped":true})))
        } else {
            Ok(RpcResponse::ok(id, json!({"stopped":false,"reason":"no active backend"})))
        }
    }

    async fn forward_to_backend(&self, id: u64, method: &str, params: Option<Value>) -> Result<RpcResponse> {
        let backend = {
            let state = self.inner.lock().await;
            state.backend.clone().ok_or_else(|| anyhow!("no active backend; call core.startBackend"))?
        };

        let mut resp = backend.request(method, params).await?;
        // Keep frontend request ID stable. Backend has its own internal IDs.
        resp.id = id;
        Ok(resp)
    }
}
