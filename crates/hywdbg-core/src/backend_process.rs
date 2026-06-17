use anyhow::{anyhow, Context, Result};
use hywdbg_protocol::{RpcRequest, RpcResponse};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;

pub struct BackendProcess {
    pub kind: String,
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    next_id: Mutex<u64>,
    pending: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, tokio::sync::oneshot::Sender<RpcResponse>>>>,
}

impl BackendProcess {
    pub async fn spawn(kind: String, path: PathBuf) -> Result<Self> {
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn backend {kind} at {}", path.display()))?;

        let stdin = child.stdin.take().ok_or_else(|| anyhow!("backend stdin unavailable"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("backend stdout unavailable"))?;

        let pending = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<u64, tokio::sync::oneshot::Sender<RpcResponse>>::new()));
        let pending_clone = pending.clone();

        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(stdout);
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line).await {
                if n == 0 { break; }
                if let Ok(resp) = serde_json::from_str::<RpcResponse>(&line) {
                    let mut p = pending_clone.lock().unwrap();
                    if let Some(tx) = p.remove(&resp.id) {
                        let _ = tx.send(resp);
                    }
                }
                line.clear();
            }
        });

        Ok(Self {
            kind,
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            next_id: Mutex::new(1),
            pending,
        })
    }

    pub async fn request(&self, method: impl Into<String>, params: Option<Value>) -> Result<RpcResponse> {
        let id = {
            let mut next_id = self.next_id.lock().await;
            let id = *next_id;
            *next_id += 1;
            id
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut p = self.pending.lock().unwrap();
            p.insert(id, tx);
        }

        let req = RpcRequest { id, method: method.into(), params };
        let line = serde_json::to_string(&req)?;

        {
            let mut stdin = self.stdin.lock().await;
            stdin.write_all(line.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
        }

        match rx.await {
            Ok(resp) => Ok(resp),
            Err(_) => Err(anyhow!("backend closed stdout before responding")),
        }
    }

    pub async fn kill(&self) -> Result<()> {
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        Ok(())
    }
}
