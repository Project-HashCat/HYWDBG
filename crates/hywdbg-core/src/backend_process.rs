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
    stdout: Mutex<BufReader<tokio::process::ChildStdout>>,
    next_id: Mutex<u64>,
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

        Ok(Self {
            kind,
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: Mutex::new(1),
        })
    }

    pub async fn request(&self, method: impl Into<String>, params: Option<Value>) -> Result<RpcResponse> {
        let id = {
            let mut next_id = self.next_id.lock().await;
            let id = *next_id;
            *next_id += 1;
            id
        };

        let req = RpcRequest { id, method: method.into(), params };
        let line = serde_json::to_string(&req)?;

        {
            let mut stdin = self.stdin.lock().await;
            stdin.write_all(line.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
        }

        let mut buf = String::new();
        {
            let mut stdout = self.stdout.lock().await;
            let n = stdout.read_line(&mut buf).await?;
            if n == 0 {
                return Err(anyhow!("backend closed stdout"));
            }
        }

        let resp: RpcResponse = serde_json::from_str(&buf)
            .with_context(|| format!("backend returned invalid response: {buf}"))?;
        Ok(resp)
    }

    pub async fn kill(&self) -> Result<()> {
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        Ok(())
    }
}
