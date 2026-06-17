use anyhow::{Context, Result};
use hywdbg_protocol::{RpcRequest, RpcResponse};
use serde_json::Value;
use std::io::{self, BufRead, Write};

pub trait BackendHandler {
    fn handle(&mut self, method: &str, params: Option<Value>) -> RpcResponse;
}

pub fn run_stdio_backend(mut handler: impl BackendHandler) -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line.context("stdin read failed")?;
        if line.trim().is_empty() {
            continue;
        }

        let mut response = match serde_json::from_str::<RpcRequest>(&line) {
            Ok(req) => {
                let mut resp = handler.handle(&req.method, req.params);
                resp.id = req.id;
                resp
            }
            Err(e) => RpcResponse::err(0, "bad_json", format!("cannot parse request: {e}")),
        };

        let encoded = serde_json::to_string(&response)?;
        writeln!(stdout, "{encoded}")?;
        stdout.flush()?;
    }

    Ok(())
}

pub fn param_str(params: &Option<Value>, key: &str) -> Option<String> {
    params.as_ref()?.get(key)?.as_str().map(ToString::to_string)
}

pub fn param_u64(params: &Option<Value>, key: &str) -> Result<Option<u64>, String> {
    let Some(v) = params.as_ref().and_then(|p| p.get(key)) else { return Ok(None); };
    hywdbg_protocol::parse_u64ish(v).map(Some)
}
