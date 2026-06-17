use anyhow::Result;
use hywdbg_core::{CoreConfig, CoreHandle};
use hywdbg_protocol::{RpcRequest, RpcResponse};
use std::env;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

const MAX_HTTP_BODY: usize = 1024 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    let listen = arg_value(&args, "--listen").unwrap_or_else(|| "127.0.0.1:31337".to_string());
    let http_listen =
        arg_value(&args, "--http-listen").unwrap_or_else(|| "127.0.0.1:31338".to_string());
    let backend_dir = arg_value(&args, "--backend-dir")
        .map(PathBuf::from)
        .unwrap_or_else(default_backend_dir);

    let core = CoreHandle::new(CoreConfig { backend_dir });
    tokio::try_join!(
        serve_tcp(core.clone(), listen),
        serve_http(core, http_listen)
    )?;

    Ok(())
}

async fn serve_tcp(core: CoreHandle, listen: String) -> Result<()> {
    let listener = TcpListener::bind(&listen).await?;
    info!("HYWDbg core TCP listening on {listen}");

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("frontend connected: {addr}");
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(core, stream).await {
                error!("client error: {e:#}");
            }
        });
    }
}

async fn serve_http(core: CoreHandle, listen: String) -> Result<()> {
    let listener = TcpListener::bind(&listen).await?;
    info!("HYWDbg core HTTP listening on http://{listen}/rpc");

    loop {
        let (stream, addr) = listener.accept().await?;
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http_client(core, stream).await {
                error!("http client {addr} error: {e:#}");
            }
        });
    }
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find_map(|w| {
        if w[0] == name {
            Some(w[1].clone())
        } else {
            None
        }
    })
}

fn default_backend_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

async fn handle_client(core: CoreHandle, stream: TcpStream) -> Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();
    
    let write_half = std::sync::Arc::new(tokio::sync::Mutex::new(write_half));

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let core = core.clone();
        let write_half = write_half.clone();
        
        tokio::spawn(async move {
            let response = match serde_json::from_str::<RpcRequest>(&line) {
                Ok(req) => {
                    core.handle_frontend_request(req.id, &req.method, req.params).await
                }
                Err(e) => {
                    RpcResponse::err(0, "bad_json", format!("cannot parse frontend request: {e}"))
                }
            };

            if let Ok(encoded) = serde_json::to_string(&response) {
                let mut w = write_half.lock().await;
                let _ = w.write_all(encoded.as_bytes()).await;
                let _ = w.write_all(b"\n").await;
                let _ = w.flush().await;
            }
        });
    }

    Ok(())
}

async fn handle_http_client(core: CoreHandle, stream: TcpStream) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).await? == 0 {
            return Ok(());
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    if method == "OPTIONS" {
        let mut stream = reader.into_inner();
        return write_http_response(&mut stream, "204 No Content", "text/plain", b"").await;
    }
    if method != "POST" || path != "/rpc" {
        let mut stream = reader.into_inner();
        return write_http_response(
            &mut stream,
            "404 Not Found",
            "application/json",
            br#"{"error":"not found"}"#,
        )
        .await;
    }
    if content_length > MAX_HTTP_BODY {
        let mut stream = reader.into_inner();
        return write_http_response(
            &mut stream,
            "413 Payload Too Large",
            "application/json",
            br#"{"error":"request body too large"}"#,
        )
        .await;
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).await?;
    let mut stream = reader.into_inner();

    let response = match serde_json::from_slice::<RpcRequest>(&body) {
        Ok(req) => {
            core.handle_frontend_request(req.id, &req.method, req.params)
                .await
        }
        Err(e) => RpcResponse::err(0, "bad_json", format!("cannot parse frontend request: {e}")),
    };
    let encoded = serde_json::to_vec(&response)?;
    write_http_response(
        &mut stream,
        "200 OK",
        "application/json; charset=utf-8",
        &encoded,
    )
    .await
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Headers: content-type\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
