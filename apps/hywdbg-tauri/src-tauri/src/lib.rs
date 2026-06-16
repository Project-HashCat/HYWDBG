use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[tauri::command]
fn core_request(method: String, params: Option<Value>) -> Result<String, String> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let req = serde_json::json!({"id": id, "method": method, "params": params});

    let mut stream = TcpStream::connect("127.0.0.1:31337").map_err(|e| format!("connect core failed: {e}"))?;
    writeln!(stream, "{}", req).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![core_request])
        .run(tauri::generate_context!())
        .expect("error while running HYWDbg Tauri app");
}
