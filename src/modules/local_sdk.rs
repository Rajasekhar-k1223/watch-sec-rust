use std::path::Path;
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use serde_json::Value;

pub fn start_sdk_server() -> broadcast::Sender<Value> {
    let (tx, _rx) = broadcast::channel::<Value>(100);
    let tx_clone = tx.clone();

    #[cfg(unix)]
    {
        tokio::spawn(async move {
            let socket_path = "/tmp/monitorix_sdk.sock";
            if Path::new(socket_path).exists() {
                let _ = std::fs::remove_file(socket_path);
            }

            match UnixListener::bind(socket_path) {
                Ok(listener) => {
                    println!("[SDK] Federation Server listening on {}", socket_path);
                    
                    loop {
                        if let Ok((mut stream, _addr)) = listener.accept().await {
                            let mut rx = tx_clone.subscribe();
                            tokio::spawn(async move {
                                println!("[SDK] New local connection established.");
                                
                                loop {
                                    if let Ok(event) = rx.recv().await {
                                        if let Some(severity) = event.get("severity").and_then(|s| s.as_str()) {
                                            if severity == "HIGH" || severity == "CRITICAL" {
                                                let payload = format!("{}\n", serde_json::to_string(&event).unwrap_or_default());
                                                if let Err(e) = stream.write_all(payload.as_bytes()).await {
                                                    eprintln!("[SDK] Failed to send to client: {}", e);
                                                    break;
                                                }
                                            }
                                        }
                                    } else {
                                        break; // Channel closed or lagged
                                    }
                                }
                                println!("[SDK] Client disconnected.");
                            });
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[SDK] Failed to bind to socket {}: {}", socket_path, e);
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        println!("[SDK] Unix domain sockets are not supported on this platform. SDK disabled.");
    }

    tx
}
