use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
};
use serde::Deserialize;
use serde_json::{json, Value};
use ssh2::Session;
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::mpsc as std_mpsc,
    thread,
    time::Duration,
};
use tokio::sync::mpsc as tokio_mpsc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TerminalHostConfig {
    ip: String,
    port: u16,
    username: String,
    password: Option<String>,
    #[serde(alias = "sshKey", alias = "privateKey")]
    key: Option<String>,
    key_password: Option<String>,
    auth_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TerminalConnectData {
    cols: Option<u32>,
    rows: Option<u32>,
    #[serde(rename = "hostConfig")]
    host_config: TerminalHostConfig,
}

#[derive(Debug, Deserialize)]
struct TerminalMessage {
    #[serde(rename = "type")]
    message_type: String,
    data: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ResizeRequest {
    cols: Option<u32>,
    rows: Option<u32>,
}

enum TerminalCommand {
    Input(String),
    Resize { cols: u32, rows: u32 },
}

pub(crate) async fn terminal_ws(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_terminal_socket)
}

async fn handle_terminal_socket(mut socket: WebSocket) {
    let mut input_tx: Option<std_mpsc::Sender<TerminalCommand>> = None;
    let mut output_rx: Option<tokio_mpsc::UnboundedReceiver<Value>> = None;

    loop {
        tokio::select! {
            message = socket.recv() => {
                let Some(Ok(message)) = message else {
                    break;
                };

                let Message::Text(text) = message else {
                    continue;
                };

                let parsed = serde_json::from_str::<TerminalMessage>(&text);
                let Ok(parsed) = parsed else {
                    let _ = socket
                        .send(Message::Text(
                            json!({ "type": "error", "message": "Invalid terminal message" })
                                .to_string()
                                .into(),
                        ))
                        .await;
                    continue;
                };

                match parsed.message_type.as_str() {
                    "ping" => {
                        let _ = socket
                            .send(Message::Text(json!({ "type": "pong" }).to_string().into()))
                            .await;
                    }
                    "connectToHost" | "reconnect_with_credentials" => {
                        let Some(data) = parsed.data else {
                            let _ = socket
                                .send(Message::Text(
                                    json!({ "type": "error", "message": "Missing connection data" })
                                        .to_string()
                                        .into(),
                                ))
                                .await;
                            continue;
                        };

                        let connect_data = serde_json::from_value::<TerminalConnectData>(data);
                        let Ok(connect_data) = connect_data else {
                            let _ = socket
                                .send(Message::Text(
                                    json!({ "type": "error", "message": "Invalid connection data" })
                                        .to_string()
                                        .into(),
                                ))
                                .await;
                            continue;
                        };

                        let (new_input_tx, new_output_rx) = spawn_ssh_terminal(connect_data);
                        input_tx = Some(new_input_tx);
                        output_rx = Some(new_output_rx);
                    }
                    "input" => {
                        if let (Some(tx), Some(data)) = (&input_tx, parsed.data) {
                            if let Some(input) = data.as_str() {
                                let _ = tx.send(TerminalCommand::Input(input.to_string()));
                            }
                        }
                    }
                    "resize" => {
                        if let (Some(tx), Some(data)) = (&input_tx, parsed.data) {
                            if let Ok(size) = serde_json::from_value::<ResizeRequest>(data) {
                                if let (Some(cols), Some(rows)) = (size.cols, size.rows) {
                                    let _ = tx.send(TerminalCommand::Resize { cols, rows });
                                }
                            }
                        }
                    }
                    "disconnect" => {
                        break;
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(2)) => {
                let mut pending = Vec::new();
                if let Some(rx) = output_rx.as_mut() {
                    while let Ok(event) = rx.try_recv() {
                        pending.push(event);
                    }
                }
                for event in pending {
                    if socket.send(Message::Text(event.to_string().into())).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

fn spawn_ssh_terminal(
    connect_data: TerminalConnectData,
) -> (
    std_mpsc::Sender<TerminalCommand>,
    tokio_mpsc::UnboundedReceiver<Value>,
) {
    let (input_tx, input_rx) = std_mpsc::channel::<TerminalCommand>();
    let (output_tx, output_rx) = tokio_mpsc::unbounded_channel::<Value>();

    thread::spawn(move || {
        if let Err(error) = run_ssh_terminal(connect_data, input_rx, output_tx.clone()) {
            let message = format!("Failed to connect to host: {error}");
            let event = if error.contains("key is missing") || error.contains("password is missing")
            {
                json!({
                    "type": "auth_method_not_available",
                    "message": message
                })
            } else {
                json!({
                    "type": "error",
                    "message": message
                })
            };
            let _ = output_tx.send(event);
        }
    });

    (input_tx, output_rx)
}

fn run_ssh_terminal(
    connect_data: TerminalConnectData,
    input_rx: std_mpsc::Receiver<TerminalCommand>,
    output_tx: tokio_mpsc::UnboundedSender<Value>,
) -> Result<(), String> {
    let host = connect_data.host_config;
    let tcp = TcpStream::connect(format!("{}:{}", host.ip, host.port))
        .map_err(|error| format!("TCP connection failed: {error}"))?;
    tcp.set_read_timeout(Some(Duration::from_millis(50))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(10))).ok();

    let mut session = Session::new().map_err(|error| format!("SSH session failed: {error}"))?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|error| format!("SSH handshake failed: {error}"))?;

    let auth_type = host.auth_type.as_deref().unwrap_or("password");
    if auth_type == "key" {
        let key = host
            .key
            .as_deref()
            .filter(|key| !key.trim().is_empty())
            .ok_or_else(|| "SSH key is missing".to_string())?;
        session
            .userauth_pubkey_memory(&host.username, None, key, host.key_password.as_deref())
            .map_err(|error| format!("SSH key authentication failed: {error}"))?;
    } else if auth_type == "none" {
        session
            .userauth_agent(&host.username)
            .map_err(|error| format!("SSH agent authentication failed: {error}"))?;
    } else {
        let password = host
            .password
            .as_deref()
            .filter(|password| !password.is_empty())
            .ok_or_else(|| "SSH password is missing".to_string())?;
        session
            .userauth_password(&host.username, password)
            .map_err(|error| format!("SSH password authentication failed: {error}"))?;
    }

    if !session.authenticated() {
        return Err("SSH authentication failed".to_string());
    }

    let mut channel = session
        .channel_session()
        .map_err(|error| format!("SSH channel failed: {error}"))?;
    channel
        .request_pty(
            "xterm-256color",
            None,
            Some((
                connect_data.cols.unwrap_or(80),
                connect_data.rows.unwrap_or(24),
                0,
                0,
            )),
        )
        .map_err(|error| format!("PTY request failed: {error}"))?;
    channel
        .shell()
        .map_err(|error| format!("Shell request failed: {error}"))?;
    session.set_blocking(false);

    let _ = output_tx.send(json!({ "type": "connected", "message": "SSH connected" }));

    let mut buffer = [0_u8; 8192];
    loop {
        while let Ok(command) = input_rx.try_recv() {
            match command {
                TerminalCommand::Input(input) => {
                    channel
                        .write_all(input.as_bytes())
                        .map_err(|error| format!("SSH write failed: {error}"))?;
                    channel.flush().ok();
                }
                TerminalCommand::Resize { cols, rows } => {
                    channel
                        .request_pty_size(cols, rows, None, None)
                        .map_err(|error| format!("PTY resize failed: {error}"))?;
                }
            }
        }

        match channel.read(&mut buffer) {
            Ok(0) => {
                if channel.eof() {
                    let _ = output_tx.send(json!({ "type": "session_ended" }));
                    break;
                }
            }
            Ok(n) => {
                let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                let _ = output_tx.send(json!({ "type": "data", "data": data }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(format!("SSH read failed: {error}")),
        }

        thread::sleep(Duration::from_millis(1));
    }

    Ok(())
}
