use super::{resolve_credential_auth, LocalServerState};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use serde::Deserialize;
use serde_json::{json, Value};
use ssh2::Session;
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::mpsc::{self as std_mpsc, TryRecvError},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::mpsc as tokio_mpsc;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SSH_OPERATION_TIMEOUT_MS: u32 = 20_000;
const SSH_KEEPALIVE_INTERVAL_SECS: u32 = 15;
const SSH_KEEPALIVE_TICK: Duration = Duration::from_secs(10);
const IDLE_SLEEP: Duration = Duration::from_millis(5);
const MAX_PENDING_INPUT_BYTES: usize = 1024 * 1024;

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
    credential_id: Option<i64>,
    user_id: Option<String>,
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

pub(crate) async fn terminal_ws(
    State(state): State<LocalServerState>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_terminal_socket(state, socket))
}

async fn handle_terminal_socket(state: LocalServerState, mut socket: WebSocket) {
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

                        let (new_input_tx, new_output_rx) = spawn_ssh_terminal(state.clone(), connect_data);
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
            _ = tokio::time::sleep(Duration::from_millis(8)) => {
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
    state: LocalServerState,
    connect_data: TerminalConnectData,
) -> (
    std_mpsc::Sender<TerminalCommand>,
    tokio_mpsc::UnboundedReceiver<Value>,
) {
    let (input_tx, input_rx) = std_mpsc::channel::<TerminalCommand>();
    let (output_tx, output_rx) = tokio_mpsc::unbounded_channel::<Value>();

    thread::spawn(move || {
        if let Err(error) = run_ssh_terminal(&state, connect_data, input_rx, output_tx.clone()) {
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
    state: &LocalServerState,
    connect_data: TerminalConnectData,
    input_rx: std_mpsc::Receiver<TerminalCommand>,
    output_tx: tokio_mpsc::UnboundedSender<Value>,
) -> Result<(), String> {
    let mut host = connect_data.host_config;
    apply_terminal_credential(state, &mut host)?;
    let tcp = connect_tcp(&host.ip, host.port)?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(10))).ok();

    let mut session = Session::new().map_err(|error| format!("SSH session failed: {error}"))?;
    session.set_timeout(SSH_OPERATION_TIMEOUT_MS);
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
    session.set_keepalive(true, SSH_KEEPALIVE_INTERVAL_SECS);
    session.set_blocking(false);

    let _ = output_tx.send(json!({ "type": "connected", "message": "SSH connected" }));

    let mut buffer = [0_u8; 8192];
    let mut pending_input = VecDeque::<u8>::new();
    let mut next_keepalive = Instant::now() + SSH_KEEPALIVE_TICK;
    loop {
        loop {
            match input_rx.try_recv() {
                Ok(command) => match command {
                    TerminalCommand::Input(input) => {
                        if pending_input.len() + input.len() > MAX_PENDING_INPUT_BYTES {
                            return Err("SSH input buffer is full".to_string());
                        }
                        pending_input.extend(input.bytes());
                    }
                    TerminalCommand::Resize { cols, rows } => {
                        channel
                            .request_pty_size(cols, rows, None, None)
                            .map_err(|error| format!("PTY resize failed: {error}"))?;
                    }
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    let _ = channel.close();
                    let _ = channel.wait_close();
                    return Ok(());
                }
            }
        }

        flush_pending_input(&mut channel, &mut pending_input)?;

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

        if Instant::now() >= next_keepalive {
            match session.keepalive_send() {
                Ok(seconds) => {
                    let delay = if seconds == 0 {
                        SSH_KEEPALIVE_TICK
                    } else {
                        Duration::from_secs(u64::from(seconds))
                    };
                    next_keepalive = Instant::now() + delay.min(SSH_KEEPALIVE_TICK);
                }
                Err(error) => {
                    let io_error = std::io::Error::from(error);
                    if io_error.kind() != std::io::ErrorKind::WouldBlock {
                        return Err(format!("SSH keepalive failed: {io_error}"));
                    }
                    next_keepalive = Instant::now() + Duration::from_millis(250);
                }
            }
        }

        thread::sleep(IDLE_SLEEP);
    }

    Ok(())
}

fn apply_terminal_credential(
    state: &LocalServerState,
    host: &mut TerminalHostConfig,
) -> Result<(), String> {
    if host.auth_type.as_deref() != Some("credential") {
        return Ok(());
    }

    let Some(credential) =
        resolve_credential_auth(state, host.credential_id, host.user_id.as_deref())?
    else {
        return Err("Credential is required".to_string());
    };

    if let Some(username) = credential.username {
        host.username = username;
    }
    host.password = credential.password;
    host.key = credential.key;
    host.key_password = credential.key_password;
    host.auth_type = Some(credential.auth_type);
    Ok(())
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let address = format!("{host}:{port}");
    let addresses = address
        .to_socket_addrs()
        .map_err(|error| format!("Failed to resolve {address}: {error}"))?;

    let mut last_error = None;
    for socket_address in addresses {
        match TcpStream::connect_timeout(&socket_address, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(format!(
        "TCP connection failed: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no resolved addresses".to_string())
    ))
}

fn flush_pending_input(
    channel: &mut ssh2::Channel,
    pending_input: &mut VecDeque<u8>,
) -> Result<(), String> {
    while !pending_input.is_empty() {
        let contiguous = pending_input.make_contiguous();
        match channel.write(contiguous) {
            Ok(0) => break,
            Ok(bytes_written) => {
                pending_input.drain(..bytes_written);
                channel.flush().ok();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(format!("SSH write failed: {error}")),
        }
    }

    Ok(())
}
