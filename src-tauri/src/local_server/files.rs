use super::{ApiError, LocalServerState};
use axum::{extract::Query, extract::State, Json};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ssh2::{Session, Sftp};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    path::Path as FsPath,
    sync::{Arc, Mutex},
};

pub(crate) type FileSessions = Arc<Mutex<HashMap<String, FileSession>>>;

pub(crate) fn new_file_sessions() -> FileSessions {
    Arc::new(Mutex::new(HashMap::new()))
}

#[derive(Clone)]
pub(crate) struct FileSession {
    config: FileSessionConfig,
    session: Arc<Mutex<Session>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileSessionConfig {
    session_id: Option<String>,
    ip: String,
    port: u16,
    username: String,
    password: Option<String>,
    #[serde(alias = "key", alias = "privateKey")]
    ssh_key: Option<String>,
    key_password: Option<String>,
    auth_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionPathQuery {
    session_id: String,
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionRequest {
    session_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileContentRequest {
    session_id: String,
    path: String,
    content: String,
    file_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateFolderRequest {
    session_id: String,
    path: String,
    folder_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeleteItemRequest {
    session_id: String,
    path: String,
    is_directory: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RenameItemRequest {
    session_id: String,
    old_path: String,
    new_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MoveItemRequest {
    session_id: String,
    old_path: String,
    new_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DownloadRequest {
    session_id: String,
    path: String,
}

pub(crate) async fn file_connect(
    State(state): State<LocalServerState>,
    Json(config): Json<FileSessionConfig>,
) -> Result<Json<Value>, ApiError> {
    let session_id = config
        .session_id
        .clone()
        .ok_or_else(|| ApiError::bad_request("sessionId is required"))?;
    let ssh_session = connect_file_session(&config)?;
    state
        .file_sessions
        .lock()
        .map_err(|_| ApiError::internal("File session lock poisoned"))?
        .insert(
            session_id.clone(),
            FileSession {
                config,
                session: Arc::new(Mutex::new(ssh_session)),
            },
        );

    Ok(Json(json!({
        "success": true,
        "connected": true,
        "sessionId": session_id,
        "connectionLogs": [{
            "type": "success",
            "stage": "ready",
            "message": "SFTP connected"
        }]
    })))
}

pub(crate) async fn file_disconnect(
    State(state): State<LocalServerState>,
    Json(payload): Json<SessionRequest>,
) -> Result<Json<Value>, ApiError> {
    state
        .file_sessions
        .lock()
        .map_err(|_| ApiError::internal("File session lock poisoned"))?
        .remove(&payload.session_id);
    Ok(Json(json!({ "success": true, "connected": false })))
}

pub(crate) async fn file_status(
    State(state): State<LocalServerState>,
    Query(payload): Query<SessionRequest>,
) -> Result<Json<Value>, ApiError> {
    let connected = state
        .file_sessions
        .lock()
        .map_err(|_| ApiError::internal("File session lock poisoned"))?
        .contains_key(&payload.session_id);
    Ok(Json(json!({ "connected": connected })))
}

pub(crate) async fn file_keepalive(
    State(state): State<LocalServerState>,
    Json(payload): Json<SessionRequest>,
) -> Result<Json<Value>, ApiError> {
    let session = file_session(&state, &payload.session_id).ok();
    let connected = session
        .as_ref()
        .and_then(|session| session.session.lock().ok())
        .is_some_and(|session| session.authenticated());
    Ok(Json(
        json!({ "success": connected, "connected": connected }),
    ))
}

pub(crate) async fn file_list(
    State(state): State<LocalServerState>,
    Query(payload): Query<SessionPathQuery>,
) -> Result<Json<Value>, ApiError> {
    let path = payload.path.unwrap_or_else(|| "/".to_string());
    let sftp = file_sftp(&state, &payload.session_id)?;
    let entries = sftp
        .readdir(FsPath::new(&path))
        .map_err(|error| ApiError::bad_request(format!("Failed to list {path}: {error}")))?;

    let files: Vec<Value> = entries
        .into_iter()
        .filter_map(|(entry_path, stat)| {
            let name = entry_path.file_name()?.to_string_lossy().to_string();
            if name == "." || name == ".." {
                return None;
            }
            let permissions = mode_to_permissions(stat.perm.unwrap_or(0));
            let file_type = file_type_from_perm(stat.perm.unwrap_or(0));
            Some(json!({
                "name": name,
                "type": file_type,
                "size": if file_type == "directory" { Value::Null } else { json!(stat.size.unwrap_or(0)) },
                "modified": stat.mtime.unwrap_or(0).to_string(),
                "permissions": permissions,
                "owner": stat.uid.map(|v| v.to_string()).unwrap_or_default(),
                "group": stat.gid.map(|v| v.to_string()).unwrap_or_default(),
                "path": join_remote_path(&path, &name),
                "executable": file_type == "file" && is_executable_permissions(&permissions, &name),
            }))
        })
        .collect();

    Ok(Json(json!({ "files": files, "path": path })))
}

pub(crate) async fn file_read(
    State(state): State<LocalServerState>,
    Query(payload): Query<SessionPathQuery>,
) -> Result<Json<Value>, ApiError> {
    let path = payload
        .path
        .ok_or_else(|| ApiError::bad_request("path is required"))?;
    let bytes = read_remote_file(&state, &payload.session_id, &path)?;
    match String::from_utf8(bytes) {
        Ok(content) => Ok(Json(
            json!({ "content": content, "path": path, "encoding": "utf8" }),
        )),
        Err(error) => Ok(Json(json!({
            "content": general_purpose::STANDARD.encode(error.into_bytes()),
            "path": path,
            "encoding": "base64"
        }))),
    }
}

pub(crate) async fn file_write(
    State(state): State<LocalServerState>,
    Json(payload): Json<FileContentRequest>,
) -> Result<Json<Value>, ApiError> {
    write_remote_file(
        &state,
        &payload.session_id,
        &payload.path,
        payload.content.as_bytes(),
    )?;
    Ok(Json(
        json!({ "success": true, "message": "File written successfully" }),
    ))
}

pub(crate) async fn file_upload(
    State(state): State<LocalServerState>,
    Json(payload): Json<FileContentRequest>,
) -> Result<Json<Value>, ApiError> {
    let file_name = payload
        .file_name
        .ok_or_else(|| ApiError::bad_request("fileName is required"))?;
    let target_path = join_remote_path(&payload.path, &file_name);
    let bytes = decode_upload_content(&payload.content)?;
    write_remote_file(&state, &payload.session_id, &target_path, &bytes)?;
    Ok(Json(
        json!({ "success": true, "message": "File uploaded successfully" }),
    ))
}

pub(crate) async fn file_download(
    State(state): State<LocalServerState>,
    Json(payload): Json<DownloadRequest>,
) -> Result<Json<Value>, ApiError> {
    let path = payload.path;
    let bytes = read_remote_file(&state, &payload.session_id, &path)?;
    let file_name = FsPath::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    Ok(Json(json!({
        "content": general_purpose::STANDARD.encode(bytes),
        "path": path,
        "fileName": file_name,
        "encoding": "base64",
        "mimeType": "application/octet-stream"
    })))
}

pub(crate) async fn file_create(
    State(state): State<LocalServerState>,
    Json(payload): Json<FileContentRequest>,
) -> Result<Json<Value>, ApiError> {
    let file_name = payload
        .file_name
        .ok_or_else(|| ApiError::bad_request("fileName is required"))?;
    let target_path = join_remote_path(&payload.path, &file_name);
    write_remote_file(
        &state,
        &payload.session_id,
        &target_path,
        payload.content.as_bytes(),
    )?;
    Ok(Json(
        json!({ "success": true, "message": "File created successfully" }),
    ))
}

pub(crate) async fn file_mkdir(
    State(state): State<LocalServerState>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<Value>, ApiError> {
    let target_path = join_remote_path(&payload.path, &payload.folder_name);
    let sftp = file_sftp(&state, &payload.session_id)?;
    sftp.mkdir(FsPath::new(&target_path), 0o755)
        .map_err(|error| ApiError::bad_request(format!("Failed to create folder: {error}")))?;
    Ok(Json(
        json!({ "success": true, "message": "Folder created successfully" }),
    ))
}

pub(crate) async fn file_delete(
    State(state): State<LocalServerState>,
    Json(payload): Json<DeleteItemRequest>,
) -> Result<Json<Value>, ApiError> {
    let sftp = file_sftp(&state, &payload.session_id)?;
    let result = if payload.is_directory.unwrap_or(false) {
        sftp.rmdir(FsPath::new(&payload.path))
    } else {
        sftp.unlink(FsPath::new(&payload.path))
    };
    result.map_err(|error| ApiError::bad_request(format!("Failed to delete item: {error}")))?;
    Ok(Json(
        json!({ "success": true, "message": "Item deleted successfully" }),
    ))
}

pub(crate) async fn file_rename(
    State(state): State<LocalServerState>,
    Json(payload): Json<RenameItemRequest>,
) -> Result<Json<Value>, ApiError> {
    let parent = FsPath::new(&payload.old_path)
        .parent()
        .and_then(FsPath::to_str)
        .unwrap_or("/");
    let new_path = join_remote_path(parent, &payload.new_name);
    rename_remote_path(&state, &payload.session_id, &payload.old_path, &new_path)?;
    Ok(Json(
        json!({ "success": true, "message": "Item renamed successfully" }),
    ))
}

pub(crate) async fn file_move(
    State(state): State<LocalServerState>,
    Json(payload): Json<MoveItemRequest>,
) -> Result<Json<Value>, ApiError> {
    rename_remote_path(
        &state,
        &payload.session_id,
        &payload.old_path,
        &payload.new_path,
    )?;
    Ok(Json(
        json!({ "success": true, "message": "Item moved successfully" }),
    ))
}

fn file_session(state: &LocalServerState, session_id: &str) -> Result<FileSession, ApiError> {
    state
        .file_sessions
        .lock()
        .map_err(|_| ApiError::internal("File session lock poisoned"))?
        .get(session_id)
        .cloned()
        .ok_or_else(|| ApiError::bad_request("SSH connection not established"))
}

fn file_sftp(state: &LocalServerState, session_id: &str) -> Result<Sftp, ApiError> {
    let file_session = file_session(state, session_id)?;
    let session = file_session
        .session
        .lock()
        .map_err(|_| ApiError::internal("SSH session lock poisoned"))?;
    if !session.authenticated() {
        drop(session);
        let reconnected = connect_file_session(&file_session.config)?;
        let mut stored = file_session
            .session
            .lock()
            .map_err(|_| ApiError::internal("SSH session lock poisoned"))?;
        *stored = reconnected;
        return stored
            .sftp()
            .map_err(|error| ApiError::internal(format!("Failed to open SFTP: {error}")));
    }
    session
        .sftp()
        .map_err(|error| ApiError::internal(format!("Failed to open SFTP: {error}")))
}

fn connect_file_session(config: &FileSessionConfig) -> Result<Session, ApiError> {
    let tcp = TcpStream::connect(format!("{}:{}", config.ip, config.port))
        .map_err(|error| ApiError::bad_request(format!("TCP connection failed: {error}")))?;
    let mut session = Session::new()
        .map_err(|error| ApiError::internal(format!("SSH session failed: {error}")))?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|error| ApiError::bad_request(format!("SSH handshake failed: {error}")))?;

    let auth_type = config.auth_type.as_deref().unwrap_or("password");
    if auth_type == "key" {
        let key = config
            .ssh_key
            .as_deref()
            .filter(|key| !key.trim().is_empty())
            .ok_or_else(|| ApiError::bad_request("SSH key is missing"))?;
        session
            .userauth_pubkey_memory(&config.username, None, key, config.key_password.as_deref())
            .map_err(|error| {
                ApiError::bad_request(format!("SSH key authentication failed: {error}"))
            })?;
    } else {
        let password = config
            .password
            .as_deref()
            .filter(|password| !password.is_empty())
            .ok_or_else(|| ApiError::bad_request("SSH password is missing"))?;
        session
            .userauth_password(&config.username, password)
            .map_err(|error| {
                ApiError::bad_request(format!("SSH password authentication failed: {error}"))
            })?;
    }

    if !session.authenticated() {
        return Err(ApiError::bad_request("SSH authentication failed"));
    }
    Ok(session)
}

fn write_remote_file(
    state: &LocalServerState,
    session_id: &str,
    path: &str,
    bytes: &[u8],
) -> Result<(), ApiError> {
    let sftp = file_sftp(state, session_id)?;
    let mut file = sftp
        .create(FsPath::new(path))
        .map_err(|error| ApiError::bad_request(format!("Failed to open remote file: {error}")))?;
    file.write_all(bytes)
        .map_err(|error| ApiError::internal(format!("Failed to write remote file: {error}")))
}

fn read_remote_file(
    state: &LocalServerState,
    session_id: &str,
    path: &str,
) -> Result<Vec<u8>, ApiError> {
    let sftp = file_sftp(state, session_id)?;
    let mut file = sftp
        .open(FsPath::new(path))
        .map_err(|error| ApiError::not_found(format!("Failed to open {path}: {error}")))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| ApiError::internal(format!("Failed to read {path}: {error}")))?;
    Ok(bytes)
}

fn rename_remote_path(
    state: &LocalServerState,
    session_id: &str,
    old_path: &str,
    new_path: &str,
) -> Result<(), ApiError> {
    let sftp = file_sftp(state, session_id)?;
    sftp.rename(FsPath::new(old_path), FsPath::new(new_path), None)
        .map_err(|error| ApiError::bad_request(format!("Failed to rename item: {error}")))
}

fn decode_upload_content(content: &str) -> Result<Vec<u8>, ApiError> {
    let encoded = content
        .split_once(',')
        .map(|(_, data)| data)
        .unwrap_or(content);
    general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| ApiError::bad_request(format!("Invalid upload content: {error}")))
}

fn join_remote_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn file_type_from_perm(mode: u32) -> &'static str {
    match mode & 0o170000 {
        0o040000 => "directory",
        0o120000 => "link",
        _ => "file",
    }
}

fn mode_to_permissions(mode: u32) -> String {
    let prefix = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        _ => '-',
    };
    let mut result = String::with_capacity(10);
    result.push(prefix);
    for bit in [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ] {
        result.push(match bit {
            0o400 | 0o040 | 0o004 if mode & bit != 0 => 'r',
            0o200 | 0o020 | 0o002 if mode & bit != 0 => 'w',
            0o100 | 0o010 | 0o001 if mode & bit != 0 => 'x',
            _ => '-',
        });
    }
    result
}

fn is_executable_permissions(permissions: &str, file_name: &str) -> bool {
    let has_execute = permissions.as_bytes().get(3) == Some(&b'x')
        || permissions.as_bytes().get(6) == Some(&b'x')
        || permissions.as_bytes().get(9) == Some(&b'x');
    has_execute
        && ([
            ".sh", ".py", ".pl", ".rb", ".js", ".php", ".bash", ".zsh", ".fish", ".bin", ".exe",
            ".out",
        ]
        .iter()
        .any(|ext| file_name.to_lowercase().ends_with(ext))
            || !file_name.contains('.'))
}
