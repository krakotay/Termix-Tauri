mod files;
mod terminal;

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use files::{
    file_connect, file_create, file_delete, file_disconnect, file_download, file_keepalive,
    file_list, file_mkdir, file_move, file_read, file_rename, file_status, file_upload, file_write,
    new_file_sessions,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};
use terminal::terminal_ws;
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

#[derive(Clone)]
pub struct LocalServerState {
    db: Arc<Mutex<Connection>>,
    data_dir: PathBuf,
    file_sessions: files::FileSessions,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    username: String,
    password: String,
    remember_me: Option<bool>,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    #[serde(rename = "userId")]
    user_id: String,
    username: String,
    is_admin: bool,
    is_oidc: bool,
    totp_enabled: bool,
    data_unlocked: bool,
}

pub async fn start(app: AppHandle) -> Result<LocalServerState, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Failed to resolve app data directory: {error}"))?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|error| format!("Failed to create app data directory: {error}"))?;

    let db_path = data_dir.join("termix.sqlite");
    let db = Connection::open(&db_path)
        .map_err(|error| format!("Failed to open local SQLite database: {error}"))?;
    initialize_db(&db).map_err(|error| format!("Failed to initialize database: {error}"))?;

    let state = LocalServerState {
        db: Arc::new(Mutex::new(db)),
        data_dir,
        file_sessions: new_file_sessions(),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/users/setup-required", get(setup_required))
        .route("/users/count", get(user_count))
        .route("/users/registration-allowed", get(true_allowed))
        .route("/users/password-login-allowed", get(true_allowed))
        .route("/users/password-reset-allowed", get(false_allowed))
        .route("/users/oidc-config", get(not_found))
        .route("/users/oidc-config/admin", get(not_found))
        .route("/users/create", post(create_user))
        .route("/users/login", post(login))
        .route("/users/logout", post(logout))
        .route("/users/me", get(me))
        .route("/users/me/token", get(me_token))
        .route("/users/sessions", get(empty_array))
        .route("/users/api-keys", get(empty_array))
        .route("/users/log-level", get(log_level))
        .route("/users/session-timeout", get(session_timeout))
        .route("/users/guacamole-settings", get(guacamole_settings))
        .route("/alerts", get(alerts))
        .route("/credentials", get(empty_array))
        .route("/credentials/folders", get(empty_array))
        .route("/host/db/host", get(list_hosts).post(create_host))
        .route(
            "/host/db/host/{host_id}",
            get(get_host).put(update_host).delete(delete_host),
        )
        .route("/host/db/host/{host_id}/password", get(host_password))
        .route("/host/db/host/{host_id}/export", get(get_host))
        .route("/host/db/hosts/export", get(export_hosts))
        .route("/host/db/all", get(empty_array))
        .route("/host/db/folders/with-stats", get(empty_array))
        .route("/host/folders", get(empty_array))
        .route("/snippets", get(empty_array))
        .route("/snippets/folders", get(empty_array))
        .route("/network-topology/", get(empty_topology))
        .route("/status", get(empty_object))
        .route("/status/{host_id}", get(host_status))
        .route("/metrics/{host_id}", get(metrics_not_found))
        .route("/metrics/start/{host_id}", post(metrics_skipped))
        .route("/metrics/stop/{host_id}", post(ok_response))
        .route("/metrics/heartbeat", post(ok_response))
        .route("/metrics/register-viewer", post(metrics_skipped))
        .route("/metrics/unregister-viewer", post(ok_response))
        .route("/dashboard/preferences", get(dashboard_preferences))
        .route("/activity/recent", get(empty_array))
        .route("/activity/log", post(ok_response))
        .route(
            "/host/file_manager/recent",
            get(empty_array).post(ok_response).delete(ok_response),
        )
        .route(
            "/host/file_manager/pinned",
            get(empty_array).post(ok_response).delete(ok_response),
        )
        .route(
            "/host/file_manager/shortcuts",
            get(empty_array).post(ok_response).delete(ok_response),
        )
        .route("/ssh/file_manager/ssh/connect", post(file_connect))
        .route("/ssh/file_manager/ssh/disconnect", post(file_disconnect))
        .route("/ssh/file_manager/ssh/status", get(file_status))
        .route("/ssh/file_manager/ssh/keepalive", post(file_keepalive))
        .route("/ssh/file_manager/ssh/listFiles", get(file_list))
        .route("/ssh/file_manager/ssh/readFile", get(file_read))
        .route("/ssh/file_manager/ssh/writeFile", post(file_write))
        .route("/ssh/file_manager/ssh/uploadFile", post(file_upload))
        .route("/ssh/file_manager/ssh/downloadFile", post(file_download))
        .route("/ssh/file_manager/ssh/createFile", post(file_create))
        .route("/ssh/file_manager/ssh/createFolder", post(file_mkdir))
        .route("/ssh/file_manager/ssh/deleteItem", delete(file_delete))
        .route("/ssh/file_manager/ssh/renameItem", put(file_rename))
        .route("/ssh/file_manager/ssh/moveItem", put(file_move))
        .route("/uptime", get(uptime))
        .fallback(fallback)
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|_, _| true))
                .allow_credentials(true)
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers([
                    header::ACCEPT,
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    HeaderName::from_static("x-electron-app"),
                ]),
        )
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:30001")
        .await
        .map_err(|error| format!("Failed to bind local server on 127.0.0.1:30001: {error}"))?;

    tauri::async_runtime::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            eprintln!("Termix local Rust server stopped: {error}");
        }
    });

    let terminal_app = Router::new().route("/", get(terminal_ws));
    let terminal_listener = tokio::net::TcpListener::bind("127.0.0.1:30002")
        .await
        .map_err(|error| {
            format!("Failed to bind terminal WebSocket on 127.0.0.1:30002: {error}")
        })?;

    tauri::async_runtime::spawn(async move {
        if let Err(error) = axum::serve(terminal_listener, terminal_app).await {
            eprintln!("Termix terminal Rust server stopped: {error}");
        }
    });

    Ok(state)
}

fn initialize_db(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_oidc INTEGER NOT NULL DEFAULT 0,
            totp_enabled INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        ",
    )
}

async fn health(State(state): State<LocalServerState>) -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "database": "connected",
        "dataDir": state.data_dir.to_string_lossy(),
        "success": true
    }))
}

async fn version() -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "current_version": env!("CARGO_PKG_VERSION")
    }))
}

async fn ok_response() -> Json<Value> {
    Json(json!({ "success": true }))
}

async fn host_status(Path(_host_id): Path<i64>) -> Json<Value> {
    Json(json!({
        "status": "unknown",
        "lastChecked": null
    }))
}

async fn metrics_not_found(Path(_host_id): Path<i64>) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "Metrics are not available in local desktop mode" })),
    )
}

async fn metrics_skipped() -> Json<Value> {
    Json(json!({
        "success": true,
        "skipped": true,
        "reason": "Metrics are not available in local desktop mode"
    }))
}

async fn setup_required(State(state): State<LocalServerState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        json!({ "setup_required": user_count_value(&state)? == 0 }),
    ))
}

async fn user_count(State(state): State<LocalServerState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({ "count": user_count_value(&state)? })))
}

async fn true_allowed() -> Json<Value> {
    Json(json!({ "allowed": true }))
}

async fn false_allowed() -> Json<Value> {
    Json(json!({ "allowed": false }))
}

async fn create_user(
    State(state): State<LocalServerState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<Value>, ApiError> {
    let username = payload.username.trim();
    if username.is_empty() || payload.password.len() < 1 {
        return Err(ApiError::bad_request("Username and password are required"));
    }

    let password_hash = hash(payload.password, DEFAULT_COST)
        .map_err(|error| ApiError::internal(format!("Failed to hash password: {error}")))?;
    let is_admin = user_count_value(&state)? == 0;
    let user_id = Uuid::new_v4().to_string();
    let db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("Database lock poisoned"))?;

    db.execute(
        "INSERT INTO users (id, username, password_hash, is_admin) VALUES (?1, ?2, ?3, ?4)",
        params![
            user_id,
            username,
            password_hash,
            if is_admin { 1 } else { 0 }
        ],
    )
    .map_err(|error| {
        if error.to_string().contains("UNIQUE") {
            ApiError::conflict("Username already exists")
        } else {
            ApiError::internal(format!("Failed to create user: {error}"))
        }
    })?;

    Ok(Json(
        json!({ "success": true, "userId": user_id, "is_admin": is_admin }),
    ))
}

async fn login(
    State(state): State<LocalServerState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let row = {
        let db = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("Database lock poisoned"))?;
        db.query_row(
            "SELECT id, username, password_hash, is_admin, is_oidc, totp_enabled FROM users WHERE username = ?1",
            params![payload.username.trim()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? != 0,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, i64>(5)? != 0,
                ))
            },
        )
        .optional()
        .map_err(|error| ApiError::internal(format!("Failed to query user: {error}")))?
    };

    let Some((user_id, username, password_hash, is_admin, is_oidc, totp_enabled)) = row else {
        return Err(ApiError::unauthorized("Invalid username or password"));
    };

    let ok = verify(payload.password, &password_hash)
        .map_err(|error| ApiError::internal(format!("Failed to verify password: {error}")))?;
    if !ok {
        return Err(ApiError::unauthorized("Invalid username or password"));
    }

    let token = Uuid::new_v4().to_string();
    let max_age = if payload.remember_me.unwrap_or(false) {
        60 * 60 * 24 * 30
    } else {
        60 * 60 * 24
    };
    let now = now_secs();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("Database lock poisoned"))?;
        db.execute(
            "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![token, user_id, now + max_age, now],
        )
        .map_err(|error| ApiError::internal(format!("Failed to create session: {error}")))?;
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "jwt={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        ))
        .map_err(|error| ApiError::internal(format!("Failed to build cookie: {error}")))?,
    );

    Ok((
        headers,
        Json(json!({
            "success": true,
            "is_admin": is_admin,
            "username": username,
            "requires_totp": false,
            "rememberMe": payload.remember_me.unwrap_or(false),
            "is_oidc": is_oidc,
            "totp_enabled": totp_enabled,
            "data_unlocked": true
        })),
    )
        .into_response())
}

async fn logout() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("jwt=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    (
        headers,
        Json(json!({ "success": true, "message": "Logged out" })),
    )
        .into_response()
}

async fn me(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
) -> Result<Json<UserResponse>, ApiError> {
    let (token, user) = authenticated_user(&state, &headers)?;
    let _ = token;
    Ok(Json(user))
}

async fn me_token(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (token, _) = authenticated_user(&state, &headers)?;
    Ok(Json(json!({ "token": token })))
}

async fn list_hosts(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (_, user) = authenticated_user(&state, &headers)?;
    let db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("Database lock poisoned"))?;
    let mut statement = db
        .prepare(
            "SELECT id, data, created_at, updated_at FROM hosts WHERE user_id = ?1 ORDER BY id ASC",
        )
        .map_err(|error| ApiError::internal(format!("Failed to prepare host query: {error}")))?;
    let rows = statement
        .query_map(params![user.user_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| ApiError::internal(format!("Failed to query hosts: {error}")))?;

    let mut hosts = Vec::new();
    for row in rows {
        let (id, data, created_at, updated_at) =
            row.map_err(|error| ApiError::internal(format!("Failed to read host row: {error}")))?;
        hosts.push(host_json(
            id,
            &user.user_id,
            serde_json::from_str(&data).unwrap_or_else(|_| json!({})),
            created_at,
            updated_at,
        ));
    }

    Ok(Json(Value::Array(hosts)))
}

async fn create_host(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let (_, user) = authenticated_user(&state, &headers)?;
    validate_host_payload(&payload)?;

    let now = now_secs();
    let data = serde_json::to_string(&payload)
        .map_err(|error| ApiError::internal(format!("Failed to serialize host: {error}")))?;
    let db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("Database lock poisoned"))?;
    db.execute(
        "INSERT INTO hosts (user_id, data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
        params![user.user_id, data, now, now],
    )
    .map_err(|error| ApiError::internal(format!("Failed to save host: {error}")))?;
    let id = db.last_insert_rowid();

    Ok(Json(host_json(id, &user.user_id, payload, now, now)))
}

async fn get_host(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
    Path(host_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let (_, user) = authenticated_user(&state, &headers)?;
    let db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("Database lock poisoned"))?;
    let host = db
        .query_row(
            "SELECT data, created_at, updated_at FROM hosts WHERE id = ?1 AND user_id = ?2",
            params![host_id, user.user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| ApiError::internal(format!("Failed to load host: {error}")))?;

    let Some((data, created_at, updated_at)) = host else {
        return Err(ApiError::not_found("Host not found"));
    };

    Ok(Json(host_json(
        host_id,
        &user.user_id,
        serde_json::from_str(&data).unwrap_or_else(|_| json!({})),
        created_at,
        updated_at,
    )))
}

async fn update_host(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
    Path(host_id): Path<i64>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let (_, user) = authenticated_user(&state, &headers)?;
    validate_host_payload(&payload)?;

    let now = now_secs();
    let data = serde_json::to_string(&payload)
        .map_err(|error| ApiError::internal(format!("Failed to serialize host: {error}")))?;
    let db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("Database lock poisoned"))?;
    let updated = db
        .execute(
            "UPDATE hosts SET data = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
            params![data, now, host_id, user.user_id],
        )
        .map_err(|error| ApiError::internal(format!("Failed to update host: {error}")))?;
    if updated == 0 {
        return Err(ApiError::not_found("Host not found"));
    }

    Ok(Json(host_json(host_id, &user.user_id, payload, now, now)))
}

async fn delete_host(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
    Path(host_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let (_, user) = authenticated_user(&state, &headers)?;
    let db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("Database lock poisoned"))?;
    db.execute(
        "DELETE FROM hosts WHERE id = ?1 AND user_id = ?2",
        params![host_id, user.user_id],
    )
    .map_err(|error| ApiError::internal(format!("Failed to delete host: {error}")))?;

    Ok(Json(json!({ "success": true })))
}

async fn host_password(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
    Path(host_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let Json(host) = get_host(State(state), headers, Path(host_id)).await?;
    Ok(Json(json!({
        "value": host.get("password").and_then(Value::as_str).unwrap_or("")
    })))
}

async fn export_hosts(
    State(state): State<LocalServerState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let Json(hosts) = list_hosts(State(state), headers).await?;
    Ok(Json(json!({ "hosts": hosts })))
}

async fn empty_array() -> Json<Value> {
    Json(json!([]))
}

async fn empty_object() -> Json<Value> {
    Json(json!({}))
}

async fn empty_topology() -> Json<Value> {
    Json(json!({ "nodes": [], "edges": [] }))
}

async fn alerts() -> Json<Value> {
    Json(json!({ "alerts": [] }))
}

async fn log_level() -> Json<Value> {
    Json(json!({ "level": "info" }))
}

async fn session_timeout() -> Json<Value> {
    Json(json!({ "timeoutHours": 24 }))
}

async fn guacamole_settings() -> Json<Value> {
    Json(json!({ "enabled": false, "url": "" }))
}

async fn dashboard_preferences() -> Json<Value> {
    Json(json!({
        "layout": [],
        "widgets": [],
        "preferences": {}
    }))
}

async fn uptime() -> Json<Value> {
    Json(json!({
        "uptime": 0,
        "startedAt": null
    }))
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "Not configured" })),
    )
}

async fn fallback() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "This local Tauri server endpoint has not been ported to Rust yet",
            "code": "NOT_IMPLEMENTED"
        })),
    )
}

fn user_count_value(state: &LocalServerState) -> Result<i64, ApiError> {
    let db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("Database lock poisoned"))?;
    db.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(|error| ApiError::internal(format!("Failed to count users: {error}")))
}

fn validate_host_payload(payload: &Value) -> Result<(), ApiError> {
    let ip_ok = payload
        .get("ip")
        .and_then(Value::as_str)
        .is_some_and(|v| !v.trim().is_empty());
    let port_ok = payload
        .get("port")
        .and_then(Value::as_i64)
        .is_some_and(|port| (1..=65535).contains(&port));

    if !ip_ok || !port_ok {
        return Err(ApiError::bad_request("Invalid SSH host data"));
    }

    Ok(())
}

fn host_json(id: i64, user_id: &str, mut data: Value, created_at: i64, updated_at: i64) -> Value {
    let object = data.as_object_mut();
    if object.is_none() {
        data = json!({});
    }
    let object = data.as_object_mut().expect("host JSON object");

    object.insert("id".to_string(), json!(id));
    object.insert("userId".to_string(), json!(user_id));
    object
        .entry("connectionType".to_string())
        .or_insert_with(|| json!("ssh"));
    object
        .entry("name".to_string())
        .or_insert_with(|| json!(""));
    object
        .entry("folder".to_string())
        .or_insert_with(|| json!(""));
    object
        .entry("tags".to_string())
        .or_insert_with(|| json!([]));
    object
        .entry("pin".to_string())
        .or_insert_with(|| json!(false));
    object
        .entry("authType".to_string())
        .or_insert_with(|| json!("none"));
    object
        .entry("enableTerminal".to_string())
        .or_insert_with(|| json!(true));
    object
        .entry("enableTunnel".to_string())
        .or_insert_with(|| json!(true));
    object
        .entry("enableFileManager".to_string())
        .or_insert_with(|| json!(true));
    object
        .entry("enableDocker".to_string())
        .or_insert_with(|| json!(false));
    object
        .entry("showTerminalInSidebar".to_string())
        .or_insert_with(|| json!(true));
    object
        .entry("showFileManagerInSidebar".to_string())
        .or_insert_with(|| json!(false));
    object
        .entry("showTunnelInSidebar".to_string())
        .or_insert_with(|| json!(false));
    object
        .entry("showDockerInSidebar".to_string())
        .or_insert_with(|| json!(false));
    object
        .entry("showServerStatsInSidebar".to_string())
        .or_insert_with(|| json!(false));
    object
        .entry("defaultPath".to_string())
        .or_insert_with(|| json!("/"));
    object
        .entry("tunnelConnections".to_string())
        .or_insert_with(|| json!([]));
    object
        .entry("jumpHosts".to_string())
        .or_insert_with(|| json!([]));
    object
        .entry("quickActions".to_string())
        .or_insert_with(|| json!([]));
    object.insert("createdAt".to_string(), json!(timestamp_string(created_at)));
    object.insert("updatedAt".to_string(), json!(timestamp_string(updated_at)));
    object.insert(
        "hasPassword".to_string(),
        json!(object
            .get("password")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())),
    );
    object.insert(
        "hasKey".to_string(),
        json!(object
            .get("key")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())),
    );
    object.insert(
        "hasSudoPassword".to_string(),
        json!(object
            .get("sudoPassword")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())),
    );

    data
}

fn timestamp_string(timestamp: i64) -> String {
    timestamp.to_string()
}

fn authenticated_user(
    state: &LocalServerState,
    headers: &HeaderMap,
) -> Result<(String, UserResponse), ApiError> {
    let token = extract_token(headers)
        .ok_or_else(|| ApiError::unauthorized("Missing authentication token"))?;
    let now = now_secs();
    let db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("Database lock poisoned"))?;

    let user = db
        .query_row(
            "
            SELECT users.id, users.username, users.is_admin, users.is_oidc, users.totp_enabled
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?1 AND sessions.expires_at > ?2
            ",
            params![token, now],
            |row| {
                Ok(UserResponse {
                    user_id: row.get(0)?,
                    username: row.get(1)?,
                    is_admin: row.get::<_, i64>(2)? != 0,
                    is_oidc: row.get::<_, i64>(3)? != 0,
                    totp_enabled: row.get::<_, i64>(4)? != 0,
                    data_unlocked: true,
                })
            },
        )
        .optional()
        .map_err(|error| ApiError::internal(format!("Failed to load session: {error}")))?;

    user.map(|user| (token, user))
        .ok_or_else(|| ApiError::unauthorized("Invalid token"))
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            return Some(token.to_string());
        }
    }

    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| {
            cookie.split(';').find_map(|part| {
                let part = part.trim();
                part.strip_prefix("jwt=").map(|token| token.to_string())
            })
        })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": self.message,
                "code": if self.status == StatusCode::INTERNAL_SERVER_ERROR {
                    "DATABASE_ERROR"
                } else {
                    "REQUEST_ERROR"
                }
            })),
        )
            .into_response()
    }
}
