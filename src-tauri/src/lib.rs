use serde::{Deserialize, Serialize};
use std::{fs, time::Duration};
use tauri::{AppHandle, Manager};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerConfig {
    server_url: String,
    last_updated: String,
}

#[derive(Debug, Serialize)]
struct CommandResult {
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct EmbeddedServerStatus {
    running: bool,
    embedded: bool,
    data_dir: Option<String>,
}

fn server_config_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Failed to resolve app data directory: {error}"))?;

    fs::create_dir_all(&app_data_dir)
        .map_err(|error| format!("Failed to create app data directory: {error}"))?;

    Ok(app_data_dir.join("server-config.json"))
}

#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
fn get_platform() -> String {
    std::env::consts::OS.to_string()
}

#[tauri::command]
fn get_server_config(app: AppHandle) -> Result<Option<ServerConfig>, String> {
    let path = server_config_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read server config: {error}"))?;
    serde_json::from_str(&raw).map_err(|error| format!("Failed to parse server config: {error}"))
}

#[tauri::command]
fn save_server_config(app: AppHandle, config: ServerConfig) -> Result<CommandResult, String> {
    let path = server_config_path(&app)?;
    let raw = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Failed to serialize server config: {error}"))?;
    fs::write(path, raw).map_err(|error| format!("Failed to save server config: {error}"))?;

    Ok(CommandResult {
        success: true,
        error: None,
    })
}

#[tauri::command]
async fn test_server_connection(server_url: String) -> Result<CommandResult, String> {
    let base_url = server_url.trim_end_matches('/');
    let health_url = format!("{base_url}/health");
    let version_url = format!("{base_url}/version");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?;

    for url in [health_url, version_url] {
        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                return Ok(CommandResult {
                    success: true,
                    error: None,
                });
            }
            Ok(response) => {
                if url.ends_with("/version") {
                    return Ok(CommandResult {
                        success: false,
                        error: Some(format!("Server returned {}", response.status())),
                    });
                }
            }
            Err(error) => {
                if url.ends_with("/version") {
                    return Ok(CommandResult {
                        success: false,
                        error: Some(error.to_string()),
                    });
                }
            }
        }
    }

    Ok(CommandResult {
        success: false,
        error: Some("Connection test failed".to_string()),
    })
}

#[tauri::command]
fn get_embedded_server_status(app: AppHandle) -> EmbeddedServerStatus {
    let data_dir = app
        .path()
        .app_data_dir()
        .ok()
        .map(|path| path.to_string_lossy().to_string());

    EmbeddedServerStatus {
        running: false,
        embedded: false,
        data_dir,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            get_platform,
            get_server_config,
            save_server_config,
            test_server_connection,
            get_embedded_server_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
