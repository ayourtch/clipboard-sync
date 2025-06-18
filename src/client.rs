use eframe::egui;
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::runtime::Runtime;
use base64::{Engine as _, engine::general_purpose};
use clipboard::{ClipboardContext, ClipboardProvider};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Serialize, Deserialize)]
struct ClipboardData {
    content: String,
    timestamp: u64,
}

#[derive(Clone)]
struct ClientState {
    server_url: Arc<Mutex<String>>,
    username: Arc<Mutex<String>>,
    password: Arc<Mutex<String>>,
    connected: Arc<Mutex<bool>>,
    last_sync: Arc<Mutex<String>>,
    clipboard_data: Arc<Mutex<ClipboardData>>,
    connection_status: Arc<Mutex<String>>,
    sync_enabled: Arc<Mutex<bool>>,
    clipboard_ctx: Arc<Mutex<ClipboardContext>>,
}

impl Default for ClientState {
    fn default() -> Self {
        Self {
            server_url: Arc::new(Mutex::new("http://127.0.0.1:5585".to_string())),
            username: Arc::new(Mutex::new("admin".to_string())),
            password: Arc::new(Mutex::new("password".to_string())),
            connected: Arc::new(Mutex::new(false)),
            last_sync: Arc::new(Mutex::new("Not connected".to_string())),
            clipboard_ctx: Arc::new(Mutex::new(ClipboardProvider::new().expect("Could not get clipboard provider"))),
            clipboard_data: Arc::new(Mutex::new(ClipboardData {
                content: String::new(),
                timestamp: 0,
            })),
            connection_status: Arc::new(Mutex::new("Disconnected".to_string())),
            sync_enabled: Arc::new(Mutex::new(false)),
        }
    }
}

struct ClipboardClientApp {
    state: ClientState,
    runtime: Option<Runtime>,
}

impl ClipboardClientApp {
    fn new() -> Self {
        Self {
            state: ClientState::default(),
            runtime: None,
        }
    }

    fn start_sync(&mut self) {
       println!("Start sync");
    /*
        if *self.state.sync_enabled.lock().unwrap() {
            return;
        }

        *self.state.sync_enabled.lock().unwrap() = true;
	*/

	{
    let mut sync_enabled = self.state.sync_enabled.lock().unwrap();
    if *sync_enabled {
        return;
    }
    *sync_enabled = true;
}


        let state = self.state.clone();

        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut last_local_content = String::new();
                let mut last_server_timestamp = 0u64;

                loop {
                    if !*state.sync_enabled.lock().unwrap() {
                        break;
                    }

                    // Check local clipboard for changes
                    if let Ok(local_content) = get_clipboard_contents(&state) {
                        if local_content != last_local_content && !local_content.is_empty() {
                            let timestamp = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();

                            let clipboard_data = ClipboardData {
                                content: local_content.clone(),
                                timestamp,
                            };

                            // Send local changes to server
                            if let Err(e) = send_clipboard_to_server(&state, &clipboard_data).await {
                                *state.connection_status.lock().unwrap() = 
                                    format!("Error sending: {}", e);
                                *state.connected.lock().unwrap() = false;
                            } else {
                                *state.connected.lock().unwrap() = true;
                                *state.connection_status.lock().unwrap() = "Connected".to_string();
                                *state.last_sync.lock().unwrap() = 
                                    format!("Sent at {}", chrono::Utc::now().format("%H:%M:%S"));
                            }

                            last_local_content = local_content;
                        }
                    }

                    // Get updates from server
                    match get_clipboard_from_server(&state).await {
                        Ok(server_data) => {
                            if server_data.timestamp > last_server_timestamp 
                                && server_data.content != last_local_content 
                                && !server_data.content.is_empty() {
                                
                                if let Err(e) = set_clipboard_contents(&server_data.content) {
                                    *state.connection_status.lock().unwrap() = 
                                        format!("Error setting clipboard: {}", e);
                                } else {
                                    *state.clipboard_data.lock().unwrap() = server_data.clone();
                                    last_server_timestamp = server_data.timestamp;
                                    last_local_content = server_data.content;
                                    *state.last_sync.lock().unwrap() = 
                                        format!("Received at {}", chrono::Utc::now().format("%H:%M:%S"));
                                }
                            }
                            
                            *state.connected.lock().unwrap() = true;
                            *state.connection_status.lock().unwrap() = "Connected".to_string();
                        }
                        Err(e) => {
                            *state.connection_status.lock().unwrap() = 
                                format!("Connection error: {}", e);
                            *state.connected.lock().unwrap() = false;
                        }
                    }

                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            });
        });
    }

    fn stop_sync(&mut self) {
        *self.state.sync_enabled.lock().unwrap() = false;
        *self.state.connected.lock().unwrap() = false;
        *self.state.connection_status.lock().unwrap() = "Disconnected".to_string();
    }
}

async fn send_clipboard_to_server(
    state: &ClientState,
    data: &ClipboardData,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
    let server_url = state.server_url.lock().unwrap().clone();
    let username = state.username.lock().unwrap().clone();
    let password = state.password.lock().unwrap().clone();

    let auth_header = format!("Basic {}", 
        general_purpose::STANDARD.encode(format!("{}:{}", username, password))
    );

    let response = client
        .post(&format!("{}/clipboard", server_url))
        .header("Authorization", auth_header)
        .json(data)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Server error: {}", response.status()).into());
    }

    Ok(())
}

async fn get_clipboard_from_server(
    state: &ClientState,
) -> Result<ClipboardData, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
    let server_url = state.server_url.lock().unwrap().clone();
    let username = state.username.lock().unwrap().clone();
    let password = state.password.lock().unwrap().clone();

    let auth_header = format!("Basic {}", 
        general_purpose::STANDARD.encode(format!("{}:{}", username, password))
    );

    let response = client
        .get(&format!("{}/clipboard", server_url))
        .header("Authorization", auth_header)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Server error: {}", response.status()).into());
    }

    let data: ClipboardData = response.json().await?;
    Ok(data)
}

fn get_clipboard_contents(state: &ClientState) -> Result<String, Box<dyn std::error::Error>> {
    let contents = state.clipboard_ctx.lock().expect("Could not lock").get_contents()?;
    //let mut ctx: ClipboardContext = ClipboardProvider::new()?;
    //let contents = ctx.get_contents()?;
    Ok(contents.to_string())
}

fn set_clipboard_contents(content: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx: ClipboardContext = ClipboardProvider::new()?;
    ctx.set_contents(content.to_owned())?;
    Ok(())
}

impl eframe::App for ClipboardClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Linux Clipboard Sync Client");
            ui.separator();

            // Server configuration
            ui.horizontal(|ui| {
                ui.label("Server URL:");
                let mut server_url = self.state.server_url.lock().unwrap();
                ui.text_edit_singleline(&mut *server_url);
            });

            ui.horizontal(|ui| {
                ui.label("Username:");
                let mut username = self.state.username.lock().unwrap();
                ui.text_edit_singleline(&mut *username);
            });

            ui.horizontal(|ui| {
                ui.label("Password:");
                let mut password = self.state.password.lock().unwrap();
                ui.text_edit_singleline(&mut *password);
            });

            ui.separator();

            // Connection controls
            let sync_enabled = *self.state.sync_enabled.lock().unwrap();
            let connected = *self.state.connected.lock().unwrap();
            
            ui.horizontal(|ui| {
                if sync_enabled {
                    if ui.button("Stop Sync").clicked() {
                        self.stop_sync();
                    }
                    if connected {
                        ui.label("🟢 Connected & Syncing");
                    } else {
                        ui.label("🟡 Sync enabled, trying to connect...");
                    }
                } else {
                    if ui.button("Start Sync").clicked() {
                        self.start_sync();
                    }
                    ui.label("🔴 Sync disabled");
                }
            });

            // Connection status
            let connection_status = self.state.connection_status.lock().unwrap().clone();
            ui.label(format!("Status: {}", connection_status));

            ui.separator();

            // Sync information
            ui.label("Last Sync:");
            let last_sync = self.state.last_sync.lock().unwrap().clone();
            ui.label(&last_sync);

            ui.separator();

            // Current clipboard preview
            ui.label("Current Local Clipboard:");
            match get_clipboard_contents(&self.state) {
                Ok(contents) => {
                    let preview = if contents.len() > 200 {
                        format!("{}... ({} total chars)", &contents[..200], contents.len())
                    } else {
                        contents
                    };
                    ui.text_edit_multiline(&mut preview.as_str());
                }
                Err(e) => {
                    ui.label(format!("Error reading clipboard: {}", e));
                }
            }

            ui.separator();

            // Server clipboard preview
            ui.label("Last Received from Server:");
            let clipboard_data = self.state.clipboard_data.lock().unwrap();
            if clipboard_data.timestamp > 0 {
                ui.label(format!("Received at: {}", 
                    chrono::DateTime::from_timestamp(clipboard_data.timestamp as i64, 0)
                        .unwrap_or_default()
                        .format("%H:%M:%S")
                ));
                
                let preview = if clipboard_data.content.len() > 200 {
                    format!("{}... ({} total chars)", &clipboard_data.content[..200], clipboard_data.content.len())
                } else {
                    clipboard_data.content.clone()
                };
                ui.text_edit_multiline(&mut preview.as_str());
            } else {
                ui.label("No data received yet");
            }
        });

        // Refresh the UI periodically
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 700.0])
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "Clipboard Sync Client (Linux)",
        options,
        Box::new(|_cc| Ok(Box::new(ClipboardClientApp::new()))),
    )
}
