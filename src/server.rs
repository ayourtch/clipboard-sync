use eframe::egui;
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::runtime::Runtime;
use warp::Filter;
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
struct ServerState {
    server_running: Arc<Mutex<bool>>,
    last_request: Arc<Mutex<String>>,
    username: Arc<Mutex<String>>,
    password: Arc<Mutex<String>>,
    port: Arc<Mutex<u16>>,
    clipboard_data: Arc<Mutex<ClipboardData>>,
    connected_clients: Arc<Mutex<Vec<String>>>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            server_running: Arc::new(Mutex::new(false)),
            last_request: Arc::new(Mutex::new("No requests yet".to_string())),
            username: Arc::new(Mutex::new("admin".to_string())),
            password: Arc::new(Mutex::new("password".to_string())),
            port: Arc::new(Mutex::new(5585)),
            clipboard_data: Arc::new(Mutex::new(ClipboardData {
                content: String::new(),
                timestamp: 0,
            })),
            connected_clients: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

struct ClipboardServerApp {
    state: ServerState,
    runtime: Option<Runtime>,
}

impl ClipboardServerApp {
    fn new() -> Self {
        Self {
            state: ServerState::default(),
            runtime: None,
        }
    }

    fn start_server(&mut self) {
        if *self.state.server_running.lock().unwrap() {
            return;
        }

        let rt = Runtime::new().unwrap();
        let state_for_thread = self.state.clone();
        
        let username = self.state.username.lock().unwrap().clone();
        let password = self.state.password.lock().unwrap().clone();
        let port = *self.state.port.lock().unwrap();

        // Start clipboard monitoring thread
        let clipboard_state = self.state.clone();
        thread::spawn(move || {
            let mut last_content = String::new();
            loop {
                if let Ok(content) = get_clipboard_contents() {
                    if content != last_content {
                        let timestamp = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        
                        *clipboard_state.clipboard_data.lock().unwrap() = ClipboardData {
                            content: content.clone(),
                            timestamp,
                        };
                        last_content = content;
                    }
                }
                thread::sleep(Duration::from_millis(500));
            }
        });

        thread::spawn(move || {
            rt.block_on(async {
                let auth_header = format!("Basic {}", 
                    general_purpose::STANDARD.encode(format!("{}:{}", username, password))
                );

                // Clone state_for_thread before moving it into the closure
                let state_for_closure = state_for_thread.clone();

                // GET /clipboard - Get current clipboard content
                let get_clipboard = warp::path("clipboard")
                    .and(warp::get())
                    .and(warp::header::<String>("authorization"))
                    .and_then({
                        let auth_header = auth_header.clone();
                        let state = state_for_closure.clone();
                        move |auth: String| {
                            let expected_auth = auth_header.clone();
                            let state = state.clone();
                            
                            async move {
                                if auth != expected_auth {
                                    return Err(warp::reject::custom(AuthError));
                                }

                                let clipboard_data = state.clipboard_data.lock().unwrap().clone();
                                
                                *state.last_request.lock().unwrap() = 
                                    format!("GET at {}: {} chars", 
                                        chrono::Utc::now().format("%H:%M:%S"),
                                        clipboard_data.content.len()
                                    );

                                Ok::<_, warp::Rejection>(warp::reply::json(&clipboard_data))
                            }
                        }
                    });

                // POST /clipboard - Update clipboard content
                let post_clipboard = warp::path("clipboard")
                    .and(warp::post())
                    .and(warp::header::<String>("authorization"))
                    .and(warp::body::json())
                    .and_then({
                        let auth_header = auth_header.clone();
                        let state = state_for_closure.clone();
                        move |auth: String, data: ClipboardData| {
                            let expected_auth = auth_header.clone();
                            let state = state.clone();
                            
                            async move {
                                if auth != expected_auth {
                                    return Err(warp::reject::custom(AuthError));
                                }

                                // Only update if the incoming data is newer
                                let mut current_data = state.clipboard_data.lock().unwrap();
                                if data.timestamp > current_data.timestamp {
                                    set_clipboard_contents(&data.content).ok();
                                    *current_data = data.clone();
                                    
                                    *state.last_request.lock().unwrap() = 
                                        format!("POST at {}: {} chars", 
                                            chrono::Utc::now().format("%H:%M:%S"),
                                            data.content.len()
                                        );
                                }

                                Ok::<_, warp::Rejection>(warp::reply::json(&*current_data))
                            }
                        }
                    });

                let routes = get_clipboard
                    .or(post_clipboard)
                    .recover(handle_rejection);

                println!("Starting server on 127.0.0.1:{}", port);
                *state_for_thread.server_running.lock().unwrap() = true;

                warp::serve(routes)
                    .run(([127, 0, 0, 1], port))
                    .await;
            });
        });
        
        *self.state.server_running.lock().unwrap() = true;
    }

    fn stop_server(&mut self) {
        *self.state.server_running.lock().unwrap() = false;
    }
}

#[derive(Debug)]
struct AuthError;
impl warp::reject::Reject for AuthError {}

async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, std::convert::Infallible> {
    if err.find::<AuthError>().is_some() {
        return Ok(warp::reply::with_status(
            "Unauthorized",
            warp::http::StatusCode::UNAUTHORIZED,
        ));
    }

    Ok(warp::reply::with_status(
        "Internal Server Error",
        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
    ))
}

fn get_clipboard_contents() -> Result<String, Box<dyn std::error::Error>> {
    let mut ctx: ClipboardContext = ClipboardProvider::new()?;
    let contents = ctx.get_contents()?;
    Ok(contents)
}

fn set_clipboard_contents(content: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx: ClipboardContext = ClipboardProvider::new()?;
    ctx.set_contents(content.to_owned())?;
    Ok(())
}

impl eframe::App for ClipboardServerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("macOS Clipboard Sync Server");
            ui.separator();

            // Server configuration
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

            ui.horizontal(|ui| {
                ui.label("Port:");
                let mut port = self.state.port.lock().unwrap();
                ui.add(egui::DragValue::new(&mut *port).range(1024..=65535));
            });

            ui.separator();

            // Server controls
            let server_running = *self.state.server_running.lock().unwrap();
            
            ui.horizontal(|ui| {
                if server_running {
                    if ui.button("Stop Server").clicked() {
                        self.stop_server();
                    }
                    ui.label("🟢 Server is running");
                } else {
                    if ui.button("Start Server").clicked() {
                        self.start_server();
                    }
                    ui.label("🔴 Server is stopped");
                }
            });

            if server_running {
                let port = *self.state.port.lock().unwrap();
                ui.label(format!("Server URL: http://127.0.0.1:{}/clipboard", port));
                ui.label("Synchronizing clipboard with connected clients");
            }

            ui.separator();

            // Status information
            ui.label("Last Request:");
            let last_request = self.state.last_request.lock().unwrap().clone();
            ui.label(&last_request);

            ui.separator();

            // Current clipboard preview
            ui.label("Current Clipboard Contents:");
            let clipboard_data = self.state.clipboard_data.lock().unwrap();
            let preview = if clipboard_data.content.len() > 200 {
                format!("{}... ({} total chars)", &clipboard_data.content[..200], clipboard_data.content.len())
            } else {
                clipboard_data.content.clone()
            };
            
            if clipboard_data.timestamp > 0 {
                ui.label(format!("Last updated: {}", 
                    chrono::DateTime::from_timestamp(clipboard_data.timestamp as i64, 0)
                        .unwrap_or_default()
                        .format("%H:%M:%S")
                ));
            }
            
            ui.text_edit_multiline(&mut preview.as_str());
        });

        // Refresh the UI periodically
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 600.0])
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "Clipboard Sync Server (macOS)",
        options,
        Box::new(|_cc| Ok(Box::new(ClipboardServerApp::new()))),
    )
}
