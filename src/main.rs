use axum::{
    extract::{ConnectInfo, Query},
    routing::get,
    Router,
    response::{Html, IntoResponse},
    http::HeaderMap,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};
use std::cmp;

#[derive(Deserialize)]
struct AdminParams {
    key: Option<String>,
}

const AUTOMATION_INDICATORS: [&str; 5] = ["WebZip", "Nutch", "Jetbot", "BecomeBot", "CheeseBot"];

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    println!("[SYSTEM_INIT] CyberMoranda CIDS v3.1 (Final Stable) starting...");
    println!("[POLICY] Enforcement Mode: STRICT");
    println!("[UI_THEME] Professional/Muted");
    
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/robots.txt", get(bait_handler))
        .route("/admin", get(trap_handler))
        .into_make_service_with_connect_info::<SocketAddr>();

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("[NETWORK] Listening on http://localhost:3000");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// --- LOGIC ---
fn calculate_risk(agent: &str, path: &str) -> (u8, Vec<String>) {
    let mut score = 0;
    let mut reasons = Vec::new();

    for bot in AUTOMATION_INDICATORS.iter() {
        if agent.contains(bot) {
            score += 30;
            reasons.push(format!("Automation indicator: {}", bot));
        }
    }
    if path == "/admin" { score += 50; reasons.push("Privileged endpoint probe".to_string()); }
    if path == "/robots.txt" { score += 10; reasons.push("Reconnaissance pattern".to_string()); }

    (cmp::min(score, 100), reasons)
}

fn extract_intel(headers: &HeaderMap, addr: SocketAddr) -> (String, String) {
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("Unknown");
    let ip = addr.ip().to_string();
    (ip, user_agent.to_string())
}

// --- HANDLERS ---

// 1. PUBLIC DASHBOARD
async fn home_handler() -> impl IntoResponse {
    Html(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberMoranda CIDS</title>
        <style>
            body { background-color: #0B0F14; color: #E6EDF3; font-family: 'Segoe UI', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .card { background: #161b22; border: 1px solid #30363d; padding: 40px; border-radius: 12px; width: 400px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
            h1 { color: #00E5FF; font-size: 24px; letter-spacing: 1px; margin-bottom: 10px; text-transform: uppercase; }
            .status-line { display: flex; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #30363d; padding-bottom: 20px; }
            .dot { height: 10px; width: 10px; background-color: #2ea043; border-radius: 50%; display: inline-block; margin-right: 10px; box-shadow: 0 0 10px #2ea043; }
            .info { color: #8B949E; font-size: 14px; line-height: 1.6; }
            .metric { margin-top: 20px; background: #0d1117; padding: 15px; border-radius: 6px; border-left: 3px solid #00E5FF; }
            .metric-title { font-size: 12px; color: #8B949E; text-transform: uppercase; }
            .metric-value { font-size: 18px; color: #E6EDF3; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="status-line">
                <span class="dot"></span>
                <span style="font-weight:bold;">SYSTEM OPERATIONAL</span>
            </div>
            <h1>CyberMoranda CIDS</h1>
            <p class="info">Behavioral Intrusion Defense System is active. Network traffic is being monitored for anomaly patterns.</p>
            <div class="metric">
                <div class="metric-title">Active Policy</div>
                <div class="metric-value">Ethical Containment</div>
            </div>
        </div>
    </body>
    </html>
    "#)
}

// 2. THE BAIT
async fn bait_handler(ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> impl IntoResponse {
    let (ip, agent) = extract_intel(&headers, addr);
    let (score, _) = calculate_risk(&agent, "/robots.txt");
    println!("[OBSERVATION] Risk: {} | IP: {} visited robots.txt", score, ip);
    "User-agent: *\nDisallow: /admin"
}

// 3. THE TRAP / ADMIN
async fn trap_handler(
    Query(params): Query<AdminParams>, 
    ConnectInfo(addr): ConnectInfo<SocketAddr>, 
    headers: HeaderMap
) -> impl IntoResponse {
    
    let (ip, agent) = extract_intel(&headers, addr);
    let (mut score, mut reasons) = calculate_risk(&agent, "/admin");

    // AUTH CHECK
    let is_authorized = match params.key {
        Some(ref k) if k == "MorandaBoss" => true,
        _ => false
    };

    if is_authorized {
        println!("[ACCESS_LOG] Admin Dashboard Loaded for {}", ip);
        return Html(r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin // CyberMoranda</title>
                <style>
                    body { background-color: #0B0F14; color: #E6EDF3; font-family: monospace; padding: 50px; }
                    .header { border-bottom: 2px solid #00E5FF; padding-bottom: 20px; margin-bottom: 30px; }
                    h1 { color: #00E5FF; margin: 0; }
                    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
                    .panel { background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; }
                    .stat { font-size: 30px; font-weight: bold; color: #E6EDF3; }
                    .log-box { margin-top: 20px; background: #0d1117; padding: 15px; border-left: 3px solid #d29922; color: #8B949E; font-size: 13px; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>ADMIN_CONSOLE // SECURE</h1>
                    <p>Identity Verified. Session Encrypted.</p>
                </div>
                <div class="grid">
                    <div class="panel">
                        <p style="color:#8B949E">THREATS CONTAINED</p>
                        <div class="stat">1</div>
                    </div>
                    <div class="panel">
                        <p style="color:#8B949E">SYSTEM HEALTH</p>
                        <div class="stat" style="color:#2ea043">100%</div>
                    </div>
                </div>
                <div class="log-box">
                    <strong>LAST ACTION:</strong> Containment applied due to unauthorized privileged endpoint probe.
                    
                    <p style="color:#8B949E; font-size:12px; margin-top:10px;">
                        Decisions are behavior-based and non-punitive.
                    </p>
                </div>
            </body>
            </html>
        "#);
}

    // 🔴 TRAP PAGE (Refined: Muted Amber/Red)
    reasons.push("Auth missing".to_string());
    score = cmp::min(score + 20, 100);
    println!("[CONTAINMENT] Engaged. Risk Score: {} | IP: {}", score, ip);
    
    sleep(Duration::from_millis(2000)).await;

    Html(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Restricted</title>
            <style>
                /* Muted Red Background #1a0505 instead of pure black/red */
                body { background-color: #0B0F14; color: #d29922; font-family: 'Segoe UI', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; text-align: center; }
                .box { border: 1px solid #d29922; padding: 40px; border-radius: 8px; background: #161b22; box-shadow: 0 0 15px rgba(210, 153, 34, 0.1); }
                h1 { font-size: 24px; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px; }
                p { color: #8B949E; font-size: 14px; }
                .loader { border: 3px solid #30363d; border-top: 3px solid #d29922; border-radius: 50%; width: 20px; height: 20px; animation: spin 1s linear infinite; margin: 20px auto; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            </style>
        </head>
        <body>
            <div class="box">
                <h1>Access Restricted by Policy</h1>
                <p>Request did not meet access requirements.</p>
                <div class="loader"></div>
                <p style="font-size:12px; margin-top:20px; color:#555;">Verifying session parameters...</p>
            </div>
        </body>
        </html>
    "#)
}
