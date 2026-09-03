use axum::{
    extract::{ConnectInfo, Query, State},
    routing::get,
    response::{Html, IntoResponse, Json},
    Router,
    http::HeaderMap,
};
use serde::{Serialize, Deserialize};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    fs::{self, OpenOptions},
    io::Write,
    cmp,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::{sleep, Duration};
use chrono::Utc;
use std::collections::{HashMap, HashSet};

/* =========================================================
   CONSTANTS & CONFIG
========================================================= */
const MAX_SESSIONS: usize = 10_000;
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;
const AUTOMATION_INDICATORS: [&str; 5] = ["WebZip", "Nutch", "Jetbot", "BecomeBot", "CheeseBot"];

/* =========================================================
   ATTACK INTELLIGENCE
========================================================= */
#[derive(Clone, Serialize, PartialEq, Eq, Hash, Debug)]
enum AttackPhase { Recon, InitialAccess, Exploitation, Impact }

#[derive(Clone, Serialize, Debug, PartialEq)]
enum Verdict { Benign, Suspicious, Hostile }

#[derive(Clone, Serialize, Debug, PartialEq)]
enum DeceptionStrategy { None, FakeSuccess, InfiniteWait, GhostMode }

/* =========================================================
   SESSION INTELLIGENCE
========================================================= */
#[derive(Clone, Serialize)]
struct SessionIntel {
    ip: String,
    request_count: u32,
    intent_score: u32,
    phases: HashSet<AttackPhase>,
    mitre_chain: Vec<String>,
    verdict: Verdict,
    first_seen: u64,
    last_seen: u64,
    last_request_ts: u64,
    is_deceived: bool,
    active_strategy: DeceptionStrategy,
    time_wasted_ms: u64,
}

/* =========================================================
   APP STATE
========================================================= */
#[derive(Clone, Serialize, Deserialize)]
struct PolicyConfig {
    delays: DelayConfig,
    containment_threshold: u8,
    app_mode: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct DelayConfig { low: u64, medium: u64, high: u64 }

#[derive(Clone, Serialize)]
struct AppState {
    sessions: HashMap<String, SessionIntel>,
    total_observations: u64,
    total_containments: u64,
    total_time_wasted: u64,
    #[serde(skip)]
    policy: PolicyConfig,
}

impl Default for AppState {
    fn default() -> Self {
        let content = fs::read_to_string("policy.json")
            .unwrap_or_else(|_| r#"{ "delays":{"low":0,"medium":500,"high":3000}, "containment_threshold":70, "app_mode":"STRICT" }"#.to_string());
        
        let policy: PolicyConfig = serde_json::from_str(&content).expect("Invalid policy.json");
        Self {
            sessions: HashMap::new(),
            total_observations: 0,
            total_containments: 0,
            total_time_wasted: 0,
            policy,
        }
    }
}

#[derive(Deserialize)]
struct AdminParams { key: Option<String>, q: Option<String> }

/* =========================================================
   CORE LOGIC
========================================================= */

fn current_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}

fn get_client_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(s) = forwarded.to_str() {
            return s.split(',').next().unwrap_or("unknown").trim().to_string();
        }
    }
    addr.ip().to_string()
}

fn log_to_terminal(ip: &str, path: &str, score: u8, session: &SessionIntel) {
    // 1. Color & Mode Logic (Fixed Names)
    let (mode, color_code) = match session.verdict {
        Verdict::Benign => ("OBSERVE", "\x1b[32m"),     // Green
        Verdict::Suspicious => ("TARPIT", "\x1b[33m"),  // Yellow (Changed from MONITOR)
        Verdict::Hostile => ("DECEPTION", "\x1b[31m"),  // Red
    };
    let reset = "\x1b[0m";

    // 2. Confidence Calculation
    let confidence = (session.intent_score as f32 / 200.0 * 100.0).min(100.0);

    // 3. Print with RISK (+score) and TOTAL
    println!(
        "[CIDS] {} | Path: {:<15} | Risk: +{:<2} | Total: {:<3} | Conf: {:>5.1}% | Mode: {}{}{}",
        ip,
        path,
        score,                 // Current Request Risk
        session.intent_score,  // Accumulated History
        confidence,
        color_code,
        mode,
        reset
    );
}

fn run_cleanup(state: &mut AppState) {
    let now = current_ts();
    if state.sessions.len() > MAX_SESSIONS {
        state.sessions.clear(); return;
    }
    let timeout = 1800;
    state.sessions.retain(|_, v| (now - v.last_seen) < timeout);
}

// 🔥 UPGRADE: OFFICE & SUPPLY CHAIN AWARENESS
fn calculate_risk(agent: &str, path: &str) -> (u8, Vec<String>) {
    let mut score = 0; 
    let mut reasons = Vec::new();
    let ua = agent.to_lowercase();

    if path == "/robots.txt" { score += 10; reasons.push("[T1595] Reconnaissance Scan".into()); }
    if path == "/admin" { score += 40; reasons.push("[T1078] Privileged Endpoint Probe".into()); }

    if ua.contains("curl") || ua.contains("bot") || ua.contains("python") {
        score += 20; reasons.push("[T1589] Automated Tooling".into());
    }
    
    for indicator in AUTOMATION_INDICATORS.iter() {
        if agent.contains(indicator) {
            score += 25;
            reasons.push(format!("[T1589] Known Bot: {}", indicator));
        }
    }

    if ua.contains("npm") || ua.contains("node") || ua.contains("pip") || ua.contains("setup") || ua.contains("gradle") || ua.contains("mvn") {
        score += 30;
        reasons.push("[T1072] Suspicious Package Manager Activity".into());
    }

    if ua.contains("word") || ua.contains("excel") || ua.contains("powerpoint") || ua.contains("office") || ua.contains("outlook") {
        score += 35;
        reasons.push("[T1204] Suspicious Office Application Traffic".into());
    }

    (cmp::min(score, 100), reasons)
}

// 🔥 UPGRADE: SHELLCODE / RCE DETECTION
fn inspect_payload(payload: &str) -> (u32, Vec<String>) {
    let p = payload.to_lowercase(); 
    let mut s = 0; 
    let mut d = Vec::new();

    if p.contains("' or") || p.contains("1=1") || p.contains("union") { 
        d.push("[T1190] SQL Injection".to_string()); s += 30; 
    }
    if p.contains("<script>") || p.contains("alert(") { 
        d.push("[T1059] XSS".to_string()); s += 30; 
    }

    if p.contains("powershell") || p.contains("cmd.exe") || p.contains("bitsadmin") || p.contains("certutil") || p.contains("-enc") {
        d.push("[T1059] Critical Command/Script Execution Attempt".to_string());
        s += 60;
    }
    
    if p.contains("wget") || p.contains("curl") || p.contains(" | sh") || p.contains("bash -i") {
        d.push("[T1105] Ingress Tool Transfer / RCE".to_string());
        s += 60;
    }

    if p.contains("../") || p.contains("/etc/") { d.push("[T1083] Path Traversal".to_string()); s += 40; }
    
    (s, d)
}

fn update_session(state: &mut AppState, ip: &str, score: u8, path: &str, reasons: &[String]) -> (bool, DeceptionStrategy) {
    let now = current_ts();
    if state.total_observations % 100 == 0 { run_cleanup(state); }

    let session = state.sessions.entry(ip.to_string()).or_insert(SessionIntel {
        ip: ip.to_string(), request_count: 0, intent_score: 0, phases: HashSet::new(), mitre_chain: Vec::new(),
        verdict: Verdict::Benign, first_seen: now, last_seen: now, last_request_ts: now,
        is_deceived: false, active_strategy: DeceptionStrategy::None, time_wasted_ms: 0,
    });

    let time_diff = now - session.last_seen;
    if time_diff > 60 && session.intent_score > 0 {
        let decay = (time_diff / 60) as u32 * 5;
        session.intent_score = session.intent_score.saturating_sub(decay);
    }
    if now == session.last_request_ts { session.intent_score += 5; }

    session.last_seen = now; session.last_request_ts = now; session.request_count += 1;
    session.intent_score += cmp::min(score as u32, 40);

    if path == "/robots.txt" { session.phases.insert(AttackPhase::Recon); }
    if path == "/admin" { session.phases.insert(AttackPhase::InitialAccess); }
    if score >= 80 { session.phases.insert(AttackPhase::Exploitation); }
    if session.intent_score > 200 { session.phases.insert(AttackPhase::Impact); }

    for r in reasons {
        if let Some(code_part) = r.split(']').next() {
            if code_part.starts_with("[T") {
                let t_code = code_part.trim_start_matches('[').to_string();
                if !session.mitre_chain.contains(&t_code) && session.mitre_chain.len() < 20 {
                    session.mitre_chain.push(t_code);
                }
            }
        }
    }

    session.verdict = if session.intent_score > 150 || session.phases.contains(&AttackPhase::Exploitation) { Verdict::Hostile }
                      else if session.intent_score > 50 { Verdict::Suspicious }
                      else { Verdict::Benign };

    if session.verdict == Verdict::Hostile && session.intent_score > 200 {
        session.is_deceived = true;
        if session.active_strategy == DeceptionStrategy::None {
            session.active_strategy = if path == "/admin" { DeceptionStrategy::FakeSuccess } else { DeceptionStrategy::InfiniteWait };
        }
    }

    log_to_terminal(ip, path, score, session);
    (session.is_deceived, session.active_strategy.clone())
}

fn get_deception_content(strategy: &DeceptionStrategy) -> String {
    match strategy {
        DeceptionStrategy::FakeSuccess => r#"<!DOCTYPE html><html><head><title>Admin Console</title><style>body{background:#f4f6f8;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;}.box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center;}h1{color:#2ecc71;}p{color:#666;}</style></head><body><div class="box"><h1>Login Successful</h1><p>Welcome to the secure administrative area.</p><p><i>Loading dashboard modules...</i></p></div></body></html>"#.to_string(),
        
        DeceptionStrategy::InfiniteWait => r#"<!DOCTYPE html><html><head><title>Processing</title></head><body style="background:#000;color:#0F0;">Processing... Please wait...</body></html>"#.to_string(),
        
        _ => "<h1>404 Not Found</h1>".to_string(),
    }
}

fn audit_log(ip: &str, score: u8, reasons: &[String]) {
    if let Ok(metadata) = fs::metadata("audit.log") {
        if metadata.len() > MAX_LOG_SIZE { let _ = fs::remove_file("audit.log"); }
    }
    let event = serde_json::json!({ "time": Utc::now().to_rfc3339(), "ip": ip, "risk": score, "reasons": reasons });
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("audit.log") { let _ = writeln!(file, "{}", event); }
}

/* =========================================================
   HANDLERS
========================================================= */

async fn home_handler() -> impl IntoResponse {
    Html(r##"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CyberMoranda | Threat Intelligence Console</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --brand-primary: #0f172a;
                --brand-accent: #2F5F8F;
                --bg-body: #f1f5f9;
                --bg-card: #ffffff;
                --border-color: #e2e8f0;
                --text-main: #1e293b;
                --text-muted: #64748b;
                --risk-high: #ef4444;
                --risk-med: #f59e0b;
                --risk-low: #10b981;
            }

            * { box-sizing: border-box; }
            body { background-color: var(--bg-body); color: var(--text-main); font-family: 'Inter', sans-serif; margin: 0; padding: 0; }

            /* Navbar */
            .navbar {
                background: var(--brand-primary);
                color: #fff;
                padding: 0 30px;
                height: 64px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .brand { font-size: 16px; font-weight: 700; display: flex; align-items: center; gap: 12px; letter-spacing: -0.5px; }
            .brand span { background: rgba(255,255,255,0.1); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; color: #94a3b8; }
            
            .nav-right { display: flex; align-items: center; gap: 20px; font-size: 13px; color: #cbd5e1; }
            .status-dot { width: 8px; height: 8px; background-color: var(--risk-low); border-radius: 50%; }

            /* Info Button Style */
            .btn-info {
                background: transparent;
                border: 1px solid rgba(255,255,255,0.2);
                color: #cbd5e1;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 12px;
                cursor: pointer;
                transition: all 0.2s;
            }
            .btn-info:hover { background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.4); color: #fff; }

            /* Dashboard Layout */
            .container { max-width: 1200px; margin: 40px auto; padding: 0 24px; }
            
            .header-section { margin-bottom: 32px; }
            .header-title { font-size: 24px; font-weight: 700; color: var(--text-main); margin: 0; }
            .header-subtitle { font-size: 14px; color: var(--text-muted); margin-top: 4px; }

            /* KPI Cards */
            .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 32px; }
            .kpi-card { background: var(--bg-card); padding: 24px; border: 1px solid var(--border-color); border-radius: 8px; }
            .kpi-label { font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; margin-bottom: 12px; }
            .kpi-value { font-size: 28px; font-weight: 700; color: var(--text-main); letter-spacing: -1px; }
            .kpi-meta { font-size: 12px; color: var(--text-muted); margin-top: 6px; }

            /* Table */
            .table-container { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }
            .table-header { padding: 16px 24px; border-bottom: 1px solid var(--border-color); background: #f8fafc; display: flex; justify-content: space-between; align-items: center; }
            .table-title { font-size: 14px; font-weight: 600; color: var(--text-main); }
            
            table { width: 100%; border-collapse: collapse; font-size: 13px; }
            th { text-align: left; padding: 12px 24px; background: #f8fafc; color: var(--text-muted); font-weight: 600; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--border-color); }
            td { padding: 16px 24px; border-bottom: 1px solid var(--border-color); color: var(--text-main); vertical-align: middle; }
            tr:hover { background-color: #f8fafc; }

            /* Badges */
            .badge { padding: 4px 10px; border-radius: 100px; font-size: 11px; font-weight: 600; border: 1px solid transparent; }
            .badge-crit { background: #fef2f2; color: #991b1b; border-color: #fecaca; }
            .badge-warn { background: #fffbeb; color: #92400e; border-color: #fde68a; }
            .badge-safe { background: #f0fdf4; color: #166534; border-color: #bbf7d0; }
            .tech-pill { font-family: 'Roboto Mono', monospace; font-size: 11px; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; color: #475569; border: 1px solid #e2e8f0; }
            
            .risk-bar-bg { width: 60px; height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; }
            .risk-bar-fill { height: 100%; border-radius: 3px; }

            /* MODAL STYLES */
            .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.5); z-index: 1000; backdrop-filter: blur(2px); }
            .modal-content { background: var(--bg-card); width: 500px; margin: 100px auto; padding: 32px; border-radius: 8px; border: 1px solid var(--border-color); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); position: relative; }
            .modal-header { margin-bottom: 20px; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
            .modal-title { font-size: 18px; font-weight: 700; color: var(--text-main); }
            .close-btn { background: none; border: none; font-size: 24px; color: var(--text-muted); cursor: pointer; }
            .modal-row { margin-bottom: 16px; }
            .modal-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px; }
            .modal-text { font-size: 14px; color: var(--text-main); }
            .legal-box { background: #f8fafc; padding: 12px; font-size: 12px; color: var(--text-muted); border-radius: 4px; border-left: 3px solid var(--brand-accent); margin-top: 24px; }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="brand">CYBERMORANDA <span>CIDS v3.6 ENTERPRISE</span></div>
            <div class="nav-right">
                <button onclick="openModal()" class="btn-info">Project Info</button>
                <div style="width: 1px; height: 16px; background: rgba(255,255,255,0.2);"></div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <div class="status-dot"></div> System Operational
                </div>
            </div>
        </nav>

        <div class="container">
            <div class="header-section">
                <h1 class="header-title">Security Operations Center</h1>
                <div class="header-subtitle">Real-time threat telemetry and deception analytics</div>
            </div>

            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Total Traffic</div>
                    <div class="kpi-value" id="kpi-total">0</div>
                    <div class="kpi-meta">Requests processed</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Active Threats</div>
                    <div class="kpi-value" id="kpi-threats" style="color: var(--risk-high)">0</div>
                    <div class="kpi-meta">High severity actors</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Policy Blocks</div>
                    <div class="kpi-value" id="kpi-blocked">0</div>
                    <div class="kpi-meta">Containment actions</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Deception Metrics</div>
                    <div class="kpi-value" id="kpi-time" style="color: var(--brand-accent)">0.0s</div>
                    <div class="kpi-meta">Adversary time wasted</div>
                </div>
            </div>

            <div class="table-container">
                <div class="table-header">
                    <div class="table-title">Live Session Intelligence</div>
                    <div style="font-size:11px; font-weight:600; color:#64748b; background:#fff; padding:4px 8px; border:1px solid #e2e8f0; border-radius:4px;">AUTO-REFRESH: ON</div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Source IP</th>
                            <th>Risk Assessment</th>
                            <th>Intent Score</th>
                            <th>MITRE ATT&CK Chain</th>
                            <th>Response Status</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody id="table-body">
                        <tr><td colspan="6" style="text-align:center; padding:40px; color:#94a3b8; font-style:italic;">Awaiting telemetry stream...</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div style="text-align: center; margin-top: 40px; font-size: 12px; color: var(--text-muted); padding-bottom: 20px;">
                CyberMoranda Research | Cognitive Intrusion Defense System
            </div>
        </div>

        <div id="aboutModal" class="modal-overlay">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">About Platform</div>
                    <button onclick="closeModal()" class="close-btn">&times;</button>
                </div>
                
                <div class="modal-row">
                    <div class="modal-label">Product Name</div>
                    <div class="modal-text">CyberMoranda CIDS (Cognitive Intrusion Defense System)</div>
                </div>
                <div class="modal-row">
                    <div class="modal-label">Version</div>
                    <div class="modal-text">v3.6.0 Enterprise Edition</div>
                </div>
                <div class="modal-row">
                    <div class="modal-label">Owner / Developer</div>
                    <div class="modal-text"><strong>Saurabh kumar</strong></div>
                </div>
                <div class="modal-row">
                    <div class="modal-label">Core Architecture</div>
                    <div class="modal-text">Rust (Hyper/Axum) • Behavioral Scoring • Tarpit Engine</div>
                </div>

                <div class="legal-box">
                    <strong>LEGAL NOTICE:</strong> This system is engineered for defensive security research and ethical monitoring purposes only. Deception modules are deployed within a controlled localhost environment.
                </div>
            </div>
        </div>

        <script>
            function openModal() { document.getElementById('aboutModal').style.display = 'block'; }
            function closeModal() { document.getElementById('aboutModal').style.display = 'none'; }
            
            // Close if clicked outside
            window.onclick = function(event) {
                if (event.target == document.getElementById('aboutModal')) { closeModal(); }
            }

            async function refresh() {
                try {
                    let res = await fetch('/stats');
                    let data = await res.json();

                    document.getElementById('kpi-total').innerText = data.total_observations.toLocaleString();
                    document.getElementById('kpi-blocked').innerText = data.total_containments.toLocaleString();
                    document.getElementById('kpi-time').innerText = (data.total_time_wasted / 1000).toFixed(1) + "s";

                    let tbody = document.getElementById('table-body');
                    tbody.innerHTML = '';
                    let threatCount = 0;

                    let sessions = Object.values(data.sessions).sort((a,b) => b.intent_score - a.intent_score);

                    if (sessions.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:40px; color:#94a3b8;">No active threats detected in current window.</td></tr>';
                        return;
                    }

                    sessions.forEach(s => {
                        let verdictBadge = '';
                        if (s.verdict === 'Hostile') {
                            threatCount++;
                            verdictBadge = '<span class="badge badge-crit">CRITICAL</span>';
                        } else if (s.verdict === 'Suspicious') {
                            verdictBadge = '<span class="badge badge-warn">SUSPICIOUS</span>';
                        } else {
                            verdictBadge = '<span class="badge badge-safe">MONITORING</span>';
                        }

                        let chain = s.mitre_chain.length > 0
                            ? s.mitre_chain.map(t => `<span class="tech-pill">${t}</span>`).join(" ")
                            : '<span style="color:#cbd5e1; font-size:11px;">-</span>';

                        let responseText = s.is_deceived
                            ? `<span style="color:var(--brand-accent); font-weight:600; font-size:12px;">⚡ Deception Engaged (${s.active_strategy})</span>`
                            : '<span style="color:#64748b; font-size:12px;">Passive Observation</span>';
                        
                        let riskColor = s.intent_score > 60 ? '#ef4444' : (s.intent_score > 30 ? '#f59e0b' : '#10b981');

                        let html = `
                        <tr>
                            <td style="font-family:'Roboto Mono'; font-weight:500; font-size:12px;">${s.ip}</td>
                            <td>${verdictBadge}</td>
                            <td>
                                <div style="display:flex; align-items:center; gap:10px;">
                                    <span style="font-weight:700; font-size:12px;">${s.intent_score}</span>
                                    <div class="risk-bar-bg">
                                        <div class="risk-bar-fill" style="width:${Math.min(s.intent_score, 100)}%; background:${riskColor};"></div>
                                    </div>
                                </div>
                            </td>
                            <td>${chain}</td>
                            <td>${responseText}</td>
                            <td style="color:#64748b; font-size:12px;">${new Date(s.last_seen * 1000).toLocaleTimeString()}</td>
                        </tr>`;
                        tbody.innerHTML += html;
                    });
                    document.getElementById('kpi-threats').innerText = threatCount;
                } catch (e) { console.log("Stream paused"); }
            }
            setInterval(refresh, 2000);
            refresh();
        </script>
    </body>
    </html>
    "##)
}

async fn robots_handler(State(state): State<Arc<Mutex<AppState>>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> impl IntoResponse {
    let ip = get_client_ip(&headers, addr);
    let agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("Unknown");
    let (score, reasons) = calculate_risk(&agent, "/robots.txt");
    {
        let mut s = state.lock().unwrap();
        s.total_observations += 1;
        update_session(&mut s, &ip, score, "/robots.txt", &reasons);
    }
    audit_log(&ip, score, &reasons);
    "User-agent: *\nDisallow: /admin"
}

async fn trap_handler(State(state): State<Arc<Mutex<AppState>>>, Query(params): Query<AdminParams>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> impl IntoResponse {
    let ip = get_client_ip(&headers, addr);
    let agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("Unknown");
    let mut reasons = Vec::new(); 
    let mut score = 0;

    if let Some(ref q) = params.q {
        if q.len() > 500 {
            println!("[ALERT] Payload too large from {}", ip);
            return Html("<h1>400 Bad Request</h1>".to_string());
        }
    }

    let (base, r) = calculate_risk(&agent, "/admin");
    score += base; reasons.extend(r);

    let payload = params.q.unwrap_or_default();
    let (p_score, p_reasons) = inspect_payload(&payload);
    score += p_score as u8; reasons.extend(p_reasons);

    reasons.push("Auth missing".into()); 
    score = cmp::min(score + 20, 100);

    let (policy_delay, _) = {
        let d = state.lock().unwrap(); 
        let p = &d.policy;
        let delay = if score < 30 { 
            p.delays.low 
        } else if score < p.containment_threshold { 
            p.delays.medium 
        } else { 
            p.delays.high 
        };
        (delay, p.containment_threshold)
    };

    let (is_deceived, strategy) = {
        let mut s = state.lock().unwrap();
        if score >= s.policy.containment_threshold { s.total_containments += 1; }
        let (deceived, strat) = update_session(&mut s, &ip, score, "/admin", &reasons);
        if deceived { 
            s.total_time_wasted += policy_delay; 
            if let Some(sess) = s.sessions.get_mut(&ip) { 
                sess.time_wasted_ms += policy_delay; 
            }
        }
        (deceived, strat)
    };

    audit_log(&ip, score, &reasons);
    if is_deceived {
        println!("[DECEPTION] Strategy: {:?} | Wasting {}ms", strategy, policy_delay);
        sleep(Duration::from_millis(policy_delay)).await;
        return Html(get_deception_content(&strategy));
    }

    println!("[CONTAINMENT] Engaged. IP: {}", ip);
    sleep(Duration::from_millis(policy_delay)).await;
    Html(r#"<html><body style="background:#0B0F14;color:red;display:flex;justify-content:center;align-items:center;height:100vh;"><h1>ACCESS DENIED // 403</h1></body></html>"#.to_string())
}

async fn stats_handler(State(state): State<Arc<Mutex<AppState>>>) -> Json<AppState> {
    let data = state.lock().unwrap(); 
    Json(data.clone())
}

#[tokio::main]
async fn main() {
    let state = Arc::new(Mutex::new(AppState::default()));

    let app = Router::new()
        .route("/", get(home_handler))
        .route("/robots.txt", get(robots_handler))
        .route("/admin", get(trap_handler))
        .route("/stats", get(stats_handler))
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    println!("📡 Console: http://localhost:3000\n");

    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap(), app).await.unwrap();
}

