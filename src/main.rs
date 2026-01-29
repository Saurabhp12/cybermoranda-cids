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
const AUTOMATION_INDICATORS: [&str; 5] = ["WebZip", "Nutch", "Jetbot", "BecomeBot", "CheeseBot"];

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
    let color = match session.verdict {
        Verdict::Benign => "\x1b[32m", Verdict::Suspicious => "\x1b[33m", Verdict::Hostile => "\x1b[31m",
    };
    let reset = "\x1b[0m";
    println!("\n------------------------------------------------");
    println!("📡 INCOMING: {} | Path: {}", ip, path);
    println!("⚡ RISK ADDED: +{}", score);
    println!("🧠 INTELLIGENCE UPDATE:");
    println!("   • Intent Score: {}{}{}", color, session.intent_score, reset);
    println!("   • Verdict:      {}{:?}{}", color, session.verdict, reset);
    println!("   • Phases:       {:?}", session.phases);
    println!("   • Chain:        {:?}", session.mitre_chain);
    println!("------------------------------------------------");
}

fn run_cleanup(state: &mut AppState) {
    let now = current_ts();
    if state.sessions.len() > MAX_SESSIONS {
        state.sessions.clear(); return;
    }
    let timeout = 1800; 
    state.sessions.retain(|_, v| (now - v.last_seen) < timeout);
}

// 🔥 UPGRADE #12 + POLISH: OFFICE & SUPPLY CHAIN AWARENESS
fn calculate_risk(agent: &str, path: &str) -> (u8, Vec<String>) {
    let mut score = 0; let mut reasons = Vec::new();
    let ua = agent.to_lowercase();
    
    // Standard Recon Checks
    if path == "/robots.txt" { score += 10; reasons.push("[T1595] Reconnaissance Scan".into()); }
    if path == "/admin" { score += 40; reasons.push("[T1078] Privileged Endpoint Probe".into()); }
    
    // Bot Checks
    if ua.contains("curl") || ua.contains("bot") || ua.contains("python") { 
        score += 20; reasons.push("[T1589] Automated Tooling".into()); 
    }

    // 🛡️ NEW POLISH: AI/Supply Chain Tool Detection (From Video Use Case)
    // Ye line us "AI Package Hallucination" wale virus ko pakad legi
    if ua.contains("npm") || ua.contains("node") || ua.contains("pip") || ua.contains("setup") {
        score += 30; 
        reasons.push("[T1072] Suspicious Package Manager Activity".into());
    }

    // 🛡️ OFFICE: Malicious Doc Detection
    if ua.contains("word") || ua.contains("excel") || ua.contains("powerpoint") || ua.contains("office") {
        score += 35; // Significant Risk
        reasons.push("[T1204] Suspicious Office Application Traffic".into());
    }

    (cmp::min(score, 100), reasons)
}

// 🔥 UPGRADE #12: SHELLCODE / RCE DETECTION
fn inspect_payload(payload: &str) -> (u32, Vec<String>) {
    let p = payload.to_lowercase(); let mut s = 0; let mut d = Vec::new();
    
    // Standard Web Attacks
    if p.contains("' or") || p.contains("1=1") || p.contains("union") { d.push("[T1190] SQL Injection".to_string()); s += 30; }
    if p.contains("<script>") || p.contains("alert(") { d.push("[T1059] XSS".to_string()); s += 30; }
    
    // 🛡️ NEW: Command Execution / Shellcode
    // These indicate a script trying to download/execute payload
    if p.contains("powershell") || p.contains("cmd.exe") || p.contains("bitsadmin") || p.contains("certutil") || p.contains("-enc") {
        d.push("[T1059] Critical Command/Script Execution Attempt".to_string());
        s += 60; // Immediate Hostile Territory
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
    if score >= 60 { session.phases.insert(AttackPhase::Exploitation); } // Fixed threshold logic
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
            // For Shellcode attacks, InfiniteWait is best (hangs the malware)
            session.active_strategy = if path == "/admin" { DeceptionStrategy::FakeSuccess } else { DeceptionStrategy::InfiniteWait };
        }
    }

    log_to_terminal(ip, path, score, session);
    (session.is_deceived, session.active_strategy.clone())
}

fn get_deception_content(strategy: &DeceptionStrategy) -> String {
    match strategy {
        DeceptionStrategy::FakeSuccess => r#"<!DOCTYPE html><html><head><title>Admin Console</title><style>body{background:#f4f6f8;color:#333;font-family:sans-serif;padding:0;margin:0;}.nav{background:#24292e;color:#fff;padding:15px;display:flex;justify-content:space-between;}.container{padding:30px;}.alert{background:#d4edda;color:#155724;padding:15px;border:1px solid #c3e6cb;border-radius:4px;margin-bottom:20px;}table{width:100%;border-collapse:collapse;background:#fff;}th,td{padding:12px;text-align:left;border-bottom:1px solid #ddd;}.btn-disabled{background:#e9ecef;color:#6c757d;padding:5px 10px;border-radius:4px;cursor:not-allowed;font-size:12px;}</style></head><body><div class="nav"><span><strong>ADMIN_PANEL</strong> // v4.2.0</span><span>User: root</span></div><div class="container"><div class="alert">✔ <strong>Success:</strong> Authentication verified via LDAP.</div><h3>Database (Read-Only)</h3><table><tr><th>ID</th><th>User</th><th>Role</th><th>Actions</th></tr><tr><td>101</td><td>admin_sys</td><td>SuperAdmin</td><td><button class="btn-disabled">Edit</button></td></tr><tr><td>102</td><td>backup_svc</td><td>Service</td><td><button class="btn-disabled">Edit</button></td></tr></table><p style="color:#666;font-size:12px;margin-top:20px;">* Write access is currently locked by security policy.</p></div></body></html>"#.to_string(),
        DeceptionStrategy::InfiniteWait => r#"<!DOCTYPE html><html><head><title>Processing</title></head><body style="background:#0d1117;color:#58a6ff;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;"><div style="text-align:center;border:1px solid #30363d;padding:40px;border-radius:6px;background:#161b22;width:400px;"><h2>PROCESSING REQUEST</h2><div style="text-align:left;font-size:12px;color:#8b949e;">> Allocating thread pool... OK<br>> HANDSHAKE [US-EAST-2]...<br>> Waiting for shard...</div><div style="margin-top:30px;font-size:24px;animation:pulse 1.5s infinite;">⌛</div></div><style>@keyframes pulse{0%{opacity:0.3;}50%{opacity:1;}100%{opacity:0.3;}}</style></body></html>"#.to_string(),
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
        <title>CyberMoranda Security Operations</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-body: #f4f7fa; --bg-card: #ffffff;
                --text-primary: #1e293b; --text-secondary: #64748b;
                --border: #e2e8f0;
                --accent: #3b82f6; 
                --success: #10b981; --warning: #f59e0b; --danger: #ef4444;
            }
            body { background-color: var(--bg-body); color: var(--text-primary); font-family: 'Inter', sans-serif; margin: 0; padding: 0; }
            
            /* Navbar */
            .navbar { background: #fff; border-bottom: 1px solid var(--border); padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
            .brand { font-size: 18px; font-weight: 600; color: #0f172a; display: flex; align-items: center; gap: 10px; }
            .brand span { color: var(--text-secondary); font-weight: 400; font-size: 14px; }
            
            .nav-right { display: flex; align-items: center; gap: 15px; }
            .status-indicator { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--success); font-weight: 500; background: #ecfdf5; padding: 4px 10px; border-radius: 20px; border: 1px solid #d1fae5; }
            .dot { width: 8px; height: 8px; background-color: var(--success); border-radius: 50%; }
            
            .btn-about { font-size: 13px; padding: 8px 16px; border: 1px solid var(--border); background: #fff; border-radius: 6px; cursor: pointer; color: var(--text-primary); font-weight: 500; transition: all 0.2s; }
            .btn-about:hover { background: #f8fafc; border-color: #cbd5e1; }

            /* Layout */
            .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
            
            /* KPI Grid */
            .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
            .kpi-card { background: var(--bg-card); padding: 20px; border-radius: 8px; border: 1px solid var(--border); box-shadow: 0 1px 2px rgba(0,0,0,0.02); }
            .kpi-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; margin-bottom: 8px; }
            .kpi-value { font-size: 24px; font-weight: 700; color: var(--text-primary); }
            .kpi-sub { font-size: 11px; margin-top: 5px; color: var(--text-secondary); }

            /* Data Table */
            .table-container { background: var(--bg-card); border-radius: 8px; border: 1px solid var(--border); overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.02); }
            .table-header { padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
            .table-title { font-size: 16px; font-weight: 600; }
            
            table { width: 100%; border-collapse: collapse; font-size: 14px; }
            th { text-align: left; padding: 12px 20px; background: #f8fafc; color: var(--text-secondary); font-weight: 600; font-size: 12px; text-transform: uppercase; border-bottom: 1px solid var(--border); }
            td { padding: 16px 20px; border-bottom: 1px solid var(--border); color: var(--text-primary); }
            tr:last-child td { border-bottom: none; }
            
            /* Badges */
            .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
            .badge-safe { background: #ecfdf5; color: #047857; }
            .badge-warn { background: #fffbeb; color: #b45309; }
            .badge-crit { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
            
            .code-text { font-family: 'Roboto Mono', monospace; font-size: 12px; color: #475569; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }
            .response-text { font-size: 12px; color: var(--text-secondary); }

            /* Modal */
            .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(2px); z-index: 1000; }
            .modal-content { background: #fff; max-width: 600px; margin: 80px auto; padding: 30px; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); border: 1px solid var(--border); animation: fadeIn 0.2s ease-out; }
            .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 15px; }
            .modal-title { font-size: 20px; font-weight: 700; color: var(--text-primary); }
            .close-btn { background: none; border: none; font-size: 24px; color: var(--text-secondary); cursor: pointer; }
            .modal-body h3 { font-size: 15px; margin-top: 20px; margin-bottom: 10px; color: var(--text-primary); }
            .modal-body p { font-size: 14px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 10px; }
            .legal-box { background: #f8fafc; padding: 15px; border-radius: 6px; border-left: 4px solid var(--accent); margin-top: 20px; font-size: 13px; color: #475569; }

            @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        </style>
    </head>
    <body>
        <div class="navbar">
            <div class="brand">CyberMoranda <span>CIDS Platform v3.6</span></div>
            <div class="nav-right">
                <div class="status-indicator"><div class="dot"></div> Operational</div>
                <button onclick="openAbout()" class="btn-about">About Platform</button>
            </div>
        </div>

        <div class="container">
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Traffic Volume</div>
                    <div class="kpi-value" id="kpi-total">0</div>
                    <div class="kpi-sub">Total requests analyzed</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Active Threats</div>
                    <div class="kpi-value" id="kpi-threats" style="color: var(--danger)">0</div>
                    <div class="kpi-sub">Critical risk actors</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Containment Actions</div>
                    <div class="kpi-value" id="kpi-blocked">0</div>
                    <div class="kpi-sub">Policy enforcements</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Deception Efficiency</div>
                    <div class="kpi-value" id="kpi-time" style="color: var(--accent)">0.0s</div>
                    <div class="kpi-sub">Adversary time wasted</div>
                </div>
            </div>

            <div class="table-container">
                <div class="table-header">
                    <div class="table-title">Live Intelligence Feed</div>
                    <div style="font-size:12px; color:#64748b;">Auto-refresh: 2s</div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Source IP</th>
                            <th>Risk Assessment</th>
                            <th>Behavior Score</th>
                            <th>Technique Chain (MITRE)</th>
                            <th>Automated Response</th>
                            <th>Last Activity</th>
                        </tr>
                    </thead>
                    <tbody id="table-body">
                        <tr><td colspan="6" style="text-align:center; padding:30px; color:#94a3b8;">Waiting for telemetry...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div id="aboutModal" class="modal-overlay">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title">About CyberMoranda</div>
                    <button onclick="closeAbout()" class="close-btn">&times;</button>
                </div>
                <div class="modal-body">
                    <p>CyberMoranda is an independent cybersecurity research initiative focused on <strong>defensive, ethical, and behavior-based</strong> security systems.</p>

                    <h3>System Architecture</h3>
                    <p>CyberMoranda CIDS (Cognitive Intrusion Detection System) utilizes a zero-panic Rust architecture to observe attacker behavior, score intent using MITRE ATT&CK mapping, and apply controlled defensive responses without disrupting system availability.</p>

                    <h3>Ownership</h3>
                    <p>Project Owner & Lead Developer:<br><strong>Saurabh kumar  (Moranda)</strong></p>

                    <div class="legal-box">
                        <strong>Legal Notice:</strong> This system is designed strictly for defensive security research, monitoring, and resilience testing. No offensive exploitation is performed. All deception strategies are containment-focused.
                    </div>
                </div>
            </div>
        </div>

        <script>
            function openAbout(){ document.getElementById('aboutModal').style.display='block'; }
            function closeAbout(){ document.getElementById('aboutModal').style.display='none'; }

            // Close on outside click
            window.onclick = function(event) {
                let modal = document.getElementById('aboutModal');
                if (event.target == modal) { modal.style.display = "none"; }
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
                        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:30px; color:#94a3b8;">No active sessions detected.</td></tr>';
                        return;
                    }

                    sessions.forEach(s => {
                        let verdictBadge = '';
                        if (s.verdict === 'Hostile') {
                            threatCount++;
                            verdictBadge = '<span class="badge badge-crit">CRITICAL RISK</span>';
                        } else if (s.verdict === 'Suspicious') {
                            verdictBadge = '<span class="badge badge-warn">SUSPICIOUS</span>';
                        } else {
                            verdictBadge = '<span class="badge badge-safe">LOW RISK</span>';
                        }

                        let chain = s.mitre_chain.length > 0 
                            ? s.mitre_chain.map(t => `<span class="code-text">${t}</span>`).join(" → ")
                            : '<span style="color:#cbd5e1">None</span>';

                        let responseText = s.is_deceived 
                            ? `<span style="color:var(--accent); font-weight:600;">⚡ Active Deception (${s.active_strategy})</span>`
                            : '<span class="response-text">Monitoring</span>';

                        let html = `
                        <tr>
                            <td style="font-family:'Roboto Mono'; font-weight:500;">${s.ip}</td>
                            <td>${verdictBadge}</td>
                            <td>
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <span style="font-weight:600;">${s.intent_score}</span>
                                    <div style="width:50px; height:4px; background:#e2e8f0; border-radius:2px; overflow:hidden;">
                                        <div style="width:${Math.min(s.intent_score, 100)}%; height:100%; background:${s.intent_score > 60 ? '#ef4444' : '#3b82f6'};"></div>
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
                } catch (e) { console.log("Connection lost"); }
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
    let mut reasons = Vec::new(); let mut score = 0;
    
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
    
    reasons.push("Auth missing".into()); score = cmp::min(score + 20, 100);
    
    let (policy_delay, _) = {
        let d = state.lock().unwrap(); let p = &d.policy;
        (if score < 30 { p.delays.low } else if score < p.containment_threshold { p.delays.medium } else { p.delays.high }, p.containment_threshold)
    };
    
    let (is_deceived, strategy) = {
        let mut s = state.lock().unwrap();
        if score >= s.policy.containment_threshold { s.total_containments += 1; }
        let (deceived, strat) = update_session(&mut s, &ip, score, "/admin", &reasons);
        if deceived { s.total_time_wasted += policy_delay; if let Some(sess) = s.sessions.get_mut(&ip) { sess.time_wasted_ms += policy_delay; } }
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
    Html(r#"<html><body style="background:#0B0F14;color:red;display:flex;justify-content:center;align-items:center;height:100vh;"><h1>Access Restricted</h1></body></html>"#.to_string())
}

async fn stats_handler(State(state): State<Arc<Mutex<AppState>>>) -> Json<AppState> {
    let data = state.lock().unwrap(); Json(data.clone())
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

    println!("\n🚀 CYBERMORANDA CIDS v3.6 [OFFICE RCE EDITION]");
    println!("🛡️  Protection: Office/Shellcode Detection Active");
    println!("📡 Console: http://localhost:3000\n");

    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap(), app).await.unwrap();
}

