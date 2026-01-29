use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, Uri};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

// --- GLOBAL MEMORY ---
type ScoreStore = Arc<Mutex<HashMap<String, i32>>>;

// --- ENTERPRISE DECEPTION UI ---
// Ye UI wahi hai (Blue Theme), bas variable clean rakha hai
const FAKE_ADMIN_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign in to CyberMoranda Console</title>
    <style>
        :root { --bg-color: #0b1120; --card-bg: #1e293b; --primary: #0ea5e9; --text-main: #f1f5f9; --border: #334155; }
        body { background-color: var(--bg-color); color: var(--text-main); font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-card { width: 400px; background: var(--card-bg); padding: 48px; border-radius: 12px; border: 1px solid var(--border); text-align: center; }
        .brand-logo { width: 64px; height: 64px; margin-bottom: 24px; fill: var(--primary); }
        h2 { margin-bottom: 8px; color: #fff; }
        input { width: 100%; padding: 12px; background: #0f172a; border: 1px solid var(--border); border-radius: 8px; color: #fff; margin-bottom: 15px; }
        .btn-primary { width: 100%; padding: 14px; background-color: var(--primary); color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; }
        .env-badge { padding: 4px 12px; background: rgba(14, 165, 233, 0.1); color: var(--primary); border-radius: 99px; font-size: 0.75rem; margin-bottom: 24px; border: 1px solid rgba(14, 165, 233, 0.2); display: inline-block; }
    </style>
</head>
<body>
    <div class="login-card">
        <svg class="brand-logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M13.5 2c-5.621 0-10.211 4.443-10.475 10h-3.025l5 6.625 5-6.625h-2.975c.257-3.351 3.06-6 6.475-6 3.584 0 6.5 2.916 6.5 6.5s-2.916 6.5-6.5 6.5c-1.863 0-3.542-.793-4.728-2.053l-2.427 3.216c1.877 1.754 4.389 2.837 7.155 2.837 5.79 0 10.5-4.71 10.5-10.5s-4.71-10.5-10.5-10.5z"/></svg>
        <div class="env-badge">CIDS PROTECTION ACTIVE</div>
        <h2>Welcome back</h2>
        <p style="color: #94a3b8; margin-bottom: 30px;">Enter credentials to access <strong>CyberMoranda</strong> environment.</p>
        <input type="email" placeholder="name@cybermoranda.com">
        <input type="password" placeholder="••••••••••••">
        <button class="btn-primary" onclick="alert('⛔ Access Denied: Account flagged by CIDS Policy Engine.')">Sign In</button>
        <div style="margin-top: 30px; font-size: 0.75rem; color: #94a3b8;">v2.4.0-PROD • Session ID: 8A2-EXP</div>
    </div>
</body>
</html>
"#;

// --- PROXY LOGIC ---
async fn proxy(req: Request<Body>, scores: ScoreStore) -> Result<Response<Body>, Infallible> {
    let client_ip = "127.0.0.1";
    let path = req.uri().path().to_string();

    // 1. Reset Command
    if path.contains("/reset-cids") {
        let mut store = scores.lock().unwrap();
        store.insert(client_ip.to_string(), 0);
        return Ok(Response::new(Body::from("✅ CIDS Memory Wiped!")));
    }

    // 2. SCORING ENGINE
    let mode; // OBSERVE | TARPIT | DECEPTION
    let current_score;
    let confidence_percent;

    {
        let mut store = scores.lock().unwrap();
        let score = store.entry(client_ip.to_string()).or_insert(0);
        let mut risk_detected = false;

        // A. DECOY ZONES
        if path.contains("/admin") { *score += 40; risk_detected = true; }
        if path.contains("wp-admin") { *score += 50; risk_detected = true; }
        if path.contains(".env") { *score += 100; risk_detected = true; }

        // B. REAL DOOR (Allowlist Logic)
        if path.contains("/portal-secure") {
            *score = score.saturating_sub(50); // Trust restore
        }

        // C. LOGIN BEHAVIOR
        if path.contains("/login") && !path.contains("/portal-secure") {
            *score += 20; risk_detected = true;
        }


        // D. NATURAL DECAY
        if !risk_detected && *score > 0 {
             *score = score.saturating_sub(5); 
        }

        current_score = *score;
        
        confidence_percent = ((current_score as f32 / 200.0) * 100.0).min(100.0);

        // E. MODE SELECTION (Updated Logic)
        if current_score >= 200 { 
            mode = "DECEPTION"; 
        } else if current_score >= 100 { 
            mode = "TARPIT"; 
        } else { 
            mode = "OBSERVE"; 
        }
    } 

    // 3. TARPIT EXECUTION
    if mode == "TARPIT" {
        println!("[CIDS] 🐢 Tarpitting request (2s delay)...");
        sleep(Duration::from_secs(2)).await;
    }

    // LOGS
    println!(
        "[CIDS] Path: {:<15} | Score: {:<3} | Conf: {:.0}% | Mode: {}", 
        path, current_score, confidence_percent, mode
    );

    // 4. DECEPTION EXECUTION (Polish #4)
    if mode == "DECEPTION" {
        let response = Response::builder()
            .status(403) // 🔥 Status Code 403 Forbidden (Realism)
            .header("Content-Type", "text/html")
            .body(Body::from(FAKE_ADMIN_HTML))
            .unwrap();
        return Ok(response);
    }

    // 5. FORWARDING
    let client = Client::new();
    let uri_string = format!("http://127.0.0.1:5000{}", path);
    let uri = uri_string.parse::<Uri>().unwrap();

    let mut builder = Request::builder().method(req.method()).uri(uri);
    for (key, value) in req.headers() { builder = builder.header(key, value); }
    let new_req = builder.body(req.into_body()).unwrap();

    match client.request(new_req).await {
        Ok(res) => Ok(res),
        Err(_) => Ok(Response::new(Body::from("❌ Error: Website unreachable!")))
    }
}

// --- SERVER ---
#[tokio::main]
async fn main() {
    let scores: ScoreStore = Arc::new(Mutex::new(HashMap::new()));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let make_svc = make_service_fn(move |_| {
        let scores = scores.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| { proxy(req, scores.clone()) })) }
    });

    println!("🛡️  CyberMoranda CIDS Ready on Port 3000");
    println!("✅ Mode: Reverse Proxy (Decoy vs Real Architecture)");
    
    let server = Server::bind(&addr).serve(make_svc);
    if let Err(e) = server.await { eprintln!("Server error: {}", e); }
}

