import sys
import asyncio
import logging
import sqlite3
import time
import subprocess
import markdown
import re
import platform
import socket
import threading
import httpx
import os
from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI, WebSocket, Request, Form, BackgroundTasks, Response
from fastapi.responses import HTMLResponse, FileResponse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key

# Silencing low-level transport framework exceptions from cluttering terminal
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

if sys.platform == "win32":
    from asyncio.proactor_events import _ProactorBasePipeTransport
    original_call_connection_lost = _ProactorBasePipeTransport._call_connection_lost
    def patched_call_connection_lost(self, exc):
        try:
            original_call_connection_lost(self, exc)
        except (ConnectionResetError, OSError) as e:
            if getattr(e, 'winerror', None) == 10054 or "10054" in str(e):
                pass
            else:
                raise e
    _ProactorBasePipeTransport._call_connection_lost = patched_call_connection_lost

app = FastAPI()
exam_cache = {}

# --- LOCAL NETWORK PORT ARCHITECTURE INTERFACES ---
LOCAL_IP = "192.168.137.1"  # Hotspot Gateway IP
DNS_PORT = 53
WEB_PORT = 443  # Force full SSL Context pipeline tracking
HTTP_DETECT_PORT = 80  # Plain-HTTP responder so OS captive-portal probes actually get an answer

# Domains phones/OSes use to silently check "do I have real internet". Shared by both
# the HTTP detection listener and the HTTPS catch-all so they answer identically.
SYSTEM_TELEMETRY_ENDPOINTS = [
    "generate_204", "gen_204", "connectivitycheck", "ncsi", "connecttest", "success.txt"
]

CLOUD_LLM_URL = "https://api.groq.com/openai/v1/chat/completions"
CLOUD_API_KEY = os.environ.get("GROQ_API_KEY", "")


# --- BACKGROUND WORKER: DNS SPOOFER LAYER ---
def run_dns_spoofer():
    from dnslib import DNSRecord, A, RR
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udps.bind(('0.0.0.0', DNS_PORT))
        print(f"📡 [DNS Spoofer] Active. Intercepting traffic on port {DNS_PORT}...")
    except Exception as e:
        print(f"❌ DNS Server failed to start on port {DNS_PORT}: {e}")
        print("   This means something else already owns port 53 -- almost always Windows' own")
        print("   Internet Connection Sharing (ICS) service, which auto-binds port 53 on the hotspot")
        print("   adapter the moment Mobile Hotspot is turned on, to hand out DNS to connecting phones.")
        print("   Whichever process binds port 53 first wins. Fix: turn the hotspot OFF, stop this")
        print("   script, start this script again FIRST, then turn the hotspot back ON.")
        return

    while True:
        try:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)
            reply = request.reply()
            qname = request.q.qname
            
            reply.add_answer(RR(qname, rdata=A(LOCAL_IP), ttl=60))
            udps.sendto(reply.pack(), addr)
        except socket.error:
            continue
        except Exception:
            break


# --- BACKGROUND WORKER: PLAIN-HTTP CAPTIVE-PORTAL DETECTION LISTENER ---
# Android/iOS run their captive-portal connectivity probe over plain HTTP by design, so a
# broken/self-signed TLS cert on the real (443) server can't interfere with detection. Without
# something answering on port 80, that probe gets a connection refusal, which the OS reads as
# "no network" rather than "captive portal present" -- so the native sign-in popup never launches.
# This listener's only job is to give that probe a real HTTP response and hand everything else
# off to the existing HTTPS pipeline; it does not touch registration, signing, or fraud checks.
def run_http_redirect_server():
    from fastapi import FastAPI as _FastAPI, Response as _Response

    http_app = _FastAPI()

    @http_app.api_route("/{path_name:path}", methods=["GET", "POST", "HEAD"])
    async def http_catch_all(path_name: str, response: _Response):
        if any(endpoint in path_name.lower() for endpoint in SYSTEM_TELEMETRY_ENDPOINTS):
            response.status_code = 204
            return response
        response.headers["Location"] = f"https://{LOCAL_IP}:{WEB_PORT}/generate-captive-window"
        response.status_code = 302
        return response

    async def _serve():
        import uvicorn
        config = uvicorn.Config(http_app, host="0.0.0.0", port=HTTP_DETECT_PORT, log_level="warning")
        server = uvicorn.Server(config)
        await server.serve()

    try:
        print(f"📡 [HTTP Detect] Listening on port {HTTP_DETECT_PORT} for captive-portal probes...")
        asyncio.run(_serve())
    except Exception as e:
        print(f"❌ HTTP detection listener failed to start (port {HTTP_DETECT_PORT} may need admin/root, or is in use): {e}")


# --- UTILITY: NETWORK DEEP-LAYER MAC RESOLVER ---
def get_client_mac(client_ip: str) -> str:
    try:
        current_os = platform.system().lower()
        if "windows" in current_os:
            output = subprocess.check_output(["arp", "-a", client_ip], creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0).decode("utf-8", errors="ignore")
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output)
        else:
            output = subprocess.check_output(["arp", "-n", client_ip]).decode("utf-8", errors="ignore")
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output)
        if mac_match:
            return mac_match.group(0).lower().replace("-", ":")
    except Exception as e:
        print(f"Failed to fetch MAC via ARP entry lookup: {e}")
    return "unknown_mac"


def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS airgated_device_registry (
            roll_number TEXT PRIMARY KEY,
            name TEXT,
            public_key_hex TEXT,
            hardware_mac TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS airgated_attendance_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_number TEXT,
            timestamp REAL,
            latency_ms REAL,
            network_ip TEXT,  
            network_mac TEXT   
        )
    """)
    conn.commit()
    conn.close()

init_db()


# --- MODULE 1 SECURE LAYOUT CAPTIVE PORTAL INTERFACE ---
@app.get("/generate-captive-window", response_class=HTMLResponse)
async def captive_portal_window():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AirGated - Verification Gate</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #fafafa; color: #333; }
            .container { max-width: 400px; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); margin: 20px auto; }
            #checkin-box { border-top: 4px solid #7928ca; }
            #register-box { border-top: 4px solid #0070f3; display: none; }
            h2 { margin-top: 0; color: #111; font-size: 1.5em; text-align: center; }
            p { color: #666; font-size: 0.9em; line-height: 1.5; text-align: center; margin-bottom: 25px; }
            label { font-weight: 600; font-size: 0.85em; color: #444; display: block; margin-bottom: 5px; }
            input { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; font-size: 1em; background: #fdfdfd; }
            button { width: 100%; padding: 14px; color: white; border: none; border-radius: 8px; font-size: 1em; font-weight: 600; cursor: pointer; width: 100%; }
            .btn-checkin { background: #7928ca; }
            .btn-register { background: #0070f3; }
            button:disabled { background: #ccc; cursor: not-allowed; }
            .status-msg { margin-bottom: 20px; padding: 12px; background: #f4f4f5; border-radius: 8px; font-weight: 500; font-size: 0.9em; border: 1px solid #e4e4e7; text-align: center;}
            #debug-log { margin-top: 20px; white-space: pre-wrap; font-family: monospace; font-size: 0.85em; color: #555; background: #f3f3f3; padding: 12px; border-radius: 8px; display: none; border: 1px solid #e4e4e7; }
        </style>
    </head>
    <body>

        <div id="checkin-box" class="container">
            <h2>Classroom Authentication</h2>
            <div id="status-box" class="status-msg">Status: Verifying local node token data...</div>
            <form id="checkinForm" onsubmit="return false;">
                <label>University Roll Number</label>
                <input type="text" id="roll" placeholder="Enter Registered Roll Number" required>
                <button type="button" class="btn-checkin" id="scanBtn" onclick="startCheckIn()">Mark Presence</button>
            </form>
        </div>

        <div id="register-box" class="container">
            <h2>Enroll Identity (Day 1)</h2>
            <p>No valid cryptographic anchor found. Please register this physical hardware profile.</p>
            <form id="regForm" onsubmit="return false;">
                <label>Roll Number</label>
                <input type="text" id="reg-roll" placeholder="e.g., CSJMA24001390" required>
                <label>Full Name</label>
                <input type="text" id="reg-name" placeholder="e.g., David Dhawan" required>
                <button type="button" class="btn-register" id="regBtn" onclick="handleRegistration()">Register Hardware Anchor</button>
            </form>
            <div id="debug-log"></div>
        </div>

        <script>
            const MOCK_CHALLENGE_FROM_QR = "classroom_session_challenge_xyz123";

            // SECURITY: private key lives only as a non-extractable CryptoKey inside IndexedDB.
            // It is never exported to bytes and never touches localStorage, so it cannot be copied
            // to a second device the way a base64-exported key could be (see Finding 4.1).
            function openKeyDB() {
                return new Promise((resolve, reject) => {
                    const req = indexedDB.open("LocalDeviceAuth", 1);
                    req.onupgradeneeded = () => { req.result.createObjectStore("keys"); };
                    req.onsuccess = () => resolve(req.result);
                    req.onerror = () => reject(req.error);
                });
            }

            async function getStoredPrivateKey() {
                const db = await openKeyDB();
                return new Promise((resolve, reject) => {
                    const tx = db.transaction("keys", "readonly");
                    const getReq = tx.objectStore("keys").get("sk");
                    getReq.onsuccess = () => resolve(getReq.result || null);
                    getReq.onerror = () => reject(getReq.error);
                });
            }

            async function savePrivateKey(cryptoKey) {
                const db = await openKeyDB();
                return new Promise((resolve, reject) => {
                    const tx = db.transaction("keys", "readwrite");
                    tx.objectStore("keys").put(cryptoKey, "sk");
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            }

            window.onload = async function() {
                try {
                    const storedKey = await getStoredPrivateKey();
                    if (!storedKey) {
                        document.getElementById("checkin-box").style.display = "none";
                        document.getElementById("register-box").style.display = "block";
                    } else {
                        document.getElementById("status-box").innerText = "Status: Device anchored. Ready to verify.";
                    }
                } catch (e) {
                    document.getElementById("checkin-box").style.display = "none";
                    document.getElementById("register-box").style.display = "block";
                }
            };

            function updateStatus(msg, color = "black") {
                const box = document.getElementById("status-box");
                box.innerText = "Status: " + msg; box.style.color = color;
            }

            function logStatus(msg) {
                const logDiv = document.getElementById('debug-log');
                logDiv.style.display = "block";
                logDiv.innerText += "\\n> " + msg;
            }

            function arrayBufferToBase64(buffer) {
                var binary = ''; var bytes = new Uint8Array(buffer);
                for (var i = 0; i < bytes.byteLength; i++) { binary += String.fromCharCode(bytes[i]); }
                return window.btoa(binary);
            }

            function base64ToUint8Array(base64) {
                var binary_string = window.atob(base64);
                var bytes = new Uint8Array(binary_string.length);
                for (var i = 0; i < binary_string.length; i++) { bytes[i] = binary_string.charCodeAt(i); }
                return bytes;
            }

            async function startCheckIn() {
                const roll = document.getElementById('roll').value.trim();
                if (!roll) { alert("Roll Number required."); return; }
                updateStatus("Evaluating link speed via WebSocket...", "blue");

                const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
                const socket = new WebSocket(`${wsProtocol}//${window.location.host}/ws/latency`);
                let measuredRTT = 999.0;

                socket.onmessage = async (event) => {
                    const data = JSON.parse(event.data);
                    if (data.type === "ping") { socket.send(JSON.stringify({ type: "pong" })); } 
                    else if (data.type === "latency_result") {
                        measuredRTT = data.rtt_ms;
                        updateStatus(`Proximity Verified (${measuredRTT.toFixed(2)}ms). Fetching token...`, "blue");
                        await executeSignature(roll, measuredRTT);
                    }
                };
            }

            async function executeSignature(roll, rtt) {
                try {
                    updateStatus("Signing temporary session token...", "blue");

                    const privateKey = await getStoredPrivateKey();
                    if (!privateKey) {
                        updateStatus("❌ Device Signature Missing! Have you registered this device yet?", "red");
                        return;
                    }
                    const signatureBuffer = await window.crypto.subtle.sign(
                        { name: "RSASSA-PKCS1-v1_5" }, privateKey, new TextEncoder().encode(MOCK_CHALLENGE_FROM_QR)
                    );
                    const signatureHex = Array.prototype.map.call(new Uint8Array(signatureBuffer), x => ('0' + x.toString(16)).slice(-2)).join('');

                    updateStatus("Transmitting verification signatures...", "blue");
                    const formData = new FormData();
                    formData.append("roll_number", roll);
                    formData.append("signature_hex", signatureHex);
                    formData.append("original_challenge", MOCK_CHALLENGE_FROM_QR);
                    formData.append("current_rtt", rtt);

                    // FIXED: Force reference route directly to relative paths to keep within SSL context boundaries
                    const res = await fetch("/api/checkin", { method: "POST", body: formData });
                    const result = await res.json();

                    if (result.status === "success") updateStatus("✅ " + result.message, "green");
                    else updateStatus("❌ " + result.reason, "red");
                } catch (err) { updateStatus("❌ Signature Error: " + err.message, "red"); }
            }

            async function handleRegistration() {
                document.getElementById('debug-log').innerText = "";
                const roll = document.getElementById('reg-roll').value.trim();
                const name = document.getElementById('reg-name').value.trim();
                if (!roll || !name) { alert("Please complete all profile fields."); return; }

                document.getElementById('regBtn').disabled = true;
                try {
                    logStatus("Generating asymmetric cryptographic anchor...");
                    const keyPair = await window.crypto.subtle.generateKey(
                        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
                        false, ["sign", "verify"]
                    );

                    logStatus("Locking private key to non-extractable IndexedDB storage...");
                    await savePrivateKey(keyPair.privateKey);
                    logStatus("Private identity token locked to this device. It cannot be exported or copied.");

                    const exportedPub = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
                    const pubHex = Array.prototype.map.call(new Uint8Array(exportedPub), x => ('0' + x.toString(16)).slice(-2)).join('');
                    
                    const formData = new FormData();
                    formData.append("roll_number", roll);
                    formData.append("name", name);
                    formData.append("public_key", pubHex);

                    // FIXED: Relative endpoint formatting preserves headers cleanly over HTTPS port map boundaries
                    const res = await fetch("/api/register", { method: "POST", body: formData });
                    const data = await res.json();
                    
                    logStatus("Gateway Response: " + JSON.stringify(data));
                    alert(data.message);
                    
                    document.getElementById("register-box").style.display = "none";
                    document.getElementById("checkin-box").style.display = "block";
                    document.getElementById("roll").value = roll;
                    updateStatus("Device link compiled! Ready to verify attendance.", "green");
                } catch (error) {
                    logStatus("❌ ERROR: " + error.message);
                    document.getElementById('regBtn').disabled = false;
                }
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)


# --- API ENDPOINT: REGISTRATION & AUTO-RESET OVERRIDE ---
@app.post("/api/register")
async def register_student(request: Request, roll_number: str = Form(...), name: str = Form(...), public_key: str = Form(...)):
    client_ip = request.client.host
    hardware_mac = get_client_mac(client_ip)
    print(f"📥 [Register Request] Roll: {roll_number} | IP: {client_ip} | MAC: {hardware_mac}")

    if hardware_mac == "unknown_mac" and client_ip != "127.0.0.1":
        return {"status": "error", "message": "Could not extract physical MAC signature. Reconnect to class network."}

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT roll_number, name FROM airgated_device_registry WHERE hardware_mac = ?", (hardware_mac,))
        existing_device = cursor.fetchone()
        
        if existing_device:
            existing_roll, existing_name = existing_device
            print(f"🔄 [Auto-Reset Triggered] MAC {hardware_mac} matches profile ({existing_roll}). Overwriting keys...")
            cursor.execute(
                "UPDATE airgated_device_registry SET public_key_hex = ?, roll_number = ?, name = ? WHERE hardware_mac = ?",
                (public_key, roll_number, name, hardware_mac)
            )
            conn.commit()
            return {"status": "success", "message": "Cache clear detected! Your device link has been auto-recovered successfully."}

        cursor.execute("INSERT INTO airgated_device_registry VALUES(?, ?, ?, ?)", (roll_number, name, public_key, hardware_mac))
        conn.commit()
        return {"status": "success", "message": "Device registered successfully!"}
    except Exception as e:
        return {"status": "error", "message": f"SQLite Execution Failure: {str(e)}"}
    finally:
        conn.close()


# --- WEBSOCKET REAL-TIME PROXIMITY CHANNEL ---
@app.websocket("/ws/latency")
async def websocket_latency_endpoint(websocket: WebSocket):
    await websocket.accept()
    for _ in range(3):
        start_time = time.time()
        await websocket.send_json({"type": "ping"})
        await websocket.receive_json()
        end_time = time.time()
    rtt_ms = (end_time - start_time) * 1000
    await websocket.send_json({"type": "latency_result", "rtt_ms": rtt_ms})
    await websocket.close()


# --- VALIDATION ATTENDANCE ENGINE ENTRYPOINT ---
@app.post("/api/checkin")
async def verify_checkin(request: Request, roll_number: str = Form(...), signature_hex: str = Form(...), original_challenge: str = Form(...), current_rtt: float = Form(...)):
    client_ip = request.client.host
    incoming_mac = get_client_mac(client_ip)
    print(f"📥 [Checkin Verification] Evaluating signature for Roll: {roll_number} | RTT: {current_rtt}ms")

    if current_rtt > 20.0:
        print(f"🚫 [Checkin Rejected] Roll: {roll_number} | Reason: latency gate exceeded ({current_rtt}ms > 20.0ms threshold, possible proxy/tunnel)")
        return {"status": "fraud", "reason": "Network latency too high. Proxy/Tunnel detected."}
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT public_key_hex, hardware_mac FROM airgated_device_registry WHERE roll_number = ?", (roll_number,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        print(f"🚫 [Checkin Rejected] Roll: {roll_number} | IP: {client_ip} | Reason: no registry entry for this roll number (Stage 2 registry lookup failed)")
        return {"status": "error", "reason": "Device missing registration in hardware registry."}
    
    public_key_hex, registered_mac = result

    if client_ip != "127.0.0.1" and registered_mac != "unknown_mac" and incoming_mac != registered_mac:
        conn.close()
        print(f"🚫 [Checkin Rejected] Roll: {roll_number} | Reason: MAC binding mismatch (request from {incoming_mac}, registered device is {registered_mac}) -- Stage 3 hardware binding failed")
        return {"status": "fraud", "reason": "Hardware MAC address signature mismatch."}
    
    try:
        pub_key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = load_der_public_key(pub_key_bytes)
        
        public_key.verify(sig_bytes, original_challenge.encode(), padding.PKCS1v15(), hashes.SHA256())
        
        if incoming_mac != "unknown_mac":
            one_minute_ago = time.time() - 60.0
            cursor.execute("SELECT roll_number FROM airgated_attendance_records WHERE network_mac = ? AND timestamp > ? AND roll_number != ?", (incoming_mac, one_minute_ago, roll_number))
            other_roll = cursor.fetchone()
            if other_roll:
                print(f"🚫 [Checkin Rejected] Roll: {roll_number} | Reason: 60s multi-profile lockout -- MAC {incoming_mac} already checked in as {other_roll[0]} within the last minute")
                return {"status": "fraud", "reason": "Multiple profile check-in detected from single hardware block."}

        cursor.execute("INSERT INTO airgated_attendance_records (roll_number, timestamp, latency_ms, network_ip, network_mac) VALUES (?, ?, ?, ?, ?)", (roll_number, time.time(), current_rtt, client_ip, incoming_mac))
        conn.commit()
        print(f"🎉 [Gateway Success] Attendance stored cleanly in SQLite ledger for Roll: {roll_number}!")
        return {"status": "success", "message": "Attendance token logged successfully!"}
    except Exception as e:
        print(f"🚫 [Checkin Rejected] Roll: {roll_number} | Reason: signature/processing exception -- {type(e).__name__}: {e}")
        return {"status": "fraud", "reason": f"Signature validation failed: {str(e)}"}
    finally:
        conn.close()


# --- COGNITIVE AI EXAM CREATOR VIEW DASHBOARD ---
@app.get("/generate-exam", response_class=HTMLResponse)
async def get_generation_page():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AirGated - AI Portal</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 3em; background: #fafafa; color: #333; }
            .container { max-width: 650px; background: white; padding: 2.5em; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); margin: 0 auto; }
            h2 { margin-top: 0; color: #111; font-size: 1.6em; }
            p { color: #666; font-size: 0.95em; line-height: 1.5; }
            textarea { width: 100%; height: 200px; padding: 12px; margin: 15px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 1em; font-family: inherit; resize: vertical; }
            button { width: 100%; padding: 12px; background: #7928ca; color: white; border: none; border-radius: 6px; font-size: 1em; font-weight: 600; cursor: pointer; transition: background 0.2s; }
            button:hover { background: #611f9f; }
            #status-box { margin-top: 20px; padding: 15px; border-radius: 6px; display: none; font-size: 0.95em; }
            .processing { background: #f3e8ff; color: #6b21a8; border: 1px solid #d8b4fe; }
            .success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
            a.download-btn { display: inline-block; margin-top: 10px; padding: 8px 16px; background: #166534; color: white; text-decoration: none; border-radius: 4px; font-weight: 600; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Context-Based Question Paper Generator</h2>
            <form id="examForm" onsubmit="return false;">
                <textarea id="contextText" placeholder="Paste textbook context here..." required></textarea>
                <button type="button" id="genBtn" onclick="triggerGeneration()">Compile Question Paper (PDF)</button>
            </form>
            <div id="status-box"></div>
        </div>
        <script>
            function showStatus(msg, type) {
                const box = document.getElementById("status-box");
                box.className = type; box.style.display = "block"; box.innerHTML = msg;
            }
            async function triggerGeneration() {
                const context = document.getElementById("contextText").value;
                if (!context.trim()) return;
                document.getElementById("genBtn").disabled = true;
                showStatus("Communicating with AirGated cloud pipeline...", "processing");
                const formData = new FormData();
                formData.append("context_text", context);
                try {
                    const res = await fetch("/api/generate-exam", { method: "POST", body: formData });
                    const data = await res.json();
                    if (data.status === "processing") {
                        showStatus("<strong>Pipeline Active:</strong> drafting question paper...<br><a href='" + data.download_url + "' class='download-btn' target='_blank'>Check & Download PDF</a>", "success");
                    }
                } catch (err) { btn.disabled = false; }
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

# =====================================================================
# STEP 1: DEFINE THE WORKER FIRST (Must sit above the endpoint)
# =====================================================================
async def generate_exam_worker(prompt_context: str, session_id: str):
    system_prompt = (
        "You are an expert university professor. Draft a strict, context-based examination paper "
        "containing Section A (Multiple Choice Questions) and Section B (Subjective Long Answer Questions) "
        "based entirely on the provided text. Use proper Markdown styling for your output (# for sections, "
        "1. for ordered lists, - for options). Do not output any conversational pleasantries or chat context."
    )
    
    headers = {
        "Authorization": f"Bearer {CLOUD_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Context for the exam:\n{prompt_context}"}
        ],
        "temperature": 0.3
    }
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(CLOUD_LLM_URL, json=payload, headers=headers)
            if response.status_code == 200:
                raw_markdown = response.json()["choices"][0]["message"]["content"]
            else:
                raw_markdown = f"### Generation Error\nServer returned status code {response.status_code}\n\n{response.text}"
        
        html_body = markdown.markdown(raw_markdown)
        
        printable_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AirGated Evaluation Portal</title>
            <style>
                @page {{ size: A4; margin: 20mm; }}
                body {{ font-family: "Times New Roman", Times, serif; font-size: 12pt; line-height: 1.6; color: #000; margin: 0; padding: 0; }}
                .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #000; padding-bottom: 10px; }}
                .header h1 {{ font-size: 16pt; margin: 0 0 5px 0; text-transform: uppercase; }}
                .header h2 {{ font-size: 12pt; font-weight: normal; font-style: italic; margin: 0; }}
                h1, h2, h3 {{ font-family: Arial, Helvetica, sans-serif; page-break-after: avoid; }}
                h1 {{ font-size: 14pt; border-bottom: 1px solid #ddd; margin-top: 25px; padding-bottom: 3px; }}
                h2 {{ font-size: 12pt; margin-top: 20px; }}
                ul, ol {{ margin-top: 5px; padding-left: 25px; }}
                li {{ margin-bottom: 5px; }}
                .no-print-bar {{ background: #f4f4f5; padding: 15px; border-bottom: 1px solid #e4e4e7; text-align: center; margin-bottom: 30px; font-family: sans-serif; }}
                .print-btn {{ padding: 10px 24px; background: #7928ca; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; }}
                @media print {{
                    .no-print-bar {{ display: none !important; }}
                    body {{ font-size: 12pt; line-height: 1.5; }}
                }}
            </style>
        </head>
        <body>
            <div class="no-print-bar">
                <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
            </div>
            <div class="header">
                <h1>Institutional Evaluation Portal</h1>
                <h2>Automated Context-Based Examination Sheet</h2>
            </div>
            <div class="content">{html_body}</div>
        </body>
        </html>
        """
        exam_cache[session_id] = printable_template
        print(f"✅ [AI Engine] Rendered layout mapped successfully: {session_id}")
    except Exception as e:
        exam_cache[session_id] = f"<h2>System Compilation Exception</h2><p>{str(e)}</p>"

@app.post("/api/generate-exam")
async def create_exam(background_tasks: BackgroundTasks, context_text: str = Form(...)):
    session_id = f"exam_{int(time.time())}"
    exam_cache[session_id] = "<h2>Processing...</h2><p>The AirGated AI engine is drafting your question paper document. Please reload this tab momentarily.</p>"
    background_tasks.add_task(generate_exam_worker, context_text, session_id)
    return {"status": "processing", "message": "The AirGated AI engine is drafting the question paper.", "download_url": f"/view-exam/{session_id}"}


@app.get("/view-exam/{session_id}", response_class=HTMLResponse)
async def view_exam(session_id: str):
    return exam_cache.get(session_id, "<h2>Invalid Token</h2>")


# --- MODULE 1 CATCH-ALL ROUTE INTERCEPTOR MIDDLEWARE (HARDENED) ---
# MUST be the last HTTP route registered. Starlette/FastAPI match routes in registration
# order and this pattern (/{path_name:path}) matches literally any path, so if it were
# registered before the real endpoints above, it would intercept every request meant for
# them first -- including POST /api/register and POST /api/checkin, both of which are in
# its own exempt_paths list. A bare `return` from a matched route does not "fall through"
# to the next matching route in Starlette; it just sends an empty body, which FastAPI
# serializes as the JSON literal `null`. That is exactly what was happening here: every
# registration and check-in request was being silently swallowed by this handler and
# answered with `null` instead of ever reaching register_student() or verify_checkin().
@app.api_route("/{path_name:path}", methods=["GET", "POST"])
async def intercept_all_traffic(path_name: str, response: Response):
    exempt_paths = [
        "generate-captive-window", "api/register", "api/checkin", "ws/latency", "favicon.ico"
    ]

    # FIXED: Split layout checks allow API path segments to clear validation logic blocks seamlessly
    base_segment = path_name.split("/")[0]
    if path_name in exempt_paths or base_segment in ["api", "ws", "view-exam"]:
        return

    if any(endpoint in path_name.lower() for endpoint in SYSTEM_TELEMETRY_ENDPOINTS):
        response.status_code = 204
        return response

    print(f"🪤 [Captive Trap] Intercepted user resource fetch: /{path_name} -> Forcing Secure HTTPS Redirect.")
    response.headers["Location"] = f"https://{LOCAL_IP}:{WEB_PORT}/generate-captive-window"
    response.status_code = 302
    return {"message": "Redirecting to Secure Classroom Authentication Gateway..."}


if __name__ == "__main__":
    dns_thread = threading.Thread(target=run_dns_spoofer, daemon=True)
    dns_thread.start()

    http_detect_thread = threading.Thread(target=run_http_redirect_server, daemon=True)
    http_detect_thread.start()

    import uvicorn
    import trustme

    ca = trustme.CA()
    server_cert = ca.issue_cert(LOCAL_IP, "localhost", "127.0.0.1")

    ssl_dir = "ssl_certs"
    os.makedirs(ssl_dir, exist_ok=True)
    cert_path = os.path.join(ssl_dir, "server.crt")
    key_path = os.path.join(ssl_dir, "server.key")

    server_cert.private_key_pem.write_to_path(key_path)
    server_cert.cert_chain_pems[0].write_to_path(cert_path)

    print(f"\n🔒 [Security Engine] SSL Certificate deployed successfully at {cert_path}")
    print(f"🚀 Launching Secure FastAPI Web Server on HTTPS://{LOCAL_IP}:443")
    
    uvicorn.run(
        "server:app", 
        host="0.0.0.0", 
        port=443, 
        ssl_certfile=cert_path, 
        ssl_keyfile=key_path,
        reload=False
    )