import sqlite3
import time
import subprocess
import re
import platform
from fastapi import FastAPI, WebSocket, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# --- UTILITY: NETWORK ARP LOOKUP ---
def get_client_mac(client_ip: str) -> str:
    """
    Queries the host operating system's ARP cache to retrieve the 
    physical hardware MAC address of a locally connected client IP.
    Works entirely offline on local network loops.
    """
    try:
        current_os = platform.system().lower()
        
        if "windows" in current_os:
            # Windows command: arp -a 192.168.X.X
            output = subprocess.check_output(["arp", "-a", client_ip], creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0).decode("utf-8", errors="ignore")
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output)
        else:
            # Linux/macOS command: arp -n 192.168.X.X
            output = subprocess.check_output(["arp", "-n", client_ip]).decode("utf-8", errors="ignore")
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output)

        if mac_match:
            # Standardize formatting to lowercase with colons
            return mac_match.group(0).lower().replace("-", ":")
            
    except Exception as e:
        print(f"Failed to fetch ARP entry: {e}")
        
    return "unknown_mac"


# --- DATABASE INITIALIZATION ---
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            roll_number TEXT PRIMARY KEY,
            name TEXT,
            public_key_hex TEXT,
            hardware_mac TEXT -- Added to securely bind identity to physical network adapter
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_number TEXT,
            timestamp REAL,
            latency_ms REAL,
            network_ip TEXT,  -- Tracks device connection state
            network_mac TEXT   -- Verifies hardware alignment
        )
    """)
    conn.commit()
    conn.close()

init_db()


# --- REGISTRATION FLOW ---
@app.get("/register", response_class=HTMLResponse)
async def get_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/api/register")
async def register_student(
    request: Request, # Added request context to extract network IP
    roll_number: str = Form(...), 
    name: str = Form(...), 
    public_key: str = Form(...)
):
    client_ip = request.client.host
    hardware_mac = get_client_mac(client_ip)

    # Security check: ensure device is talking via local router/hotspot interface
    if hardware_mac == "unknown_mac" and client_ip != "127.0.0.1":
        return {"status": "error", "message": "Could not extract physical MAC signature. Make sure you are on the class network."}

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    try:
        # Check if this physical device MAC is already assigned to someone else
        cursor.execute("SELECT roll_number FROM students WHERE hardware_mac = ? AND hardware_mac != 'unknown_mac'", (hardware_mac,))
        existing = cursor.fetchone()
        if existing:
            return {"status": "error", "message": f"This physical device is already registered under Roll Number: {existing[0]}"}

        cursor.execute("INSERT INTO students VALUES(?, ?, ?, ?)", (roll_number, name, public_key, hardware_mac))
        conn.commit()
        return {"status": "success", "message": f"Device Registered and tied to MAC: {hardware_mac}"}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "Roll Number already registered"}
    finally:
        conn.close()


# --- CHECKIN & VERIFICATION FLOW ---
@app.get("/checkin", response_class=HTMLResponse)
async def get_checkin_page(request: Request):
    return templates.TemplateResponse("checkin.html", {"request": request})

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

@app.post("/api/checkin")
async def verify_checkin(
    request: Request, # Intercept raw network attributes
    roll_number: str = Form(...), 
    signature_hex: str = Form(...), 
    original_challenge: str = Form(...), 
    current_rtt: float = Form(...)
):
    # Rule 1: Threshold latency check 20ms
    if current_rtt > 20.0:
        return {"status": "fraud", "reason": "Network latency too high. Proxy detected."}
    
    client_ip = request.client.host
    incoming_mac = get_client_mac(client_ip)

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT public_key_hex, hardware_mac FROM students WHERE roll_number = ?", (roll_number,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return {"status": "error", "reason": "Device not registered in local database."}
    
    public_key_hex, registered_mac = result

    # Rule 2: Anti-Proxy Local MAC verification (Stops identical phone models spoofing)
    # Exclude localhost (127.0.0.1) checks to facilitate smooth localized developer desk testing
    if client_ip != "127.0.0.1" and registered_mac != "unknown_mac" and incoming_mac != registered_mac:
        conn.close()
        return {
            "status": "fraud", 
            "reason": f"Hardware MAC mismatch. This roll number is locked to an entirely different device physical address."
        }

    # Cryptographic signature verification
    print("\n--- [DEBUG CRYPTO START] ---")
    print(f"Original Challenge: {original_challenge}")
    print(f"Incoming Network Identity: IP={client_ip} | MAC={incoming_mac}")
    print(f"Stored PubKey Hex (First 30 chars): {public_key_hex[:30]}...")
    print(f"Incoming Signature Hex (First 30 chars): {signature_hex[:30]}...")
    
    try:
        pub_key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        
        public_key = load_der_public_key(pub_key_bytes)
        print("✅ Python successfully parsed the DER Public Key structure!")
        
        public_key.verify(
            sig_bytes,
            original_challenge.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("✅ Cryptographic Signature match verified perfectly!")
        
        # Rule 3: Concurrent Session Lockout Verification
        # Check if this identical MAC address has checked in for a different student profile in the last 60 seconds
        if incoming_mac != "unknown_mac":
            one_minute_ago = time.time() - 60.0
            cursor.execute(
                "SELECT roll_number FROM attendance_log WHERE network_mac = ? AND timestamp > ? AND roll_number != ?", 
                (incoming_mac, one_minute_ago, roll_number)
            )
            collision = cursor.fetchone()
            if collision:
                print(f"❌ CONCURRENCY ATTACK DETECTED: Device {incoming_mac} tried to flag multiple profiles.")
                return {"status": "fraud", "reason": "Multiple profile check-in detected from a single physical device profile."}

        # Record verified match
        cursor.execute(
            "INSERT INTO attendance_log (roll_number, timestamp, latency_ms, network_ip, network_mac) VALUES (?, ?, ?, ?, ?)", 
            (roll_number, time.time(), current_rtt, client_ip, incoming_mac)
        )
        conn.commit()
        return {"status": "success", "message": "Attendance marked successfully!"}
        
    except Exception as e:
        import traceback
        print("❌ CRITICAL ERROR DURING VALIDATION:")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Details: {e}")
        traceback.print_exc()
        print("--- [DEBUG CRYPTO END] ---\n")
        return {"status": "fraud", "reason": f"Cryptographic signature validation failed: {str(e)}"}
    finally:
        conn.close()