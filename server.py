import sys
import asyncio
import datetime
import hashlib
import html
import logging
import random
import secrets
import sqlite3
import statistics
import time
import subprocess
import re
import platform
import socket
import threading
import os
from contextlib import closing
from dataclasses import dataclass

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form, File, UploadFile, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, PlainTextResponse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key

import face_verify

load_dotenv()

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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
SSL_DIR = os.path.join(BASE_DIR, "ssl_certs")
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
DB_PATH = os.environ.get("AIRGATED_DB", os.path.join(BASE_DIR, "database.db"))

# --- LOCAL NETWORK PORT ARCHITECTURE INTERFACES ---
LOCAL_IP = os.environ.get("AIRGATED_LOCAL_IP", "192.168.137.1")  # Hotspot Gateway IP
DNS_PORT = 53
WEB_PORT = 443
HTTP_DETECT_PORT = 80  # Plain-HTTP responder so OS captive-portal probes actually get an answer
LOOPBACK_HOSTS = ("127.0.0.1", "::1")

# --- VERIFICATION POLICY ---
RTT_THRESHOLD_MS = 20.0
RTT_WARMUP_PINGS = 3   # discarded: wake the phone's Wi-Fi radio out of power-save first
RTT_PING_COUNT = 10
CHALLENGE_TTL_SECONDS = 120
CAPTURE_MS = 5000
BLINK_CHOICES = (2, 3)
MAX_FRAMES = 120
MAX_FRAME_BYTES = 300_000
MULTI_PROFILE_WINDOW_SECONDS = 60.0
VERIFIED_CLIENT_SECONDS = 3 * 3600


# --- CAPTIVE-PORTAL CONNECTIVITY PROBES ---
# Phones/OSes fetch these over plain HTTP to decide "is there real internet here?". The answer
# must depend on whether this client has checked in yet:
#   * not yet verified -> redirect to the portal. This is what makes the OS raise its native
#     "Sign in to network" popup. Answering 204 here (what the previous listener did) tells the
#     OS the network is already open, so the popup never appears (Finding 4.2b).
#   * verified         -> the exact "success" body each OS expects, so the Wi-Fi is marked as
#     validated and keeps passing the OS's periodic re-checks (Scenario 3).
PROBE_SUCCESS_RESPONSES = {
    "generate_204": (204, ""),
    "gen_204": (204, ""),
    "hotspot-detect.html": (200, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    "library/test/success.html": (200, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    "connecttest.txt": (200, "Microsoft Connect Test"),
    "ncsi.txt": (200, "Microsoft NCSI"),
    "success.txt": (200, "success\n"),
    "canonical.html": (200, '<meta http-equiv="refresh" content="0;url=https://support.mozilla.org/kb/captive-portal"/>'),
}

# client IP -> expiry timestamp; populated by a successful check-in
VERIFIED_CLIENTS = {}


def is_client_verified(client_ip):
    expiry = VERIFIED_CLIENTS.get(client_ip)
    return expiry is not None and expiry > time.time()


def match_connectivity_probe(path_name):
    path = path_name.lower().strip("/")
    for suffix, answer in PROBE_SUCCESS_RESPONSES.items():
        if path == suffix or path.endswith("/" + suffix):
            return answer
    return None


def probe_response(path_name, client_ip, portal_url):
    """Response for a connectivity probe, or None if the path isn't one."""
    answer = match_connectivity_probe(path_name)
    if answer is None:
        return None
    if not is_client_verified(client_ip):
        return RedirectResponse(portal_url, status_code=302)
    status, body = answer
    if status == 204:
        return Response(status_code=204)
    return HTMLResponse(body, status_code=status)


def load_template(name):
    with open(os.path.join(TEMPLATES_DIR, name), encoding="utf-8") as f:
        return f.read().replace("{{LOCAL_IP}}", LOCAL_IP)


def ca_cert_response():
    ca_path = os.path.join(SSL_DIR, "ca.crt")
    if not os.path.exists(ca_path):
        return PlainTextResponse("Certificate not generated yet.", status_code=404)
    return FileResponse(ca_path, media_type="application/x-x509-ca-cert", filename="airgated-ca.crt")


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
# broken/self-signed TLS cert on the real (443) server can't interfere with detection. This
# listener answers those probes (see probe_response), serves the landing page shown inside the
# OS sign-in popup, and offers the classroom CA certificate for one-time install. The popup's
# embedded browser usually can't use the camera, so the landing page sends students to the
# HTTPS portal in their real browser.
def build_http_app():
    from fastapi import FastAPI as _FastAPI

    http_app = _FastAPI()
    landing_url = f"http://{LOCAL_IP}/welcome"

    @http_app.get("/welcome", response_class=HTMLResponse)
    async def landing_page():
        return HTMLResponse(load_template("landing.html"))

    @http_app.get("/airgated-ca.crt")
    async def http_ca_cert():
        return ca_cert_response()

    @http_app.api_route("/{path_name:path}", methods=["GET", "POST", "HEAD"])
    async def http_catch_all(path_name: str, request: Request):
        probe = probe_response(path_name, request.client.host, landing_url)
        if probe is not None:
            return probe
        return RedirectResponse(landing_url, status_code=302)

    return http_app


def run_http_redirect_server():
    async def _serve():
        import uvicorn
        config = uvicorn.Config(build_http_app(), host="0.0.0.0", port=HTTP_DETECT_PORT, log_level="warning")
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


def db_connect():
    return closing(sqlite3.connect(DB_PATH))


def _add_missing_columns(cursor, table, columns):
    existing = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}
    for name, decl in columns.items():
        if name not in existing:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def init_db():
    with db_connect() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS airgated_device_registry (
                roll_number TEXT PRIMARY KEY,
                name TEXT,
                public_key_hex TEXT,
                hardware_mac TEXT
            )
        """)
        _add_missing_columns(cursor, "airgated_device_registry", {
            "face_embedding": "BLOB",
            "enrolled_at": "REAL",
        })
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
        _add_missing_columns(cursor, "airgated_attendance_records", {
            "face_similarity": "REAL",
            "blinks_detected": "INTEGER",
            "evidence_file": "TEXT",
        })
        # Persistent record of every rejected or security-relevant event, reviewable at /admin.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS airgated_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                event TEXT,
                roll_number TEXT,
                network_ip TEXT,
                network_mac TEXT,
                detail TEXT
            )
        """)
        conn.commit()

init_db()


def audit(event, roll_number, client_ip, mac, detail):
    print(f"🚨 [Audit:{event}] Roll: {roll_number} | IP: {client_ip} | MAC: {mac} | {detail}")
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO airgated_audit_log (timestamp, event, roll_number, network_ip, network_mac, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), event, roll_number, client_ip, mac, detail),
        )
        conn.commit()


# --- SERVER-ISSUED SINGLE-USE CHALLENGES ---
# Every registration and check-in must sign a nonce the server just issued over the challenge
# WebSocket. The nonce is bound to the purpose, roll number and client IP, carries the RTT the
# server itself measured, expires after CHALLENGE_TTL_SECONDS, and is deleted on first use --
# so a captured signature can never be replayed (Section 5 of the progress report).
@dataclass
class Challenge:
    purpose: str
    roll_number: str
    client_ip: str
    rtt_ms: float
    blinks_required: int
    issued_at: float


CHALLENGES = {}


def issue_challenge(purpose, roll_number, client_ip, rtt_ms):
    now = time.time()
    for nonce in [n for n, c in CHALLENGES.items() if now - c.issued_at > CHALLENGE_TTL_SECONDS]:
        del CHALLENGES[nonce]
    nonce = secrets.token_hex(16)
    CHALLENGES[nonce] = Challenge(purpose, roll_number, client_ip, rtt_ms, random.choice(BLINK_CHOICES), now)
    return nonce, CHALLENGES[nonce]


def consume_challenge(nonce, purpose, roll_number, client_ip):
    """Pop the challenge (single use) and return (challenge, error_message)."""
    challenge = CHALLENGES.pop(nonce, None)
    if challenge is None:
        return None, "Challenge unknown or already used. Start again."
    if time.time() - challenge.issued_at > CHALLENGE_TTL_SECONDS:
        return None, "Challenge expired. Start again."
    if (challenge.purpose, challenge.roll_number, challenge.client_ip) != (purpose, roll_number, client_ip):
        return None, "Challenge was issued for a different request."
    return challenge, None


def signed_message(purpose, nonce, roll_number, frames):
    frames_hash = hashlib.sha256(b"".join(frames)).hexdigest()
    return f"airgated|{purpose}|{nonce}|{roll_number}|{frames_hash}".encode()


def signature_valid(public_key_hex, signature_hex, message):
    try:
        public_key = load_der_public_key(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


async def read_frames(frames):
    if not frames or len(frames) > MAX_FRAMES:
        return None, f"Expected between 1 and {MAX_FRAMES} camera frames."
    blobs = []
    for upload in frames:
        blob = await upload.read(MAX_FRAME_BYTES + 1)
        if len(blob) > MAX_FRAME_BYTES:
            return None, "Camera frame too large."
        blobs.append(blob)
    return blobs, None


async def analyze_face(frames):
    try:
        return await run_in_threadpool(face_verify.analyze, frames), None
    except RuntimeError as e:
        return None, f"Face verification unavailable on server: {e}"


def save_evidence(roll_number, jpeg):
    if not jpeg:
        return None
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    safe_roll = re.sub(r"[^A-Za-z0-9_-]", "_", roll_number)
    filename = f"{safe_roll}_{int(time.time())}.jpg"
    with open(os.path.join(EVIDENCE_DIR, filename), "wb") as f:
        f.write(jpeg)
    return filename


# --- MODULE 1 SECURE LAYOUT CAPTIVE PORTAL INTERFACE ---
@app.get("/generate-captive-window", response_class=HTMLResponse)
async def captive_portal_window():
    return HTMLResponse(content=load_template("portal.html"), status_code=200)


@app.get("/airgated-ca.crt")
async def https_ca_cert():
    return ca_cert_response()


def summarize_rtt(samples):
    """Return (gate_ms, median_ms) for a list of round-trip times.

    The gate uses the fastest round trip, not the median. Phones in Wi-Fi power-save only wake
    every beacon interval (~100 ms), so a few pings in any burst come back slow even at 1 m from
    the access point -- that is radio sleep, not distance. Sleep, congestion and retries can only
    ever make a ping slower, while a tunnel or relay cannot make its fastest ping quicker than
    its real path, so the minimum is the honest measure of "is this a direct local link".
    """
    return min(samples), statistics.median(samples)


# --- WEBSOCKET: SERVER-MEASURED PROXIMITY + CHALLENGE ISSUANCE ---
# The server times the ping/pong round trips itself, so the RTT used by the latency gate is never
# a number the client reports.
@app.websocket("/ws/challenge")
async def websocket_challenge_endpoint(websocket: WebSocket):
    await websocket.accept()
    purpose = websocket.query_params.get("purpose", "")
    roll_number = websocket.query_params.get("roll", "").strip()
    client_ip = websocket.client.host
    try:
        if purpose not in ("register", "checkin") or not roll_number:
            audit("bad_challenge_request", roll_number, client_ip, None, f"purpose={purpose!r}")
            await websocket.send_json({"type": "error", "reason": "Bad challenge request."})
            await websocket.close()
            return

        samples = []
        for i in range(RTT_WARMUP_PINGS + RTT_PING_COUNT):
            start = time.perf_counter()
            await websocket.send_json({"type": "ping"})
            await websocket.receive_json()
            if i >= RTT_WARMUP_PINGS:
                samples.append((time.perf_counter() - start) * 1000)
        rtt_ms, median_ms = summarize_rtt(samples)

        if purpose == "checkin" and rtt_ms > RTT_THRESHOLD_MS:
            audit("latency_gate", roll_number, client_ip, None, f"best RTT {rtt_ms:.1f}ms > {RTT_THRESHOLD_MS}ms (median {median_ms:.1f}ms)")
            await websocket.send_json({"type": "error", "reason": "Network latency too high. Connect directly to the classroom Wi-Fi."})
            await websocket.close()
            return

        nonce, challenge = issue_challenge(purpose, roll_number, client_ip, rtt_ms)
        await websocket.send_json({
            "type": "challenge",
            "nonce": nonce,
            "blinks_required": challenge.blinks_required,
            "capture_ms": CAPTURE_MS,
            "rtt_ms": rtt_ms,
            "expires_in": CHALLENGE_TTL_SECONDS,
        })
        await websocket.close()
    except WebSocketDisconnect:
        pass


# --- API ENDPOINT: KYC ENROLLMENT (device key + face) ---
@app.post("/api/register")
async def register_student(
    request: Request,
    roll_number: str = Form(...),
    name: str = Form(...),
    public_key: str = Form(...),
    nonce: str = Form(...),
    signature_hex: str = Form(...),
    frames: list[UploadFile] = File(...),
    old_signature_hex: str = Form(""),
):
    roll_number, name = roll_number.strip(), name.strip()
    client_ip = request.client.host
    hardware_mac = get_client_mac(client_ip)
    print(f"📥 [Register Request] Roll: {roll_number} | IP: {client_ip} | MAC: {hardware_mac}")

    challenge, error = consume_challenge(nonce, "register", roll_number, client_ip)
    if error:
        audit("register_bad_challenge", roll_number, client_ip, hardware_mac, error)
        return {"status": "error", "message": error}

    if hardware_mac == "unknown_mac" and client_ip not in LOOPBACK_HOSTS:
        audit("register_unknown_mac", roll_number, client_ip, hardware_mac, "no neighbour-table entry")
        return {"status": "error", "message": "Could not extract physical MAC signature. Reconnect to class network."}

    blobs, error = await read_frames(frames)
    if error:
        audit("register_bad_frames", roll_number, client_ip, hardware_mac, error)
        return {"status": "error", "message": error}

    # Proof of possession: the new key must have signed this nonce and these exact frames.
    if not signature_valid(public_key, signature_hex, signed_message("register", nonce, roll_number, blobs)):
        audit("register_bad_signature", roll_number, client_ip, hardware_mac, "signature did not verify against submitted key")
        return {"status": "error", "message": "Device key signature invalid."}

    analysis, error = await analyze_face(blobs)
    if error:
        audit("register_face_engine_error", roll_number, client_ip, hardware_mac, error)
        return {"status": "error", "message": error}
    failure = analysis.liveness_failure(challenge.blinks_required)
    if failure:
        audit("register_liveness_failed", roll_number, client_ip, hardware_mac, failure)
        return {"status": "error", "message": failure}

    with db_connect() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT roll_number FROM airgated_device_registry WHERE hardware_mac = ? AND roll_number != ?",
            (hardware_mac, roll_number),
        )
        other = cursor.fetchone()
        if other and hardware_mac != "unknown_mac":
            audit("register_device_taken", roll_number, client_ip, hardware_mac, f"device already enrolled as {other[0]}")
            return {"status": "error", "message": "This device is already enrolled to another roll number. Ask the instructor to reset it."}

        cursor.execute(
            "SELECT hardware_mac, face_embedding, public_key_hex FROM airgated_device_registry WHERE roll_number = ?",
            (roll_number,),
        )
        existing = cursor.fetchone()
        embedding = face_verify.embedding_to_bytes(analysis.embedding)

        if existing is None:
            cursor.execute(
                "INSERT INTO airgated_device_registry (roll_number, name, public_key_hex, hardware_mac, face_embedding, enrolled_at) VALUES (?, ?, ?, ?, ?, ?)",
                (roll_number, name, public_key, hardware_mac, embedding, time.time()),
            )
            conn.commit()
            print(f"✅ [Enrolled] Roll: {roll_number} | MAC: {hardware_mac}")
            return {"status": "success", "message": "Device and face enrolled successfully!"}

        registered_mac, enrolled_face, enrolled_key = existing
        if enrolled_face is not None:
            # Re-keying needs BOTH the currently enrolled key (a signature over this request's nonce
            # and frames) and the enrolled face. A lost phone or cleared browser has no old key and
            # goes through an in-person instructor reset instead.
            if not (old_signature_hex and signature_valid(
                    enrolled_key, old_signature_hex, signed_message("register", nonce, roll_number, blobs))):
                audit("reenroll_no_old_key", roll_number, client_ip, hardware_mac, "not signed by the enrolled key")
                return {"status": "error", "message": "This roll number is enrolled on another device or browser. Ask the instructor to reset it."}
            score = face_verify.similarity(face_verify.embedding_from_bytes(enrolled_face), analysis.embedding)
            if score < face_verify.MATCH_THRESHOLD:
                audit("reenroll_face_mismatch", roll_number, client_ip, hardware_mac, f"similarity {score:.3f}")
                return {"status": "error", "message": "Face does not match the student enrolled under this roll number."}
            cursor.execute(
                "UPDATE airgated_device_registry SET public_key_hex = ?, hardware_mac = ? WHERE roll_number = ?",
                (public_key, hardware_mac, roll_number),
            )
            conn.commit()
            audit("reenroll_device", roll_number, client_ip, hardware_mac, f"face match {score:.3f}; previous MAC {registered_mac}")
            return {"status": "success", "message": "Face matched. This device is now your enrolled device."}

        # Enrolled before face verification existed: only the original device may add a face.
        if registered_mac != hardware_mac and client_ip not in LOOPBACK_HOSTS:
            audit("legacy_upgrade_refused", roll_number, client_ip, hardware_mac, f"registered MAC {registered_mac}")
            return {"status": "error", "message": "Roll number already enrolled from another device. Ask the instructor to reset it."}
        cursor.execute(
            "UPDATE airgated_device_registry SET public_key_hex = ?, face_embedding = ?, enrolled_at = ? WHERE roll_number = ?",
            (public_key, embedding, time.time(), roll_number),
        )
        conn.commit()
        audit("legacy_face_added", roll_number, client_ip, hardware_mac, "face added to pre-existing enrollment")
        return {"status": "success", "message": "Face added to your existing enrollment."}


# --- VALIDATION ATTENDANCE ENGINE ENTRYPOINT ---
@app.post("/api/checkin")
async def verify_checkin(
    request: Request,
    roll_number: str = Form(...),
    nonce: str = Form(...),
    signature_hex: str = Form(...),
    frames: list[UploadFile] = File(...),
):
    roll_number = roll_number.strip()
    client_ip = request.client.host
    incoming_mac = get_client_mac(client_ip)
    print(f"📥 [Checkin Verification] Roll: {roll_number} | IP: {client_ip} | MAC: {incoming_mac}")

    def reject(event, detail, message, status="fraud"):
        audit(event, roll_number, client_ip, incoming_mac, detail)
        return {"status": status, "message": message}

    # Stage 1: single-use server challenge (also carries the server-measured RTT)
    challenge, error = consume_challenge(nonce, "checkin", roll_number, client_ip)
    if error:
        return reject("checkin_bad_challenge", error, error)
    if challenge.rtt_ms > RTT_THRESHOLD_MS:
        return reject("latency_gate", f"best RTT {challenge.rtt_ms:.1f}ms", "Network latency too high. Proxy/Tunnel detected.")

    # Stage 2: registry lookup
    with db_connect() as conn:
        row = conn.execute(
            "SELECT public_key_hex, hardware_mac, face_embedding FROM airgated_device_registry WHERE roll_number = ?",
            (roll_number,),
        ).fetchone()
    if not row:
        return reject("checkin_unregistered", "no registry entry", "Device missing registration in hardware registry.", status="error")
    public_key_hex, registered_mac, enrolled_face = row
    if enrolled_face is None:
        return reject("checkin_no_face", "enrolled before face verification", "Face not enrolled yet. Re-open enrollment on this device.", status="error")

    # Stage 3: link-layer binding. A changed MAC (e.g. the student forgot the Wi-Fi network, which
    # gives the phone a new per-network address) is not rejected outright: stages 4 and 5 still
    # run so the response can say exactly which checks did not match, and so a student whose key
    # and face both verify is offered re-registration instead of losing the day.
    mac_changed = (client_ip not in LOOPBACK_HOSTS and registered_mac != "unknown_mac"
                   and incoming_mac != registered_mac)
    problems = []   # (audit code, human-readable text) for every check that did not match
    if mac_changed:
        problems.append(("mac_mismatch", "Wi-Fi hardware (MAC) address differs from the one recorded at enrollment"))

    def refuse_with_all_problems():
        detail = f"registered {registered_mac}; failed: " + ", ".join(code for code, _ in problems)
        audit("mac_mismatch", roll_number, client_ip, incoming_mac, detail)
        lines = [f"{i}. {text}" for i, (_, text) in enumerate(problems, 1)]
        return {"status": "fraud", "message": "Check-in refused. Not matching: " + " ".join(lines)}

    # Stage 4: device key signed this nonce and these exact frames
    blobs, error = await read_frames(frames)
    if error:
        return reject("checkin_bad_frames", error, error, status="error")
    if not signature_valid(public_key_hex, signature_hex, signed_message("checkin", nonce, roll_number, blobs)):
        if not mac_changed:
            return reject("bad_signature", "signature did not verify", "Signature validation failed.")
        problems.append(("bad_signature", "Device key signature did not verify (not the enrolled browser/device)"))

    # Stage 5: face liveness (blinks) + identity match against the enrolled face
    analysis, error = await analyze_face(blobs)
    if error:
        if not mac_changed:
            return reject("face_engine_error", error, error, status="error")
        problems.append(("face_unreadable", error))
        return refuse_with_all_problems()
    face_score = None
    failure = analysis.liveness_failure(challenge.blinks_required)
    if failure:
        if not mac_changed:
            return reject("liveness_failed", failure, failure)
        problems.append(("liveness_failed", failure))
    else:
        face_score = face_verify.similarity(face_verify.embedding_from_bytes(enrolled_face), analysis.embedding)
        if face_score < face_verify.MATCH_THRESHOLD:
            if not mac_changed:
                return reject("face_mismatch", f"similarity {face_score:.3f}", "Face does not match the enrolled student.")
            problems.append(("face_mismatch", "Face does not match the enrolled student"))
    score = face_score

    if mac_changed:
        if len(problems) > 1:
            return refuse_with_all_problems()
        # Only the MAC differs: the enrolled key signed this check-in and the face matches.
        # Attendance is NOT marked; the student must re-register this device first.
        audit("mac_changed_verified", roll_number, client_ip, incoming_mac,
              f"registered {registered_mac}; key and face verified (face {score:.3f})")
        with db_connect() as conn:
            name_row = conn.execute("SELECT name FROM airgated_device_registry WHERE roll_number = ?",
                                    (roll_number,)).fetchone()
        return {
            "status": "reenroll",
            "message": "Your key and face match, but this phone's Wi-Fi hardware (MAC) address changed "
                       "(for example a different network name or a changed Wi-Fi address setting). Re-register this device to continue.",
            "roll_number": roll_number,
            "name": name_row[0] if name_row else "",
        }

    # Stage 6: one device, one profile per window
    with db_connect() as conn:
        cursor = conn.cursor()
        if incoming_mac != "unknown_mac":
            cursor.execute(
                "SELECT roll_number FROM airgated_attendance_records WHERE network_mac = ? AND timestamp > ? AND roll_number != ?",
                (incoming_mac, time.time() - MULTI_PROFILE_WINDOW_SECONDS, roll_number),
            )
            other_roll = cursor.fetchone()
            if other_roll:
                return reject("multi_profile", f"MAC already checked in as {other_roll[0]}", "Multiple profile check-in detected from single hardware block.")

        evidence = save_evidence(roll_number, analysis.best_frame_jpeg)
        cursor.execute(
            "INSERT INTO airgated_attendance_records (roll_number, timestamp, latency_ms, network_ip, network_mac, face_similarity, blinks_detected, evidence_file) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (roll_number, time.time(), challenge.rtt_ms, client_ip, incoming_mac, score, analysis.blinks, evidence),
        )
        conn.commit()

    VERIFIED_CLIENTS[client_ip] = time.time() + VERIFIED_CLIENT_SECONDS
    print(f"🎉 [Gateway Success] Roll: {roll_number} | face {score:.3f} | blinks {analysis.blinks} | RTT {challenge.rtt_ms:.1f}ms")
    return {"status": "success", "message": "Attendance marked. Face and device verified!"}


# --- ATTENDANCE DASHBOARD (read-only stats; only reachable from the host laptop itself) ---
CHECKIN_FAILURES = {
    "checkin_bad_challenge": "Expired or reused request",
    "latency_gate": "Latency too high (not on classroom Wi-Fi?)",
    "checkin_unregistered": "Roll number not enrolled",
    "checkin_no_face": "Face not enrolled yet",
    "mac_mismatch": "Different device (MAC mismatch)",
    "mac_changed_verified": "Wi-Fi address changed; key and face OK (asked to re-register)",
    "checkin_bad_frames": "Bad camera upload",
    "bad_signature": "Invalid device signature",
    "liveness_failed": "Liveness failed (blinks / face visibility)",
    "face_mismatch": "Face did not match enrolled student",
    "multi_profile": "One device used for several students",
    "face_engine_error": "Face engine unavailable",
}
ENROLLMENT_FAILURES = {
    "register_bad_challenge": "Expired or reused request",
    "register_bad_signature": "Invalid device signature",
    "register_liveness_failed": "Liveness failed (blinks / face visibility)",
    "register_device_taken": "Device already enrolled to another roll",
    "reenroll_face_mismatch": "Re-enrollment face did not match",
    "legacy_upgrade_refused": "Roll enrolled from another device",
    "reenroll_no_old_key": "Re-key attempted without the enrolled key",
    "register_unknown_mac": "MAC could not be resolved",
    "register_bad_frames": "Bad camera upload",
    "register_face_engine_error": "Face engine unavailable",
}
TREND_DAYS = 7


def _table(headers, rows, empty="Nothing to show."):
    if not rows:
        return f'<p class="empty">{html.escape(empty)}</p>'
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape('' if v is None else str(v))}</td>" for v in row) + "</tr>"
        for row in rows
    )
    return f"<table><tr>{head}</tr>{body}</table>"


def _bars(items, total):
    """Horizontal bar chart from (label, count) pairs, scaled against `total`."""
    if not items:
        return '<p class="empty">Nothing to show.</p>'
    rows = []
    for label, count in items:
        pct = 100 * count / total if total else 0
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{html.escape(label)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{pct:.1f}%"></span></span>'
            f'<span class="bar-value">{count}</span></div>'
        )
    return "".join(rows)


def _fmt_time(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else ""


def _day_bounds(day):
    start = datetime.datetime.combine(day, datetime.time.min).timestamp()
    return start, start + 86400


@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, date: str = ""):
    if request.client.host not in LOOPBACK_HOSTS:
        return HTMLResponse("<h2>Forbidden</h2>", status_code=403)
    try:
        day = datetime.date.fromisoformat(date) if date else datetime.date.today()
    except ValueError:
        day = datetime.date.today()
    start, end = _day_bounds(day)

    with db_connect() as conn:
        names = dict(conn.execute("SELECT roll_number, name FROM airgated_device_registry"))
        checkins = conn.execute(
            "SELECT roll_number, timestamp, latency_ms, face_similarity, blinks_detected FROM airgated_attendance_records "
            "WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp", (start, end)).fetchall()
        events = conn.execute(
            "SELECT timestamp, event, roll_number, detail FROM airgated_audit_log "
            "WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp DESC", (start, end)).fetchall()
        trend = []
        for offset in range(TREND_DAYS - 1, -1, -1):
            d = day - datetime.timedelta(days=offset)
            s, e = _day_bounds(d)
            count = conn.execute(
                "SELECT COUNT(DISTINCT roll_number) FROM airgated_attendance_records WHERE timestamp >= ? AND timestamp < ?",
                (s, e)).fetchone()[0]
            trend.append((d.strftime("%a %d %b"), count))

    # Present: first successful check-in per student.
    present = {}
    for roll, ts, rtt, sim, blinks in checkins:
        if roll not in present:
            present[roll] = [ts, rtt, sim, blinks, 0]
        present[roll][4] += 1

    checkin_fails = [e for e in events if e[1] in CHECKIN_FAILURES]
    enroll_fails = [e for e in events if e[1] in ENROLLMENT_FAILURES]
    failed_rolls = {roll for _, _, roll, _ in checkin_fails}
    never_succeeded = sorted(r for r in failed_rolls if r not in present)
    absent = sorted(r for r in names if r not in present)

    enrolled = len(names)
    rate = f"{100 * len(present) / enrolled:.0f}%" if enrolled else "–"
    stats = [
        ("Enrolled", enrolled), ("Present", len(present)), ("Absent", len(absent)),
        ("Attendance rate", rate), ("Failed check-ins", len(checkin_fails)),
        ("Failed, never marked", len(never_succeeded)),
    ]
    cards = "".join(
        f'<div class="card"><div class="num">{html.escape(str(v))}</div><div class="lbl">{html.escape(k)}</div></div>'
        for k, v in stats
    )

    reason_counts = {}
    for _, event, _, _ in checkin_fails:
        reason_counts[CHECKIN_FAILURES[event]] = reason_counts.get(CHECKIN_FAILURES[event], 0) + 1
    reasons = sorted(reason_counts.items(), key=lambda kv: -kv[1])

    present_rows = [
        (roll, names.get(roll, ""), _fmt_time(ts), f"{sim:.3f}" if sim is not None else "",
         blinks, f"{rtt:.1f}" if rtt is not None else "", n)
        for roll, (ts, rtt, sim, blinks, n) in sorted(present.items(), key=lambda kv: kv[1][0])
    ]
    attention_rows = []
    for roll in never_succeeded:
        attempts = [e for e in checkin_fails if e[2] == roll]
        attention_rows.append((roll, names.get(roll, "(not enrolled)"), len(attempts), CHECKIN_FAILURES[attempts[0][1]]))
    fail_rows = [
        (_fmt_time(ts), roll, names.get(roll, ""), CHECKIN_FAILURES[event], detail)
        for ts, event, roll, detail in checkin_fails
    ]
    enroll_rows = [
        (_fmt_time(ts), roll, ENROLLMENT_FAILURES[event], detail)
        for ts, event, roll, detail in enroll_fails
    ]
    # Successful re-keys are shown too: a hijacked roll number would appear here.
    rekey_rows = [(_fmt_time(ts), roll, detail) for ts, event, roll, detail in events if event == "reenroll_device"]

    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>AirGated - Attendance</title>
    <style>
      body{{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:24px;background:#fafafa;color:#222}}
      main{{max-width:1100px;margin:0 auto}}
      header{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}}
      h1{{margin:0;font-size:1.5em}} h2{{font-size:1.1em;margin:28px 0 10px}}
      .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}}
      .card{{background:#fff;border:1px solid #e4e4e7;border-radius:10px;padding:14px}}
      .num{{font-size:1.8em;font-weight:700}} .lbl{{color:#666;font-size:.85em}}
      .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:20px}}
      .panel{{background:#fff;border:1px solid #e4e4e7;border-radius:10px;padding:4px 16px 16px;overflow-x:auto}}
      table{{border-collapse:collapse;width:100%;font-size:.88em}}
      td,th{{border-bottom:1px solid #eee;padding:6px 8px;text-align:left}} th{{background:#f4f4f5}}
      .bar-row{{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:.88em}}
      .bar-label{{flex:0 0 45%}} .bar-track{{flex:1;background:#f1f1f3;border-radius:4px;height:12px}}
      .bar-fill{{display:block;height:12px;border-radius:4px;background:#7928ca}}
      .bar-value{{flex:0 0 2.5em;text-align:right;font-variant-numeric:tabular-nums}}
      .fail .bar-fill{{background:#dc2626}} .empty{{color:#888;font-size:.9em}}
    </style></head><body><main>
    <header><h1>Attendance · {html.escape(day.strftime("%A %d %B %Y"))}</h1>
      <form method="get" action="/admin"><input type="date" name="date" value="{day.isoformat()}"> <button>Show</button></form>
    </header>
    <div class="cards">{cards}</div>

    <div class="grid">
      <div class="panel"><h2>Why check-ins failed</h2><div class="fail">{_bars(reasons, len(checkin_fails))}</div></div>
      <div class="panel"><h2>Students present, last {TREND_DAYS} days</h2>{_bars(trend, enrolled or max((c for _, c in trend), default=0))}</div>
    </div>

    <h2>Needs attention: failed and never marked present ({len(attention_rows)})</h2>
    <div class="panel">{_table(["Roll", "Name", "Failed attempts", "First failure reason"], attention_rows, "No one is stuck.")}</div>

    <h2>Present ({len(present_rows)})</h2>
    <div class="panel">{_table(["Roll", "Name", "Checked in", "Face match", "Blinks", "RTT ms", "Check-ins"], present_rows, "No check-ins yet.")}</div>

    <h2>Absent ({len(absent)})</h2>
    <div class="panel">{_table(["Roll", "Name"], [(r, names[r]) for r in absent], "Everyone enrolled is present.")}</div>

    <h2>Failed check-in attempts ({len(fail_rows)})</h2>
    <div class="panel">{_table(["Time", "Roll", "Name", "Reason", "Detail"], fail_rows, "No failed attempts.")}</div>

    <h2>Failed enrollments ({len(enroll_rows)})</h2>
    <div class="panel">{_table(["Time", "Roll", "Reason", "Detail"], enroll_rows, "No failed enrollments.")}</div>

    <h2>Device re-keys ({len(rekey_rows)})</h2>
    <div class="panel">{_table(["Time", "Roll", "Detail"], rekey_rows, "No re-keys.")}</div>

    <h2>Reset a student's enrollment</h2>
    <div class="panel"><p class="empty">For a lost or replaced phone: this deletes the student's device key and
      enrolled face so they can enroll again from the new phone.</p>
      <form method="post" action="/admin/reset"><input name="roll_number" placeholder="Roll number" required>
      <button>Reset enrollment</button></form></div>
    </main></body></html>"""
    return HTMLResponse(page)


@app.post("/admin/reset")
async def admin_reset(request: Request, roll_number: str = Form(...)):
    if request.client.host not in LOOPBACK_HOSTS:
        return HTMLResponse("<h2>Forbidden</h2>", status_code=403)
    roll_number = roll_number.strip()
    with db_connect() as conn:
        conn.execute("DELETE FROM airgated_device_registry WHERE roll_number = ?", (roll_number,))
        conn.commit()
    audit("instructor_reset", roll_number, request.client.host, None, "enrollment deleted by instructor (lost/new phone)")
    return RedirectResponse("/admin", status_code=303)


# --- MODULE 1 CATCH-ALL ROUTE INTERCEPTOR MIDDLEWARE (HARDENED) ---
# MUST be the last HTTP route registered. Starlette/FastAPI match routes in registration
# order and this pattern (/{path_name:path}) matches literally any path, so if it were
# registered before the real endpoints above, it would intercept every request meant for
# them first -- a bare `return` from a matched route does not "fall through" to the next
# route in Starlette, it just sends `null` (Finding 4.2). Real endpoints never reach here, so
# there is deliberately no exempt-path list: anything unmatched is either a connectivity
# probe or gets redirected to the portal.
@app.api_route("/{path_name:path}", methods=["GET", "POST", "HEAD"])
async def intercept_all_traffic(path_name: str, request: Request):
    portal_url = f"https://{LOCAL_IP}/generate-captive-window"
    probe = probe_response(path_name, request.client.host, portal_url)
    if probe is not None:
        return probe
    if path_name == "favicon.ico":
        return Response(status_code=404)

    print(f"🪤 [Captive Trap] Intercepted user resource fetch: /{path_name} -> Forcing Secure HTTPS Redirect.")
    return RedirectResponse(portal_url, status_code=302)


if __name__ == "__main__":
    import uvicorn
    from certs import ensure_certs

    cert_path, key_path, ca_path, reused = ensure_certs(SSL_DIR, LOCAL_IP)
    if reused:
        print(f"\n🔒 [Security Engine] Reusing persisted certificate {cert_path}")
    else:
        print(f"\n🔒 [Security Engine] Issued new certificate {cert_path} (signed by {ca_path})")
    print(f"   Students can install the classroom CA once from http://{LOCAL_IP}/airgated-ca.crt")

    try:
        face_verify._get_models()
        print("🙂 [Face Engine] Liveness + face-match models loaded (offline).")
    except RuntimeError as e:
        print(f"❌ [Face Engine] {e}")

    dns_thread = threading.Thread(target=run_dns_spoofer, daemon=True)
    dns_thread.start()

    http_detect_thread = threading.Thread(target=run_http_redirect_server, daemon=True)
    http_detect_thread.start()

    print(f"🚀 Launching Secure FastAPI Web Server on HTTPS://{LOCAL_IP}:{WEB_PORT}")
    print(f"📊 Attendance dashboard: https://localhost/admin (only from this laptop)")

    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=WEB_PORT,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
        reload=False
    )
