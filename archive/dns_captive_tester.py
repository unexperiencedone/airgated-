import socket
import threading
import time
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse
from dnslib import DNSRecord, A, RR

app = FastAPI()

LOCAL_IP = "192.168.137.1"  # Matches localhost loopback testing interface
DNS_PORT = 53
WEB_PORT = 80

# --- PART A: ROBUST, BULLETPROOF DNS SPOOFER ---
def run_dns_spoofer():
    """
    Listens on UDP Port 53 and responds to EVERY domain request.
    Handles WinError 10054 gracefully to prevent loop crashes.
    """
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udps.bind(('0.0.0.0', DNS_PORT))
        print(f"📡 [DNS Spoofer] Active. Intercepting traffic on port {DNS_PORT}...")
    except PermissionError:
        print("❌ Permission Error: Run VS Code/Terminal as ADMINISTRATOR.")
        return
    except Exception as e:
        print(f"❌ DNS Server failed to start: {e}")
        return

    while True:
        try:
            # Wrap the actual networking handshake in an inner try-except block
            try:
                data, addr = udps.recvfrom(1024)
                request = DNSRecord.parse(data)
                reply = request.reply()
                qname = request.q.qname
                
                # Point everything explicitly to our local web server machine
                reply.add_answer(RR(qname, rdata=A(LOCAL_IP), ttl=60))
                udps.sendto(reply.pack(), addr)
                print(f"🎯 [DNS Spoofer] Intercepted request for: '{qname}' -> Rerouted to {LOCAL_IP}")
            
            except socket.error as e:
                # Catch Windows WinError 10054 ICMP resets safely without quitting the loop
                if getattr(e, 'winerror', None) == 10054 or (hasattr(e, 'errno') and e.errno == 10054):
                    continue
                print(f"⚠️ Recoverable Socket Connection Warning: {e}")
                continue
                
        except Exception as e:
            print(f"❌ Critical DNS Core Loop Failure: {e}")
            break


# --- PART B: CATCH-ALL CAPTIVE REDIRECTION ENGINE ---

@app.get("/generate-captive-window", response_class=HTMLResponse)
async def captive_portal_window():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AirGated - Verification Portal</title>
        <style>
            body { font-family: system-ui, sans-serif; margin: 2em; background: #fafafa; text-align: center; }
            .card { max-width: 400px; background: white; padding: 2.5em; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); margin: 4em auto; border-top: 4px solid #00cc66; }
            h2 { color: #111; margin-top: 0; }
            p { color: #666; font-size: 0.95em; line-height: 1.5; }
            .success-badge { padding: 10px; background: #eefdf5; color: #155724; border-radius: 6px; font-weight: 600; font-size: 0.9em; margin: 15px 0; display: block; }
            .success-btn { background: #00cc66; color: white; padding: 12px 24px; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 1em; width: 100%; transition: background 0.2s; }
            .success-btn:hover { background: #00b359; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>AirGated Gateway Active</h2>
            <p>Your connection has successfully triggered the network-layer Captive Framework loop.</p>
            <div class="success-badge">
                🔒 Secure Context Emulation Verified
            </div>
            <button class="success-btn" onclick="alert('Module 1 is 100% operational!')">Proceed to Authentication</button>
        </div>
    </body>
    </html>
    """

@app.api_route("/{path_name:path}", methods=["GET", "POST"])
async def intercept_all_traffic(path_name: str, response: Response):
    if path_name in ["generate-captive-window", "favicon.ico"]:
        return

    print(f"🪤 [Captive Trap] Intercepted HTTP resource fetch for: /{path_name}")
    response.headers["Location"] = f"http://{LOCAL_IP}:{WEB_PORT}/generate-captive-window"
    response.status_code = 302
    return {"message": "Executing Captive Framework Redirect Protocol"}


if __name__ == "__main__":
    # Spin up the crash-resistant DNS thread
    dns_thread = threading.Thread(target=run_dns_spoofer, daemon=True)
    dns_thread.start()

    import uvicorn
    print(f"🚀 Launching FastAPI Web Server on http://{LOCAL_IP}:{WEB_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT)