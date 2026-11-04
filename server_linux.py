"""Linux launcher for AirGated.

server.py is the Windows-tailored entry point and is left untouched. This script imports it and
keeps every route, verification gate, face/blink check and DB behaviour exactly as-is, replacing
only the pieces that are OS-specific:

  * MAC lookup      -> reads /proc/net/arp (falls back to `ip neigh`); `arp` is not installed on
                       Ubuntu by default, and without it the device/MAC gates would all fail.
  * DNS spoofer     -> tries 0.0.0.0:53 first (same as Windows); if systemd-resolved already owns
                       53 on 127.0.0.53, falls back to binding only the hotspot address.
  * Startup checks  -> reports privileged-port access, whether LOCAL_IP exists on an interface,
                       and who holds ports 53/80/443, instead of Windows-ICS advice.

Run (ports 53/80/443 are privileged, so use the venv's python under sudo):

    sudo .venv/bin/python server_linux.py

Environment: AIRGATED_LOCAL_IP (default 192.168.137.1), AIRGATED_DB, AIRGATED_SKIP_PREFLIGHT=1.
"""
import errno
import os
import re
import socket
import subprocess
import sys
import threading

if not sys.platform.startswith("linux"):
    sys.exit("server_linux.py is for Linux. Use server.py on Windows.")

import server  # noqa: E402  (module-level code only defines things; the app starts below)

MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.I)
ZERO_MAC = "00:00:00:00:00:00"


# --- MAC RESOLVER (Linux) ---
def get_client_mac_linux(client_ip: str) -> str:
    """IP -> MAC from the kernel neighbour table. Returns 'unknown_mac' if unresolved,
    which the existing gates in server.py already handle."""
    try:
        with open("/proc/net/arp") as f:
            next(f, None)  # header
            for line in f:
                cols = line.split()
                # IP, HW type, Flags, HW address, Mask, Device
                if len(cols) >= 6 and cols[0] == client_ip and int(cols[2], 16) & 0x2:
                    mac = cols[3].lower()
                    if MAC_RE.fullmatch(mac) and mac != ZERO_MAC:
                        return mac
    except Exception as e:
        print(f"Failed to read /proc/net/arp: {e}")
    try:
        out = subprocess.check_output(["ip", "neigh", "show", client_ip],
                                      stderr=subprocess.DEVNULL, timeout=3).decode(errors="ignore")
        m = re.search(r"lladdr\s+(" + MAC_RE.pattern + ")", out, re.I)
        if m and m.group(1).lower() != ZERO_MAC:
            return m.group(1).lower()
    except Exception as e:
        print(f"Failed to fetch MAC via ip neigh: {e}")
    return "unknown_mac"


# --- DNS SPOOFER (Linux) ---
def run_dns_spoofer_linux():
    from dnslib import DNSRecord, A, RR

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bound = None
    last_err = None
    for host in ("0.0.0.0", server.LOCAL_IP):
        try:
            udps.bind((host, server.DNS_PORT))
            bound = host
            break
        except OSError as e:
            last_err = e
    if bound is None:
        print(f"❌ DNS Server failed to start on port {server.DNS_PORT}: {last_err}")
        if last_err and last_err.errno == errno.EACCES:
            print("   Port 53 is privileged: run with sudo .venv/bin/python server_linux.py")
        elif last_err and last_err.errno == errno.EADDRNOTAVAIL:
            print(f"   {server.LOCAL_IP} is not assigned to any interface yet -- bring the hotspot up first.")
        else:
            print("   Something already owns port 53 (see the preflight report above).")
        return
    print(f"📡 [DNS Spoofer] Active on {bound}:{server.DNS_PORT}. "
          f"Answering every name with {server.LOCAL_IP}...")

    while True:
        try:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)
            reply = request.reply()
            reply.add_answer(RR(request.q.qname, rdata=A(server.LOCAL_IP), ttl=60))
            udps.sendto(reply.pack(), addr)
        except socket.error:
            continue
        except Exception:
            break


# --- PREFLIGHT ---
def _port_holders(proto: str, port: int) -> str:
    try:
        out = subprocess.check_output(["ss", f"-l{proto}np", f"sport = :{port}"],
                                      stderr=subprocess.DEVNULL, timeout=3).decode(errors="ignore")
        rows = [l.split(None, 5) for l in out.splitlines()[1:] if l.strip()]
        return "; ".join(f"{r[3]} {r[5] if len(r) > 5 else ''}".strip() for r in rows)
    except Exception:
        return ""


def _local_ip_present() -> bool:
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr"], timeout=3).decode(errors="ignore")
        return re.search(rf"\binet {re.escape(server.LOCAL_IP)}/", out) is not None
    except Exception:
        return True  # can't tell; don't block


def preflight() -> None:
    print("🔎 [Preflight] Linux environment")
    privileged = os.geteuid() == 0
    try:
        with open("/proc/sys/net/ipv4/ip_unprivileged_port_start") as f:
            floor = int(f.read().strip())
    except Exception:
        floor = 1024
    need = min(server.DNS_PORT, server.HTTP_DETECT_PORT, server.WEB_PORT)
    if not privileged and need < floor:
        print(f"   ⚠ Not root and ports below {floor} are privileged. Run:")
        print("       sudo .venv/bin/python server_linux.py")
        print(f"     (or: sudo sysctl net.ipv4.ip_unprivileged_port_start={need})")
    if not _local_ip_present():
        print(f"   ⚠ {server.LOCAL_IP} is not on any interface. Bring up the hotspot/AP with that "
              f"address, or set AIRGATED_LOCAL_IP to the laptop's address on it.")
    for proto, port, label in (("u", server.DNS_PORT, "DNS"), ("t", server.HTTP_DETECT_PORT, "HTTP"),
                               ("t", server.WEB_PORT, "HTTPS")):
        holders = _port_holders(proto, port)
        if holders:
            print(f"   ⚠ Port {port} ({label}) already in use: {holders}")
    if not os.path.exists("/proc/net/arp"):
        print("   ⚠ /proc/net/arp missing; MAC gate will rely on `ip neigh`.")


def main() -> None:
    import uvicorn
    from certs import ensure_certs

    if os.environ.get("AIRGATED_SKIP_PREFLIGHT") != "1":
        preflight()

    # Swap in the Linux implementations; server.py looks these up as module globals at call time.
    server.get_client_mac = get_client_mac_linux
    server.run_dns_spoofer = run_dns_spoofer_linux

    cert_path, key_path, ca_path, reused = ensure_certs(server.SSL_DIR, server.LOCAL_IP)
    if reused:
        print(f"\n🔒 [Security Engine] Reusing persisted certificate {cert_path}")
    else:
        print(f"\n🔒 [Security Engine] Issued new certificate {cert_path} (signed by {ca_path})")
    print(f"   Students can install the classroom CA once from http://{server.LOCAL_IP}/airgated-ca.crt")

    try:
        server.face_verify._get_models()
        print("🙂 [Face Engine] Liveness + face-match models loaded (offline).")
    except RuntimeError as e:
        print(f"❌ [Face Engine] {e}")

    threading.Thread(target=server.run_dns_spoofer, daemon=True).start()
    threading.Thread(target=server.run_http_redirect_server, daemon=True).start()

    print(f"🚀 Launching Secure FastAPI Web Server on HTTPS://{server.LOCAL_IP}:{server.WEB_PORT}")
    print("📊 Attendance dashboard: https://localhost/admin (only from this laptop)")

    uvicorn.run(server.app, host="0.0.0.0", port=server.WEB_PORT,
                ssl_certfile=cert_path, ssl_keyfile=key_path, reload=False)


if __name__ == "__main__":
    main()
