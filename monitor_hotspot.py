#!/usr/bin/env python3
"""AirGated hotspot monitor (Linux).

Run it in a second terminal while the hotspot and server are up and students join. Every interval it
records, to the screen and a CSV:

  stations   devices associated to the access point right now (iw station dump)
  leases     DHCP leases handed out (dnsmasq lease file)
  ping_*     ICMP round trip to every leased IP (min / avg / max, ms) and how many answered
  checkins   successful check-ins in this interval, with avg/max server-measured RTT (database)
  lat_fail   `latency_gate` rejections in this interval (the 20 ms gate)

It also prints an event line whenever a station joins or leaves, so the station count at which new
phones stop connecting is visible. Read-only: it never touches the hotspot, firewall or database.

    ./monitor_hotspot.py                 # every 5 s, CSV in hotspot_monitor.csv
    ./monitor_hotspot.py -i 2 -o run1.csv
Environment: AIRGATED_WIFI_IF (auto), AIRGATED_DB (database.db next to this file).
"""
import argparse
import csv
import os
import re
import sqlite3
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("AIRGATED_DB", os.path.join(BASE_DIR, "database.db"))
LEASES = "/run/airgated/dnsmasq.leases"
FIELDS = ["time", "stations", "leases", "ping_ok", "ping_min_ms", "ping_avg_ms", "ping_max_ms",
          "checkins", "checkin_rtt_avg_ms", "checkin_rtt_max_ms", "lat_fail"]


def run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def wifi_if():
    if os.environ.get("AIRGATED_WIFI_IF"):
        return os.environ["AIRGATED_WIFI_IF"]
    m = re.search(r"Interface (\S+)", run(["iw", "dev"]))
    return m.group(1) if m else None


def is_ap(iface):
    return re.search(r"type AP\b", run(["iw", "dev", iface, "info"])) is not None


def parse_stations(text):
    """MACs from `iw dev X station dump` output."""
    return set(m.lower() for m in re.findall(r"^Station ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", text, re.M | re.I))


def parse_leases(text):
    """{ip: mac} from a dnsmasq lease file (expiry mac ip hostname clientid)."""
    out = {}
    for line in text.splitlines():
        cols = line.split()
        if len(cols) >= 3:
            out[cols[2]] = cols[1].lower()
    return out


def ping_ms(ip):
    m = re.search(r"time=([\d.]+) ms", run(["ping", "-c", "1", "-W", "1", ip], timeout=3))
    return float(m.group(1)) if m else None


def db_stats(since):
    try:
        with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2) as c:
            rtts = [r[0] for r in c.execute(
                "SELECT latency_ms FROM airgated_attendance_records WHERE timestamp >= ?", (since,))]
            lat_fail = c.execute(
                "SELECT COUNT(*) FROM airgated_audit_log WHERE event = 'latency_gate' AND timestamp >= ?",
                (since,)).fetchone()[0]
        return rtts, lat_fail
    except sqlite3.Error:
        return [], 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-i", "--interval", type=float, default=5.0, help="seconds between samples")
    ap.add_argument("-o", "--output", default="hotspot_monitor.csv", help="CSV file (appended)")
    args = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    iface = wifi_if()
    if not iface:
        sys.exit("No Wi-Fi interface found (is `iw` installed?)")
    print(f"Monitoring {iface}; sampling every {args.interval:g}s; CSV: {args.output}; Ctrl+C to stop")
    if not is_ap(iface):
        print(f"  note: {iface} is not in AP mode yet; waiting for `hotspot_linux.sh up`...")

    new_file = not os.path.exists(args.output)
    out = open(args.output, "a", newline="")
    writer = csv.DictWriter(out, fieldnames=FIELDS)
    if new_file:
        writer.writeheader()

    known, peak, last = set(), 0, time.time()
    pool = ThreadPoolExecutor(max_workers=32)
    try:
        while True:
            now = time.time()
            ap_mode = is_ap(iface)
            stations = parse_stations(run(["iw", "dev", iface, "station", "dump"])) if ap_mode else set()
            for mac in sorted(stations - known):
                print(f"  + joined  {mac}   (now {len(stations)})")
            for mac in sorted(known - stations):
                print(f"  - left    {mac}   (now {len(stations)})")
            known = stations
            peak = max(peak, len(stations))

            try:
                with open(LEASES) as f:
                    leases = parse_leases(f.read())
            except OSError:
                leases = {}
            # Ping only leased devices that are currently associated.
            targets = [ip for ip, mac in leases.items() if mac in stations]
            pings = [p for p in pool.map(ping_ms, targets) if p is not None]

            rtts, lat_fail = db_stats(last)
            row = {
                "time": time.strftime("%H:%M:%S", time.localtime(now)),
                "stations": len(stations),
                "leases": len(leases),
                "ping_ok": f"{len(pings)}/{len(targets)}",
                "ping_min_ms": f"{min(pings):.1f}" if pings else "",
                "ping_avg_ms": f"{statistics.mean(pings):.1f}" if pings else "",
                "ping_max_ms": f"{max(pings):.1f}" if pings else "",
                "checkins": len(rtts),
                "checkin_rtt_avg_ms": f"{statistics.mean(rtts):.1f}" if rtts else "",
                "checkin_rtt_max_ms": f"{max(rtts):.1f}" if rtts else "",
                "lat_fail": lat_fail,
            }
            writer.writerow(row)
            out.flush()
            print(f"{row['time']}  stations={row['stations']:<3} (peak {peak})  leases={row['leases']:<3} "
                  f"ping {row['ping_ok']} min/avg/max {row['ping_min_ms'] or '-'}/{row['ping_avg_ms'] or '-'}/"
                  f"{row['ping_max_ms'] or '-'} ms  check-ins={row['checkins']} "
                  f"rtt avg/max {row['checkin_rtt_avg_ms'] or '-'}/{row['checkin_rtt_max_ms'] or '-'} ms  "
                  f"latency-gate fails={lat_fail}")
            last = now
            time.sleep(max(0.0, args.interval - (time.time() - now)))
    except KeyboardInterrupt:
        print(f"\nStopped. Peak simultaneous stations: {peak}. Data in {args.output}")
    finally:
        out.close()
        pool.shutdown(wait=False)


if __name__ == "__main__":
    main()
