#!/usr/bin/env python3
"""AirGated check-in load test (CPU / server side only).

Starts a private copy of the server on 127.0.0.1 with a throw-away database, enrolls N fake students
directly in that database, then makes them all check in with the same flow a phone uses:

    WebSocket challenge (answer the server's pings)  ->  wait for the blink clip  ->  signed POST /api/checkin

and reports, per load level, how long the face analysis takes when many check-ins overlap and how
often the server's own latency gate (20 ms) would reject people because the server is busy.

What it can and cannot tell you
  * Measures: face-analysis time under contention, queueing, event-loop delay as seen by the RTT gate,
    and check-ins per minute the laptop can finish.
  * Does not measure: Wi-Fi airtime, the access point's station limit, or phone power-save. Over
    loopback the RTT is ~0, so any RTT you see here is delay caused by the server being busy. On the
    real network add the radio's share on top (use monitor_hotspot.py with real phones for that).
  * The fake students submit a still photo, so liveness fails (0 blinks) AFTER the full face analysis
    has run. That is the expensive part, so the timing is realistic; "liveness failed" is the expected
    outcome here, not an error. No attendance is recorded and your real database is never opened.

    .venv/bin/python loadtest_checkin.py                      # levels 1,5,10,20
    .venv/bin/python loadtest_checkin.py -n 10,30,60 --spread 5 --capture-secs 0
    .venv/bin/python loadtest_checkin.py --image some_face.jpg

--image defaults to the first JPEG in evidence/ (a real face is needed for realistic cost; without
one the detector finds nothing and the test is far too optimistic). It is read locally and is never
sent anywhere except to the loopback server.
"""
import argparse
import asyncio
import glob
import hashlib
import json
import os
import random
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter

import httpx
import numpy as np
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRAME_INTERVAL_S = 0.08   # matches the portal: ~12 fps
RTT_GATE_MS = 20.0        # server.RTT_THRESHOLD_MS


def pct(values, q):
    if not values:
        return float("nan")
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[min(98, max(0, int(q) - 1))]


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(db_path, port):
    env = dict(os.environ, AIRGATED_DB=db_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", str(port),
         "--log-level", "warning"],
        cwd=BASE_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc.poll() is not None:
            sys.exit("Test server exited during startup")
        try:
            if httpx.get(f"http://127.0.0.1:{port}/airgated-ca.crt", timeout=1).status_code in (200, 404):
                return proc
        except httpx.HTTPError:
            time.sleep(0.3)
    proc.terminate()
    sys.exit("Test server did not start in time")


def seed_students(db_path, count, public_hex):
    emb = np.random.default_rng(0).standard_normal(128).astype(np.float32)
    emb = (emb / np.linalg.norm(emb)).tobytes()
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO airgated_device_registry (roll_number, name, public_key_hex, hardware_mac, face_embedding, enrolled_at) "
            "VALUES (?, ?, ?, 'unknown_mac', ?, ?)",
            [(f"LT{i:04d}", f"Load Test {i}", public_hex, emb, time.time()) for i in range(count)],
        )


async def one_student(client, port, key, roll, frames, capture_s, start_delay):
    """Return a dict describing what happened to this fake student."""
    await asyncio.sleep(start_delay)
    t0 = time.perf_counter()
    result = {"roll": roll, "outcome": None, "rtt_ms": None, "ws_ms": None, "post_ms": None, "msg": ""}
    try:
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws/challenge?purpose=checkin&roll={roll}") as ws:
            challenge = None
            async for raw in ws:
                msg = json.loads(raw)
                if msg["type"] == "ping":
                    await ws.send(json.dumps({"type": "pong"}))
                elif msg["type"] == "challenge":
                    challenge = msg
                elif msg["type"] == "error":
                    result.update(outcome="latency_gate", msg=msg.get("reason", ""))
        result["ws_ms"] = (time.perf_counter() - t0) * 1000
        if challenge is None:
            result["outcome"] = result["outcome"] or "no_challenge"
            return result
        result["rtt_ms"] = challenge["rtt_ms"]

        await asyncio.sleep(capture_s)   # the student is blinking at the camera
        digest = hashlib.sha256(b"".join(frames)).hexdigest()
        message = f"airgated|checkin|{challenge['nonce']}|{roll}|{digest}".encode()
        sig = key.sign(message, padding.PKCS1v15(), hashes.SHA256()).hex()
        files = [("frames", (f"f{i}.jpg", blob, "image/jpeg")) for i, blob in enumerate(frames)]
        t1 = time.perf_counter()
        resp = await client.post(f"http://127.0.0.1:{port}/api/checkin",
                                 data={"roll_number": roll, "nonce": challenge["nonce"], "signature_hex": sig},
                                 files=files)
        result["post_ms"] = (time.perf_counter() - t1) * 1000
        body = resp.json()
        result["msg"] = body.get("message", "")
        result["outcome"] = "analysed" if resp.status_code == 200 else f"http_{resp.status_code}"
    except Exception as e:   # timeouts, resets: these are the failures worth seeing
        result["outcome"] = f"exception:{type(e).__name__}"
        result["msg"] = str(e)[:80]
    return result


async def run_level(port, key, n, frames, capture_s, spread_s):
    limits = httpx.Limits(max_connections=n + 5)
    async with httpx.AsyncClient(timeout=600, limits=limits) as client:
        t0 = time.perf_counter()
        delays = sorted(random.uniform(0, spread_s) for _ in range(n))
        results = await asyncio.gather(*[
            one_student(client, port, key, f"LT{i:04d}", frames, capture_s, delays[i]) for i in range(n)
        ])
        wall = time.perf_counter() - t0
    return results, wall


def report(n, results, wall):
    rtts = [r["rtt_ms"] for r in results if r["rtt_ms"] is not None]
    posts = [r["post_ms"] / 1000 for r in results if r["post_ms"] is not None]
    outcomes = Counter(r["outcome"] for r in results)
    gate = outcomes.get("latency_gate", 0)
    over = sum(1 for v in rtts if v > RTT_GATE_MS)
    bad = {k: v for k, v in outcomes.items() if k not in ("analysed", "latency_gate")}
    print(f"\n=== {n} students (wall {wall:.1f}s) ===")
    print(f"  finished analysis       : {outcomes.get('analysed', 0)}/{n}")
    print(f"  latency-gate rejections : {gate}/{n}   (issued challenges with RTT > {RTT_GATE_MS:g} ms: {over})")
    if rtts:
        print(f"  server-measured RTT ms  : p50 {pct(rtts, 50):.1f}  p95 {pct(rtts, 95):.1f}  max {max(rtts):.1f}")
    if posts:
        print(f"  check-in response time  : p50 {pct(posts, 50):.1f}s  p95 {pct(posts, 95):.1f}s  max {max(posts):.1f}s")
        print(f"  throughput              : {len(posts) / wall * 60:.1f} check-ins/min")
    if bad:
        print(f"  UNEXPECTED outcomes     : {bad}")
    msgs = Counter(r["msg"][:60] for r in results if r["outcome"] == "analysed")
    if msgs:
        print(f"  replies                 : {dict(msgs)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-n", "--students", default="1,5,10,20", help="comma-separated load levels")
    ap.add_argument("--spread", type=float, default=10.0, help="seconds over which students start (0 = all at once)")
    ap.add_argument("--capture-secs", type=float, default=5.0, help="simulated blink-clip time between challenge and upload")
    ap.add_argument("--frames", type=int, default=62, help="frames per clip (portal sends ~5 s at 12 fps)")
    ap.add_argument("--image", help="JPEG of a face (default: first JPEG in evidence/)")
    args = ap.parse_args()

    image = args.image or next(iter(sorted(glob.glob(os.path.join(BASE_DIR, "evidence", "*.jpg")))), None)
    if image and os.path.exists(image):
        blob = open(image, "rb").read()
        print(f"Frame source: {os.path.basename(image)} ({len(blob) // 1024} KB) x {args.frames} frames")
    else:
        import cv2
        blob = cv2.imencode(".jpg", np.random.default_rng(1).integers(0, 255, (240, 320, 3), dtype=np.uint8))[1].tobytes()
        print("WARNING: no face image found; using noise. Detection cost is far lower than real, so "
              "results are optimistic. Pass --image with a face photo.")
    frames = [blob] * args.frames
    levels = [int(x) for x in args.students.split(",")]

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_hex = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()

    tmp = tempfile.mkdtemp(prefix="airgated-load-")
    db_path, port = os.path.join(tmp, "load.db"), free_port()
    proc = start_server(db_path, port)
    try:
        seed_students(db_path, max(levels), public_hex)
        print(f"Private test server on 127.0.0.1:{port}, scratch DB {db_path}")
        print("Warm-up (loads the face models, not counted)...")
        asyncio.run(run_level(port, key, 1, frames, 0, 0))

        print("Baseline: one check-in with nothing else running...")
        base, _ = asyncio.run(run_level(port, key, 1, frames, 0, 0))
        t = base[0]["post_ms"]
        if t:
            print(f"  analysis takes {t / 1000:.2f}s. The face engine runs one clip at a time, so even a "
                  f"perfect queue finishes at most {60 / (t / 1000):.0f} check-ins per minute.")
        for n in levels:
            results, wall = asyncio.run(run_level(port, key, n, frames, args.capture_secs, args.spread))
            report(n, results, wall)
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
