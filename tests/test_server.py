"""End-to-end tests for the enrollment and check-in pipeline.

Face analysis is stubbed (the real models are covered in test_face_verify.py) so these tests
exercise the security logic: challenges, replay, signatures, MAC binding, face-match decisions,
the multi-profile window, the audit log, route ordering and captive-portal probe answers.
"""
import hashlib
import os
import sqlite3
import sys
import tempfile

import numpy as np
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_db_dir = tempfile.mkdtemp()
os.environ["AIRGATED_DB"] = os.path.join(_db_dir, "test.db")

import face_verify  # noqa: E402
import server  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

REAL_RTT_THRESHOLD_MS = server.RTT_THRESHOLD_MS  # captured before fixtures relax it
FRAMES = [b"frame-%d" % i for i in range(6)]
STUDENT_FACE = face_verify._normalize(np.eye(128, dtype=np.float32)[0])
OTHER_FACE = face_verify._normalize(np.eye(128, dtype=np.float32)[1])


def fake_analysis(embedding=STUDENT_FACE, blinks=3):
    return face_verify.FaceAnalysis(
        frames_total=len(FRAMES), frames_with_face=len(FRAMES), blinks=blinks,
        embedding=embedding, best_frame_jpeg=None,
    )


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    with sqlite3.connect(os.environ["AIRGATED_DB"]) as conn:
        for table in ("airgated_device_registry", "airgated_attendance_records", "airgated_audit_log"):
            conn.execute(f"DELETE FROM {table}")
    server.CHALLENGES.clear()
    server.VERIFIED_CLIENTS.clear()
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:01")
    monkeypatch.setattr(server.random, "choice", lambda seq: 2)
    # In-process WebSocket timing is noisy on a loaded machine; the gate itself is tested separately.
    monkeypatch.setattr(server, "RTT_THRESHOLD_MS", 10_000.0)
    monkeypatch.setattr(server.face_verify, "analyze", lambda frames: fake_analysis())
    yield


@pytest.fixture
def client():
    return TestClient(server.app)


class Device:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_hex = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()

    def sign(self, purpose, nonce, roll, frames=FRAMES):
        frames_hash = hashlib.sha256(b"".join(frames)).hexdigest()
        message = f"airgated|{purpose}|{nonce}|{roll}|{frames_hash}".encode()
        return self.key.sign(message, padding.PKCS1v15(), hashes.SHA256()).hex()


def get_challenge(client, purpose, roll):
    with client.websocket_connect(f"/ws/challenge?purpose={purpose}&roll={roll}") as ws:
        while True:
            msg = ws.receive_json()
            if msg["type"] == "ping":
                ws.send_json({"type": "pong"})
            else:
                return msg


def files(frames=FRAMES):
    return [("frames", (f"f{i}.jpg", blob, "image/jpeg")) for i, blob in enumerate(frames)]


def enroll(client, device, roll="R1", name="Student One"):
    nonce = get_challenge(client, "register", roll)["nonce"]
    data = {"roll_number": roll, "name": name, "public_key": device.public_hex,
            "nonce": nonce, "signature_hex": device.sign("register", nonce, roll)}
    return client.post("/api/register", data=data, files=files()).json()


def check_in(client, device, roll="R1", nonce=None, signature=None):
    nonce = nonce or get_challenge(client, "checkin", roll)["nonce"]
    data = {"roll_number": roll, "nonce": nonce,
            "signature_hex": signature or device.sign("checkin", nonce, roll)}
    return client.post("/api/checkin", data=data, files=files()).json()


def audit_events():
    with sqlite3.connect(os.environ["AIRGATED_DB"]) as conn:
        return [row[0] for row in conn.execute("SELECT event FROM airgated_audit_log ORDER BY id")]


def test_challenge_issued_with_server_measured_rtt(client):
    msg = get_challenge(client, "checkin", "R1")
    assert msg["type"] == "challenge"
    assert msg["blinks_required"] == 2
    assert msg["rtt_ms"] > 0
    assert msg["nonce"] in server.CHALLENGES


def test_enroll_then_check_in(client):
    device = Device()
    assert enroll(client, device)["status"] == "success"
    result = check_in(client, device)
    assert result["status"] == "success", result
    with sqlite3.connect(os.environ["AIRGATED_DB"]) as conn:
        sim, blinks = conn.execute("SELECT face_similarity, blinks_detected FROM airgated_attendance_records").fetchone()
    assert sim == pytest.approx(1.0) and blinks == 3


def test_replayed_signature_rejected(client):
    device = Device()
    enroll(client, device)
    nonce = get_challenge(client, "checkin", "R1")["nonce"]
    signature = device.sign("checkin", nonce, "R1")
    assert check_in(client, device, nonce=nonce, signature=signature)["status"] == "success"
    replay = check_in(client, device, nonce=nonce, signature=signature)
    assert replay["status"] == "fraud"
    assert "already used" in replay["message"]
    assert "checkin_bad_challenge" in audit_events()


def test_nonce_for_other_roll_rejected(client):
    device = Device()
    enroll(client, device)
    nonce = get_challenge(client, "checkin", "SOMEONE_ELSE")["nonce"]
    result = check_in(client, device, nonce=nonce)
    assert result["status"] == "fraud"


def test_expired_challenge_rejected(client, monkeypatch):
    device = Device()
    enroll(client, device)
    nonce = get_challenge(client, "checkin", "R1")["nonce"]
    server.CHALLENGES[nonce].issued_at -= server.CHALLENGE_TTL_SECONDS + 1
    assert "expired" in check_in(client, device, nonce=nonce)["message"]


def test_signature_from_other_device_rejected(client):
    enroll(client, Device())
    result = check_in(client, Device())
    assert result["status"] == "fraud"
    assert "bad_signature" in audit_events()


def test_signature_must_cover_submitted_frames(client):
    device = Device()
    enroll(client, device)
    nonce = get_challenge(client, "checkin", "R1")["nonce"]
    signature = device.sign("checkin", nonce, "R1", frames=[b"different clip"])
    assert check_in(client, device, nonce=nonce, signature=signature)["status"] == "fraud"


def test_latency_gate_uses_server_rtt(client, monkeypatch):
    device = Device()
    enroll(client, device)
    monkeypatch.setattr(server, "RTT_THRESHOLD_MS", -1.0)
    msg = get_challenge(client, "checkin", "R1")
    assert msg["type"] == "error"
    assert "latency_gate" in audit_events()


def test_rtt_gate_ignores_power_save_spikes():
    # Real numbers from a classroom test: an honest phone at 1 m with radio-sleep spikes.
    spiky_but_local = [212.9, 4.1, 5.0, 180.2, 3.9, 6.2, 4.4, 101.7, 5.1, 4.8]
    gate, median = server.summarize_rtt(spiky_but_local)
    assert gate <= REAL_RTT_THRESHOLD_MS  # passes on the fastest round trip...
    assert median > 4.0                     # ...even though the median alone looked worse
    relayed = [38.0, 41.5, 36.2, 44.0, 39.9, 37.1, 52.3, 40.0, 36.9, 38.4]
    assert server.summarize_rtt(relayed)[0] > REAL_RTT_THRESHOLD_MS


def test_face_mismatch_rejected(client, monkeypatch):
    device = Device()
    enroll(client, device)
    monkeypatch.setattr(server.face_verify, "analyze", lambda frames: fake_analysis(embedding=OTHER_FACE))
    result = check_in(client, device)
    assert result["status"] == "fraud"
    assert "face_mismatch" in audit_events()


def test_not_enough_blinks_rejected(client, monkeypatch):
    device = Device()
    enroll(client, device)
    monkeypatch.setattr(server.face_verify, "analyze", lambda frames: fake_analysis(blinks=1))
    result = check_in(client, device)
    assert result["status"] == "fraud"
    assert "blinks" in result["message"]


def test_mac_mismatch_rejected(client, monkeypatch):
    device = Device()
    enroll(client, device)
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:99")
    assert check_in(client, device)["message"] == "Hardware MAC address signature mismatch."


def test_multi_profile_window(client, monkeypatch):
    first, second = Device(), Device()
    enroll(client, first, roll="R1")
    # Second student enrolls from their own phone...
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:02")
    enroll(client, second, roll="R2")
    # ...but both check in through the first phone's link layer within 60s.
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:01")
    assert check_in(client, first, roll="R1")["status"] == "success"
    with sqlite3.connect(os.environ["AIRGATED_DB"]) as conn:
        conn.execute("UPDATE airgated_device_registry SET hardware_mac = 'unknown_mac' WHERE roll_number = 'R2'")
    result = check_in(client, second, roll="R2")
    assert result["status"] == "fraud"
    assert "multi_profile" in audit_events()


def test_device_cannot_enroll_second_roll(client):
    enroll(client, Device(), roll="R1")
    result = enroll(client, Device(), roll="R2")
    assert result["status"] == "error"
    assert "register_device_taken" in audit_events()


def test_reenroll_requires_face_match(client, monkeypatch):
    enroll(client, Device())
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:77")  # new phone / new random MAC
    monkeypatch.setattr(server.face_verify, "analyze", lambda frames: fake_analysis(embedding=OTHER_FACE))
    assert enroll(client, Device())["status"] == "error"
    monkeypatch.setattr(server.face_verify, "analyze", lambda frames: fake_analysis())
    new_device = Device()
    assert enroll(client, new_device)["status"] == "success"
    assert check_in(client, new_device)["status"] == "success"
    assert "reenroll_device" in audit_events()


def test_register_catch_all_does_not_swallow_api(client):
    # Finding 4.2 regression: the catch-all must never answer real endpoints with `null`.
    response = client.post("/api/register", data={})
    assert response.status_code == 422
    assert client.post("/api/checkin", data={}).status_code == 422


def test_probe_redirects_until_verified(client):
    response = client.get("/generate_204", follow_redirects=False)
    assert response.status_code == 302
    server.VERIFIED_CLIENTS["testclient"] = 1e12
    assert client.get("/generate_204", follow_redirects=False).status_code == 204
    apple = client.get("/hotspot-detect.html", follow_redirects=False)
    assert apple.status_code == 200 and "Success" in apple.text


def test_http_listener_probe_behaviour():
    http_client = TestClient(server.build_http_app())
    first = http_client.get("/generate_204", follow_redirects=False)
    assert first.status_code == 302 and first.headers["location"].endswith("/welcome")
    assert "generate-captive-window" in http_client.get("/welcome").text
    server.VERIFIED_CLIENTS["testclient"] = 1e12
    assert http_client.get("/generate_204", follow_redirects=False).status_code == 204


def test_portal_uses_non_extractable_indexeddb_key(client):
    page = client.get("/generate-captive-window").text
    assert "localStorage." not in page
    assert 'exportKey("pkcs8"' not in page
    assert "false, [\"sign\", \"verify\"]" in page


def test_admin_is_localhost_only(client):
    assert client.get("/admin").status_code == 403


def test_dashboard_stats(client, monkeypatch):
    present_student, failing_student = Device(), Device()
    enroll(client, present_student, roll="R1", name="Asha")
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:02")
    enroll(client, failing_student, roll="R2", name="Bilal")
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:01")
    assert check_in(client, present_student, roll="R1")["status"] == "success"
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:02")
    monkeypatch.setattr(server.face_verify, "analyze", lambda frames: fake_analysis(embedding=OTHER_FACE))
    assert check_in(client, failing_student, roll="R2")["status"] == "fraud"

    local = TestClient(server.app, client=("127.0.0.1", 50000))
    page = local.get("/admin").text
    assert "Present (1)" in page and "Absent (1)" in page
    assert "Failed check-in attempts (1)" in page
    assert "Needs attention: failed and never marked present (1)" in page
    assert "Face did not match enrolled student" in page
    assert "Bilal" in page and "50%" in page


def test_reset_lets_student_enroll_new_phone(client, monkeypatch):
    enroll(client, Device(), roll="R1")
    # Lost phone: new device, new MAC, and (say) a face that no longer matches well enough.
    monkeypatch.setattr(server, "get_client_mac", lambda ip: "aa:bb:cc:dd:ee:55")
    monkeypatch.setattr(server.face_verify, "analyze", lambda frames: fake_analysis(embedding=OTHER_FACE))
    new_phone = Device()
    assert enroll(client, new_phone, roll="R1")["status"] == "error"

    assert client.post("/admin/reset", data={"roll_number": "R1"}).status_code == 403  # not from the laptop
    local = TestClient(server.app, client=("127.0.0.1", 50000))
    assert local.post("/admin/reset", data={"roll_number": "R1"}, follow_redirects=False).status_code == 303
    assert "instructor_reset" in audit_events()
    assert enroll(client, new_phone, roll="R1")["status"] == "success"
    assert check_in(client, new_phone, roll="R1")["status"] == "success"
