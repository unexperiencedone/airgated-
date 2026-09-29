# AirGated

Offline classroom attendance. The instructor's laptop hosts a Wi-Fi network. Each check-in has
to pass six checks, all decided on the laptop:

1. **Single-use challenge.** The server issues a nonce over a WebSocket. The nonce is tied to the roll number and client IP, expires after 120 s, and is deleted when used, so a captured request can't be replayed.
2. **Latency gate.** The server times 5 round trips itself and takes the median, which must be 20 ms or less. The phone never reports this number.
3. **Link-layer binding.** The phone's MAC address, read from the laptop's ARP table, must match the enrolled one.
4. **Device key.** A non-extractable RSA-2048 key kept in the phone's IndexedDB signs the nonce, the roll number and a SHA-256 hash of the exact camera frames being submitted.
5. **KYC face check.** The phone records about 5 s of video while the student blinks a random number of times (2 or 3). The laptop counts blinks with MediaPipe, confirms there's one consistent face, and matches it against the enrolled face with OpenCV SFace.
6. **One device, one profile.** A single MAC address can't check in two different roll numbers within 60 s.

Every rejection is written to `airgated_audit_log` and shown on the instructor dashboard.

## Setup (once, while online)

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install -r requirements.txt
python fetch_models.py            # ~42 MB of face models into models/, checksum-verified
copy .env.example .env            # then put your GROQ_API_KEY in .env (only needed for /generate-exam)
```

## Running a class

1. Turn Mobile Hotspot **off**.
2. Start the server as Administrator with `python server.py`. It needs ports 53, 80 and 443.
3. Turn the hotspot **on**. The server has to claim port 53 before Windows ICS does.
4. Students join the Wi-Fi. The sign-in popup explains what to do and links to
   `https://192.168.137.1/generate-captive-window`, which they open in Chrome or Safari. The popup's
   built-in browser can't use the camera, so check-in happens in the full browser.
5. Open `https://localhost/admin` on the laptop to see today's attendance, the audit log and enrolled
   devices, and to reset a student's enrollment.

The TLS certificate and classroom CA are created once in `ssl_certs/` and reused on every start. Students can install
the CA once from `http://192.168.137.1/airgated-ca.crt` so the browser stops showing a security warning.

## Deployment prerequisites

- **Access point.** Windows Mobile Hotspot allows only 8 devices, which isn't enough for a 67-student class.
  Use a dedicated travel router, or the room's own Wi-Fi if you're allowed to, and set `AIRGATED_LOCAL_IP`
  to the laptop's address on that network.
- **MAC randomization.** Before enrolling, each student must turn off "Private Wi-Fi address" (iOS) or
  "Randomized MAC" (Android) for the class network. If they don't, their MAC can change and check-in fails
  the link-layer check. A student whose MAC or phone changed can enroll again, but only if their face matches
  the enrolled face.
- **What the latency gate actually proves.** It shows the phone is on the classroom network with low
  latency. It doesn't show the phone is inside the room, because Wi-Fi reaches hallways. The face check means
  the enrolled student has to be holding the phone, but not that they're in the room.
- **Browser HSTS errors.** If Brave or Chrome shows a certificate error with no way to proceed, clear the cached
  HSTS entry for `192.168.137.1` at `brave://net-internals/#hsts` or `chrome://net-internals/#hsts`.

## Known limits of the face check

- Liveness is a blink challenge with a random count. It stops printed photos and still images. It doesn't stop
  someone who plays a video of the enrolled student blinking the right number of times into the camera on the
  registered device.
- The face-match threshold is 0.363 cosine similarity, OpenCV's recommended value for SFace. Before relying on
  it, tune it on your own students under the room's actual lighting.
- The best open-eyes frame from each check-in is saved to `evidence/` so it can be reviewed. It contains
  students' faces, so it's excluded from git.

## Tests

```bash
python -m pytest tests
```
