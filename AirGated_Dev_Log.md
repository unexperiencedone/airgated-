# AirGated: Development Log

Running record of what changed, what broke, and how each problem was found and fixed.
Newest entry first.

---

## 2026-11-05: Linux (Ubuntu) port, hotspot, and MAC-change handling

**Starting point:** the project had been developed and tested only on Windows (Mobile Hotspot,
`192.168.137.1`, `arp -a`, Internet Connection Sharing). The development machine moved to Ubuntu
(kernel 7.0, Python 3.14.4, Intel Raptor Lake CNVi Wi-Fi). Rule for the port: **`server.py` stays
Windows-compatible; Linux-specific behaviour lives in new files.**

### 1. Verifying the repo runs on Linux

| Step | Result |
|---|---|
| `uv venv` + `pip install -r requirements.txt` on Python 3.14 | All packages installed, including mediapipe and opencv |
| `pytest` | 31 passed (the one warning and the mediapipe `TypeError` at interpreter exit are harmless) |
| Live run on alternate ports (53→5454, 80→8080, 443→8443) as a normal user, scratch DB | Face models loaded; portal and `/admin` returned 200; `/generate_204` gave 302; CA download 200; DNS answered `192.168.137.1` |

Checked afterwards that the real `database.db` was byte-identical and the git tree was clean.

### 2. Problems found on Linux and what was done

| # | Problem | How it was found | Fix |
|---|---|---|---|
| 1 | `arp` is not installed on Ubuntu, so every MAC came back `unknown_mac` (this would break the device and MAC gates and the one-MAC-one-roll rule) | `get_client_mac('127.0.0.1')` printed `Failed to fetch MAC via ARP entry lookup: [Errno 2] No such file or directory: 'arp'` | `server_linux.py` reads `/proc/net/arp` (flag `0x2` = complete entry), falls back to `ip neigh`. Verified against the real gateway (`4e:74:d4:..`); unknown IPs return `unknown_mac` |
| 2 | `systemd-resolved` already holds port 53 on `127.0.0.53` / `127.0.0.54`, so binding `0.0.0.0:53` fails | `ss -lntup` before starting | DNS spoofer tries `0.0.0.0:53` first (same as Windows) and falls back to binding only the hotspot address |
| 3 | Ports 53/80/443 are privileged | `ip_unprivileged_port_start` was `1024` | Run as `sudo .venv/bin/python server_linux.py`; preflight warns if not root |
| 4 | `192.168.137.1` is a Windows ICS default; on Linux it does not exist until the hotspot is created | Preflight check on interface addresses | `hotspot_linux.sh` creates the access point at that address |

New files: `server_linux.py` (Linux launcher; imports `server.py` and swaps in the Linux MAC lookup
and DNS spoofer, plus a preflight report) and `hotspot_linux.sh` (`up` / `down` / `status`).

### 3. Hotspot problems and how they were found

**a) NetworkManager silently turned `manual` into `shared`.**
The first hotspot script created the AP with `ipv4.method manual`. The system log showed NetworkManager
starting its own `dnsmasq` (`DHCP, IP range 192.168.137.10 -- 192.168.137.254, lease time 1h`), which
would own ports 53 and 67 and block AirGated's DNS spoofer. Creating throwaway profiles and reading the
setting back showed the rule: for AP-mode profiles `manual`, `link-local` and the default all end up
as `shared`; only `disabled` is kept. **Fix:** create the profile with `ipv4.method disabled`, assign
`192.168.137.1/24` with `ip addr add`, and run a DHCP-only `dnsmasq` (`port=0`) that hands out leases
with gateway and DNS set to the laptop.

**b) Phone showed "not connected" with the correct password.**
Two causes were considered. NetworkManager was offering WPA2/WPA3 (`WPA-PSK WPA-PSK-SHA256 SAE`), which
some phones fail against a laptop AP, so `wifi-sec.pmf disable` was added to force plain WPA2. After that
the log changed from "nothing from the phone" to the 4-way handshake being reached and failing:

```
wpa_supplicant[1772]: wlp0s20f3: AP-STA-POSSIBLE-PSK-MISMATCH e6:4d:43:..
wpa_supplicant[1772]: wlp0s20f3: AP-STA-POSSIBLE-PSK-MISMATCH 00:9c:c0:..
```

`POSSIBLE-PSK-MISMATCH` means the phone sent a different passphrase from the one the AP holds, so the
remaining suspects were typing/autocorrect and a stale saved network on the phone. The test was to restart
the hotspot with a simple lowercase password and "Forget" the network on the phone first. The phones then
connected. *The exact cause of the earlier mismatch was not isolated; the WPA3 fix and the password retry
were applied together.*

**c) DNS spoofer start order (confirmed by experiment).**
Starting the server before the hotspot is up cannot work: the port-53 bind fails on `0.0.0.0` (resolved
owns it) and then on `192.168.137.1` (address does not exist yet):

```
❌ DNS Server failed to start on port 53: [Errno 99] Cannot assign requested address
   192.168.137.1 is not assigned to any interface yet -- bring the hotspot up first.
```

After running `hotspot_linux.sh up` first and then restarting the server:

```
📡 [DNS Spoofer] Active on 192.168.137.1:53. Answering every name with 192.168.137.1...
```

Order on Linux is therefore the **reverse** of Windows: hotspot first, server second.
(The preflight still prints a warning about `systemd-resolve` on `127.0.0.53/54:53`. It is harmless
because the DNS spoofer binds only the hotspot address.)

### 4. MAC mismatch after moving from Windows

The first Linux check-ins from an already enrolled student failed:

```
🚨 [Audit:mac_mismatch] Roll: <roll> | IP: 192.168.137.209 | MAC: 00:9c:c0:.. | registered 36:59:ce:..
🚨 [Audit:mac_mismatch] Roll: <roll> | IP: 192.168.137.247 | MAC: e6:4d:43:.. | registered 36:59:ce:..
```

Reading the addresses: bit `0x02` of the first byte marks a randomized (locally administered) address.
The registered `36:59:ce:…` and the later `e6:4d:…` are randomized; `00:9c:c0:…` is the phone's real
hardware address. So the phone presented a different address on the new network than on the old hotspot.

**Observation (tested on 6 phones over 3–4 days on the Windows hotspot, no MAC settings changed):**
a phone keeps the same MAC on a given network, randomized or not, until the network is forgotten.
On Linux the same phone also kept `e6:4d:43:..` across repeated check-ins and reconnects. It follows
that the MAC changes only when the network changes (new hotspot name) or is forgotten. Moving from the
Windows hotspot to the Linux one therefore changed it for every enrolled student.

**Design consequence:** a student who forgets the network by mistake must not lose their attendance.
Re-registration already existed (face match re-keys the device), but check-in rejected on the MAC before
looking at the key or face, and the message said nothing useful.

**Change (in `server.py`, `templates/portal.html`):**
- A MAC difference no longer ends check-in early. The device-key signature and the face + blink check
  still run.
- Only the MAC differs → attendance is **not** marked; the reply is `reenroll`, the page shows a
  re-register form with roll number and name filled in, and re-registering still requires a fresh face match.
  Audit event: `mac_changed_verified`.
- MAC differs *and* something else fails → refused with a message listing **every** mismatch, e.g.
  `Check-in refused. Not matching: 1. Wi-Fi hardware (MAC) address differs ... 2. Face does not match ...`.
  No re-register offer.
- MAC matches → behaviour unchanged.
- The key is a non-extractable WebCrypto key held in IndexedDB, so a valid signature is evidence the
  enrolled browser is the one answering. Together with the face match, that is why a changed MAC alone is
  not treated as suspicious.
- 4 new tests, 1 replaced: **34 passing**.

Live confirmation after the change (server on Linux, hotspot up):

```
🚨 [Audit:mac_changed_verified] ... registered 36:59:ce:..; key and face verified (face 0.674)
🚨 [Audit:register_liveness_failed] ... Liveness check failed: asked for 2 blinks, saw 0.
🚨 [Audit:reenroll_device] ... face match 0.618; previous MAC 36:59:ce:..
🎉 [Gateway Success] Roll: <roll> | face 0.582 | blinks 3 | RTT 3.7ms
```

The flow worked end to end: verified, offered re-registration, one retry after a missed blink, re-keyed on
the new MAC, then checked in. Face scores of 0.58 to 0.67 are well above the 0.363 match threshold.

### 5. Open items from this session

- **Maximum number of devices on the hotspot is unknown.** `iw list` prints no station limit for this
  card, so none is advertised. Windows' limit of 8 came from ICS and does not apply. Limits to expect, in
  order: Wi-Fi driver/firmware station count (unknown, measure it), the 241-address DHCP pool
  (`.10`–`.250`), then CPU time for face analysis and the 20 ms latency gate under load. Measure by adding
  phones one at a time while watching `iw dev wlp0s20f3 station dump | grep -c ^Station`.
- The laptop has no internet while the hotspot runs (the one Wi-Fi card is used for the AP).
- The enrollment page still tells students to turn off Private Wi-Fi address / Randomized MAC. The MAC
  observation above makes that advice unnecessary, as long as the setting stays fixed for the class network.
- README still has Windows-only setup steps and says 31 tests.
- `systemd-resolved` is left alone; the hotspot script does not touch it.


---

## 2026-11-05 (later): hardening after an external review

A review of the paper against the code found security claims that the code did not support. Changes:

- **Face identity sampled across the whole clip.** `face_verify.analyze` built the identity embedding from the
  first 12 eyes-open frames (about the first second) but counted blinks over the whole clip, so a photo of the
  enrolled student followed by someone else blinking could pass. Frames are now sampled at random, one from each
  of 12 equal slices of the clip. The consistency check also compared each frame with the clip's mean only; a
  half-and-half clip of two people scores about 0.71 against its own mean. Every sampled pair must now reach the
  match threshold. Risk: one blurry frame can fail a genuine student; needs checking on real phones.
- **Re-keying needs the old key.** `/api/register` re-keyed a roll on a face match alone. It now also requires a
  signature from the currently enrolled key (`old_signature_hex`); a lost phone or cleared browser goes through
  an instructor reset. The browser ties its key to the portal's address, so that address must stay fixed.
- **Audit gaps closed** (unknown MAC at registration, bad frames, face-engine errors, bad challenge requests) and
  successful re-keys are shown on the dashboard.
- Tests: 39 (was 34). Mutation check: 7 deliberate bugs, all caught (`results/mutation_2026-11-05.txt`).
- Load test re-run after the face change (`results/loadtest_2026-11-05.txt`): 2.0 s per analysis, about 29
  check-ins/min at 5-20 simulated students, gate RTT unaffected.
- Not fixed, disclosed: replaying a recording with enough blinks still passes (head-turn challenge planned);
  the MAC can be changed without root.
