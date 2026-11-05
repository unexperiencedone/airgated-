# AirGated
### An Applied Systems Engineering Report on Localized, Offline Asymmetric Identity Verification

| | |
|---|---|
| **Author** | Aakshant Kumar |
| **Specialization** | Computer Science & Engineering (Artificial Intelligence) |
| **Implementation Date** | May 2026 |
| **Repository State** | Functional Core — v1.0.0-Local Verification Hub |

---

## I. Introduction & Problem Statement

In institutional environments, tracking physical presence securely typically relies on centralized cloud frameworks, biometric evaluation (e.g., facial scanning engines), or localized physical hardware tokens. These architectures suffer from significant systemic flaws:

- **Network Fragility:** Total dependence on external cloud servers renders systems unusable in dead zones, basements, or congested campus networks.
- **Identity Theft Loops:** Standard QR codes or software login portals can be easily proxied. Absent students frequently transmit access codes or credentials to peers inside the room over messaging apps.
- **Privacy Overhead:** Storing face-print vectors or biometric metrics introduces massive regulatory compliance overhead and database vulnerability vectors.

### The Objective

AirGated was engineered to design, implement, and validate a **100% offline, zero-vision identity verification application**. The system guarantees un-spoofable proximity authentication over an un-trusted local wireless network loop — without capturing personal user data or relying on active internet routing.

---

## II. Iterative System Evolution

The project moved through three distinct phases to isolate bugs and close structural loopholes.

### Phase 1: The GPS Cloud-Geofenced Model *(Decommissioned)*

The design initially leaned on cloud endpoints paired with HTML5 Geolocation browser queries. The server computed the distance between student devices and the instructor using the Haversine formula over the public internet.

> **The Exploit:** Client-side GPS data is inherently insecure. Students easily used developer options, root mock-location apps, or modified user-agents to fake coordinates while remaining completely outside the classroom.

### Phase 2: Asymmetric Device Binding *(The Cryptographic Foundation)*

To prevent credential sharing, the system shifted toward client-side cryptography utilizing the browser's native Web Crypto API (`window.crypto.subtle`).

- During initialization, the client generates a unique **2048-bit RSA key pair** (`RSASSA-PKCS1-v1_5`).
- The private key is saved with the property `extractable: false` directly into the browser's sandboxed **IndexedDB** engine (`LocalDeviceAuth`).
- Because the key cannot be read out of storage by user scripts, students are physically prevented from duplicating or texting their cryptographic identity to another device.

### Phase 3: Network-Layer Interface Hardening *(The Final Core)*

Phase 2 still left a critical vulnerability unaddressed: **Device Concurrency Collisions**. An individual could bring multiple physical devices into a classroom, or manually clear browser profiles to sequentially sign in for absent classmates using identical phone hardware configurations.

To close this loophole, the system architecture was pulled entirely down to a **local subnet wrapper**. By forcing authentication to run through a localized Wi-Fi mobile hotspot or travel router hosted by the instructor's machine, the backend gained access to physical link-layer packets.

By intercepting the client's connection properties, the system runs an active lookup against the host operating system's internal **ARP (Address Resolution Protocol)** cache, mapping the incoming IP directly to its permanent, immutable factory-burned **hardware MAC address**.

---

## III. System Architecture & Core Mechanics

The verification framework executes as a deterministic, **three-stage security pipeline** whenever a client invokes the check-in controller:

```
[ Client Device Payload ]
           │
           ├──► Stage 1: Latency Proximity Verification  (Threshold ≤ 20.0ms)
           │
           ├──► Stage 2: Link-Layer Identity Binding     (Host OS ARP Subprocess Lookup)
           │
           └──► Stage 3: Asymmetric Signature Validation (RSA SHA-256 Signature Match)
```

### Stage 1 — Temporal Proximity Gating

Before parsing cryptographic hashes, a persistent WebSocket connection (`/ws/latency`) executes a fast **3-cycle Ping/Pong** frame transmission. The backend agent calculates the precise round-trip time ($RTT_{ms}$).

If $RTT_{ms} > 20.0\text{ms}$, the session is **immediately terminated** as an un-trusted proxy anomaly, ensuring the client is communicating within the physical boundary of the local router.

### Stage 2 — Physical Address Resolution Subprocess

The backend avoids browser sandbox restrictions by conducting a native operating system query against the networking stack via an internal utility module:

```python
def get_client_mac(client_ip: str) -> str:
    try:
        current_os = platform.system().lower()
        if "windows" in current_os:
            output = subprocess.check_output(
                ["arp", "-a", client_ip], creationflags=0x08000000
            ).decode("utf-8")
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output)
        else:
            output = subprocess.check_output(["arp", "-n", client_ip]).decode("utf-8")
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output)
        return mac_match.group(0).lower().replace("-", ":") if mac_match else "unknown_mac"
    except Exception:
        return "unknown_mac"
```

### Stage 3 — Concurrent-Device Multi-Profile Lockout

To break sequential proxy submissions, the backend monitors state concurrency. If an identical network MAC token attempts to sign or write data for more than one unique enrollment roll number inside a rolling **60-second window**, the pipeline triggers a fraud restriction:

$$\text{Collision State} = \exists \, \text{Record} \in \text{Log} \mid \text{Log}_{\text{mac}} = \text{Current}_{\text{mac}} \;\land\; \text{Log}_{\text{time}} > (\text{Current}_{\text{time}} - 60s) \;\land\; \text{Log}_{\text{roll}} \neq \text{Current}_{\text{roll}}$$

---

## IV. Post-Implementation Technical Retrospective

During development, several critical system exceptions were encountered and resolved.

### 1. Namespace Pollution (Native Type Overwrite)

| | |
|---|---|
| **Symptom** | Core execution failed with `AttributeError: module 'bytes' has no attribute 'fromhex'` |
| **Root Cause** | A duplicate structural declaration `import bytes` at the top of the server module overrode Python's native built-in namespace, assigning it to an empty external module wrapper. |
| **Resolution** | Stripped out the redundant import statement, restoring native casting functionality and allowing fast hexadecimal unpacking from strings to raw binary data buffers. |

### 2. Web Crypto API Context Sandbox Restrictions

| | |
|---|---|
| **Symptom** | The registration interface loaded onto mobile browser viewports but failed silently when the form submission button was tapped. |
| **Root Cause** | Modern Chromium and WebKit architectures enforce strict sandboxing — they completely disable `window.crypto.subtle` if the parent web platform is served over an unencrypted transport layer (`http`), meaning raw local IP bindings (`http://192.168.137.1`) crash instantly. |
| **Resolution** | Configured mobile testing platforms via hidden flags (`chrome://flags/#unsafely-treat-insecure-origin-as-secure`) to explicitly register the gateway address as a verified secure context. For production scaling, this friction is eliminated by wrapping the client code within a native application environment (e.g., Flutter/Tauri), which bypasses browser sandbox restrictions. |

### 3. Subnet Inbound Adapter Blockades

| | |
|---|---|
| **Symptom** | External mobile client browsers timed out continuously when attempting to connect to the hosted application portal on the host laptop. |
| **Root Cause** | The Windows Defender Firewall filter pipeline blocks inbound traffic originating from external virtual network switches targeting un-whitelisted port layers. |
| **Resolution** | Injected a manual rule modification into the elevated system kernel via an administrative PowerShell execution path: |

```powershell
New-NetFirewallRule -DisplayName "FastAPI Attendance Port 8000" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000
```

---

## V. Peer-to-Peer Engineering Contribution Audit

As the sole **Principal Engineer and System Architect** of this architecture, technical execution spanned the entire project lifecycle:

- **Backend Pipeline Assembly:** Wrote the core FastAPI network router framework, SQLite persistent database layout, and asynchronous communication blocks.
- **Cryptographic System Design:** Structured the browser-to-server payload interface. Authored the binary-to-hex conversion logic on the frontend and mapped it to the backend `load_der_public_key` cryptography validation engine.
- **OS-Level Infrastructure Injection:** Authored the low-level regex and subprocess utilities that query host network routing tables, unlocking deep MAC hardware tracking capabilities from an offline web application loop.
- **Network Security Scripting:** Programmed the mathematical defenses guarding the endpoints — specifically the rolling 60-second database lockout checks and the strict 20ms WebSocket latency verification loop.
- **Low-Level System Troubleshooting:** Traced and resolved kernel firewall errors, isolated and fixed global namespace collisions, and resolved secure browser context flag issues across client devices.

---

## VI. Conclusion & Production Blueprint

The core system validation proves that **high-security proximity verification does not require complex remote infrastructures or intrusive data collection**. By anchoring user validation directly onto hardware-backed encryption keys and cross-checking them against native link-layer telemetry, AirGated is a working prototype of an offline attendance platform for modern offline environments; it is not production-ready (see README section 14 and the technical report for what remains).

---

*AirGated — v1.0.0-Local Verification Hub | May 2026*
