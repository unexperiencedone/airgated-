# Archived prototypes — not part of the running system

These files are kept only as experimentation history (report Finding 4.8). Nothing imports or
serves them, and they have weaker security properties than the live code — do not deploy them.

- `dns_captive_tester.py` — plain-HTTP captive-portal experiment. It showed that the OS popup
  appears when the connectivity probe gets a redirect, which is how `server.py` now answers
  probes from unverified clients.
- `checkin.html`, `register.html` — early standalone pages using a hardcoded challenge.

The live portal is `templates/portal.html` (HTTPS) plus `templates/landing.html` (HTTP popup page),
both served by `server.py`.
