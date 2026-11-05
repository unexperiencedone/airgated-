#!/usr/bin/env python3
"""Generates the vector figures used in AirGated_arXiv_Paper.tex (PDF, plus PNG previews).

    python figures/make_figures.py        # needs matplotlib; writes next to this script

Palette is light and prints acceptably in grayscale: blue = student/phone side, green = laptop/server,
amber = instructor, red = rejection, grey = neutral. Everything shown is implemented except the
hardware concept (fig_hardware), which is a proposal and is labelled as such in the figure.
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Polygon, Wedge, Rectangle

OUT = os.path.dirname(os.path.abspath(__file__))
C = {"blue": "#dbeafe", "green": "#dcfce7", "amber": "#fef3c7", "red": "#fee2e2", "grey": "#f3f4f6",
     "edge": "#374151", "redge": "#b91c1c", "text": "#111827", "purple": "#ede9fe"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "pdf.fonttype": 42})


def canvas(w, h):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, w); ax.set_ylim(0, h); ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, text, fill="grey", edge=None, fs=8, bold=False, style="round,pad=0.02,rounding_size=0.06", ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=style, fc=C.get(fill, fill), ec=edge or C["edge"], lw=0.9, ls=ls))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=C["text"],
            fontweight="bold" if bold else "normal", linespacing=1.25)


def arrow(ax, p, q, text=None, color=None, rad=0.0, fs=7, tdx=0.0, tdy=0.08, ls="-"):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=9, lw=0.9, color=color or C["edge"],
                                 connectionstyle=f"arc3,rad={rad}", linestyle=ls, shrinkA=0, shrinkB=0))
    if text:
        ax.text((p[0] + q[0]) / 2 + tdx, (p[1] + q[1]) / 2 + tdy, text, ha="center", va="bottom", fontsize=fs,
                color=color or C["text"])


def save(fig, name):
    fig.savefig(os.path.join(OUT, name + ".pdf"), bbox_inches="tight", pad_inches=0.05)
    fig.savefig(os.path.join(OUT, name + ".png"), dpi=160, bbox_inches="tight", pad_inches=0.05)
    plt.close(fig)


# --------------------------------------------------------------------------------------------
def fig_architecture():
    fig, ax = canvas(7.4, 4.1)
    # Phones
    box(ax, 0.1, 2.9, 1.7, 0.95, "Student phone A\nbrowser + non-extractable\nRSA key (IndexedDB)", "blue")
    box(ax, 0.1, 1.7, 1.7, 0.95, "Student phone B\nbrowser + key", "blue")
    box(ax, 0.1, 0.5, 1.7, 0.95, "Student phone N\nbrowser + key", "blue")
    # Laptop container
    ax.add_patch(FancyBboxPatch((2.5, 0.2), 4.7, 3.8, boxstyle="round,pad=0.02,rounding_size=0.1", fc="#f9fafb", ec=C["edge"], lw=1.2))
    ax.text(4.85, 3.82, "Access host: runs AirGated (laptop today; dedicated unit later)", ha="center", va="center", fontsize=9, fontweight="bold")
    box(ax, 2.65, 3.0, 1.45, 0.6, "Wi-Fi access point\n+ DHCP only\n(OS-specific part)", "amber", fs=7)
    box(ax, 4.2, 3.0, 1.35, 0.6, "DNS responder\nUDP 53: every name\n→ laptop", "green", fs=7)
    box(ax, 5.65, 3.0, 1.4, 0.6, "HTTP :80\nOS probes, landing\npage, CA download", "green", fs=7)
    box(ax, 2.65, 1.85, 4.4, 0.85, "HTTPS :443 — FastAPI\nportal • /ws/challenge (RTT + nonce) • /api/register • /api/checkin • /admin", "green", fs=7.5, bold=False)
    box(ax, 2.65, 0.4, 1.4, 1.1, "Face engine\nYuNet → MediaPipe\n→ SFace\n(one clip at a time)", "purple", fs=7)
    box(ax, 4.2, 0.4, 1.3, 1.1, "SQLite\nregistry • records\n• audit log", "grey", fs=7)
    box(ax, 5.65, 0.4, 1.4, 1.1, "Neighbour table\nIP → MAC\n(OS-specific lookup)", "grey", fs=7)
    for y, ty in ((3.37, 3.38), (2.17, 3.30), (0.97, 3.22)):
        arrow(ax, (1.8, y), (2.65, ty), None)
    ax.text(2.2, 3.62, "Wi-Fi", ha="center", fontsize=7, style="italic")
    arrow(ax, (3.35, 3.0), (3.35, 2.7)); arrow(ax, (4.9, 3.0), (4.9, 2.7)); arrow(ax, (6.35, 3.0), (6.35, 2.7))
    arrow(ax, (3.35, 1.85), (3.35, 1.5)); arrow(ax, (4.85, 1.85), (4.85, 1.5)); arrow(ax, (6.35, 1.85), (6.35, 1.5))
    ax.text(2.2, 3.62, "", fontsize=1)
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    save(fig, "fig_architecture")


# --------------------------------------------------------------------------------------------
def fig_checkin():
    fig, ax = canvas(7.4, 6.2)
    x0, w, h = 0.3, 2.9, 0.46
    ys = [5.5, 4.75, 4.0, 3.25, 2.5, 1.75]
    labels = [
        "1  Nonce valid?  single-use, <120 s,\nsame roll + IP",
        "2  Server-measured fastest RTT ≤ 20 ms?",
        "Roll enrolled with a face?",
        "3  MAC == enrolled MAC?\n(mismatch is recorded, not fatal)",
        "4  RSA signature over nonce + frames hash\nvalid for enrolled key?",
        "5  Liveness: ≥K blinks, one face\nFace similarity ≥ 0.363?",
    ]
    for y, t in zip(ys, labels):
        box(ax, x0, y, w, h + 0.08, t, "green", fs=7.2)
    for a, b in zip(ys[:-1], ys[1:]):
        arrow(ax, (x0 + w / 2, a), (x0 + w / 2, b + h + 0.08))
    rej = [("checkin_bad_challenge", 0), ("latency_gate", 1), ("checkin_unregistered /\ncheckin_no_face", 2)]
    for t, i in rej:
        box(ax, 4.0, ys[i] + 0.02, 2.0, 0.5, t, "red", edge=C["redge"], fs=6.8)
        arrow(ax, (x0 + w, ys[i] + 0.27), (4.0, ys[i] + 0.27), "no", C["redge"], tdy=0.03)
    # after the face stage three outcomes
    cx = x0 + w / 2
    box(ax, 0.1, 0.55, 1.95, 0.75, "MAC ok, all checks pass\n6  one MAC, one roll / 60 s?\n→ attendance recorded", "blue", fs=6.9)
    box(ax, 2.2, 0.55, 2.05, 0.75, "Only MAC differs; key + face OK\n→ NOT marked present;\nre-register offer (face re-key)", "amber", fs=6.9)
    box(ax, 4.4, 0.55, 2.1, 0.75, "MAC differs AND another check\nfails → refused; message lists\nevery mismatching check", "red", edge=C["redge"], fs=6.9)
    arrow(ax, (cx, ys[-1]), (1.1, 1.3)); arrow(ax, (cx, ys[-1]), (3.2, 1.3)); arrow(ax, (cx, ys[-1]), (5.45, 1.3))
    ax.text(5.2, 3.1, "Gate 3 is evaluated first\nbut only acted on after\ngates 4 and 5", ha="center", va="center", fontsize=7, style="italic")
    box(ax, 6.2, 3.85, 1.15, 0.7, "every rejection\n→ audit log", "grey", fs=6.8, ls="--")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    save(fig, "fig_checkin")


# --------------------------------------------------------------------------------------------
def sequence(name, actors, msgs, size):
    """UML-style sequence chart. actors: [(label, fill)], msgs: ('phase', text) | (src, dst, text, kind)
    where kind is '' (normal), 'dash' (proposed / optional), 'red' (rejection) or 'note' (self note)."""
    w, h = size
    fig, ax = canvas(w, h)
    n = len(actors)
    xs = [w * (i + 0.5) / n for i in range(n)]
    top = h - 0.55
    bw = min(1.9, w / n - 0.3)
    for x, (lab, fill) in zip(xs, actors):
        box(ax, x - bw / 2, h - 0.5, bw, 0.42, lab, fill, fs=7.6, bold=True)
        ax.plot([x, x], [0.1, h - 0.5], color="#9ca3af", lw=0.8, ls=(0, (4, 3)), zorder=0)
    step = (top - 0.25) / len(msgs)
    y = top - step * 0.6
    for m in msgs:
        if m[0] == "phase":
            ax.add_patch(Rectangle((0.05, y - 0.13), w - 0.1, 0.26, fc="#e5e7eb", ec="none", zorder=1))
            ax.text(0.15, y, m[1], fontsize=7.2, fontweight="bold", va="center", zorder=2)
        else:
            src, dst, text, kind = m
            xa, xb = xs[src], xs[dst]
            col = C["redge"] if kind == "red" else C["edge"]
            ls = (0, (3, 2)) if kind == "dash" else "-"
            arrow(ax, (xa, y), (xb, y), None, col, ls=ls)
            ax.text((xa + xb) / 2, y + 0.06, text, ha="center", va="bottom", fontsize=6.7, color=col,
                    bbox=dict(fc="white", ec="none", pad=0.6, alpha=0.85), zorder=3)
        y -= step
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    save(fig, name)


def fig_student():
    actors = [("Student\n(person)", "blue"), ("Phone browser", "grey"), ("Access host", "green")]
    P, B, H = 0, 1, 2
    msgs = [
        ("phase", "1  Join"),
        (P, B, "join class Wi-Fi", ""),
        (H, B, "OS probe redirected \u2192 portal page", ""),
        ("phase", "2  Enroll (first time only)"),
        (P, B, "roll no., name; blink as prompted", ""),
        (B, H, "challenge socket (timed pings)", ""),
        (H, B, "nonce + random blink count K", ""),
        (B, H, "public key + signed clip", ""),
        (H, B, "liveness + face OK \u2192 key, MAC, face stored", ""),
        ("phase", "3  Check in (every class)"),
        (P, B, "roll no.; blink as prompted", ""),
        (B, H, "challenge \u2192 signed clip (same flow)", ""),
        (H, B, "PRESENT: attendance recorded", ""),
        (H, B, "REFUSED: message lists every mismatch", "red"),
        (H, B, "OFFER: key + face OK, MAC changed, re-register", "dash"),
        ("phase", "4  Re-register (only after the offer above)"),
        (B, H, "new key, signed by old key + fresh face clip", ""),
        (H, B, "face matched \u2192 re-keyed, new MAC stored", ""),
        (B, H, "check in again \u2192 PRESENT", ""),
    ]
    sequence("fig_student", actors, msgs, (7.0, 6.2))


def fig_instructor():
    actors = [("Instructor\n(phone or laptop)", "amber"), ("Access host", "green"), ("Student phones", "blue")]
    I, H, S = 0, 1, 2
    msgs = [
        ("phase", "1  Before class"),
        (I, H, "start access point (script / button)", ""),
        (I, H, "start AirGated service", ""),
        (H, I, "preflight: address, ports, models", ""),
        ("phase", "2  During class"),
        (S, H, "join, enroll, check in", ""),
        (I, H, "open dashboard from own phone (proposed)", "dash"),
        (H, I, "present / absent, failures, needs attention", ""),
        ("phase", "3  Exceptions"),
        (S, I, "lost or replaced phone (in person)", ""),
        (I, H, "reset that student's enrollment (audit-logged)", ""),
        (S, H, "enroll again on new phone", ""),
        ("phase", "4  After class"),
        (I, H, "review audit log, stop service, access point off", ""),
    ]
    sequence("fig_instructor", actors, msgs, (7.0, 4.9))


# --------------------------------------------------------------------------------------------
def fig_hardware():
    fig, ax = canvas(7.4, 3.9)
    ax.text(0.05, 3.75, "Proposed (not built): room-bounded access unit", fontsize=8.5, fontweight="bold", va="center")
    # floor plan
    ax.add_patch(Rectangle((0.2, 0.3), 3.2, 2.7, fc="#f0fdf4", ec=C["edge"], lw=1.3))
    ax.add_patch(Rectangle((0.2, 3.0), 3.2, 0.45, fc="#e5e7eb", ec=C["edge"], lw=0.8))
    ax.text(0.75, 3.22, "corridor", ha="center", va="center", fontsize=7)
    ax.add_patch(Rectangle((3.4, 0.3), 0.55, 3.15, fc="#e5e7eb", ec=C["edge"], lw=0.8))
    ax.text(3.67, 1.9, "next\nroom", ha="center", va="center", fontsize=7, rotation=90)
    ax.add_patch(Wedge((0.9, 1.65), 2.35, -26, 26, fc="#bfdbfe", ec="#1d4ed8", lw=0.9, alpha=0.65))
    box(ax, 0.38, 1.4, 0.55, 0.5, "AP\nunit", "amber", fs=7)
    for (x, y) in [(1.8, 1.2), (2.3, 1.5), (1.6, 1.7), (2.5, 2.0), (2.0, 2.05), (2.4, 1.15), (1.5, 1.2)]:
        ax.plot(x, y, "o", ms=3.8, color="#1d4ed8")
    ax.text(2.0, 0.12, "sector antenna + limited TX power keep the cell inside the room", ha="center", fontsize=6.6)
    ax.plot(1.45, 3.22, "x", ms=6, color=C["redge"]); ax.text(1.6, 3.22, "student in corridor: below join threshold", fontsize=6.2, color=C["redge"], va="center")
    ax.plot(1.25, 1.95, "s", ms=5, color="#b45309"); ax.text(1.35, 2.0, "instructor\nphone", fontsize=6.2, va="bottom")
    # block diagram
    bx = 4.35
    ax.add_patch(FancyBboxPatch((bx, 0.3), 2.95, 3.15, boxstyle="round,pad=0.02,rounding_size=0.08", fc="#f9fafb", ec=C["edge"], lw=1.1))
    ax.text(bx + 1.475, 3.3, "Access unit (one per room)", ha="center", fontsize=8, fontweight="bold")
    box(ax, bx + 0.12, 2.5, 1.35, 0.6, "Radio(s) +\ndirectional / sector\nantenna, TX limit", "amber", fs=6.6)
    box(ax, bx + 1.58, 2.5, 1.25, 0.6, "Ranging: RTT,\nRSSI (FTM if the\nradio supports it)", "amber", fs=6.6)
    box(ax, bx + 0.12, 1.5, 1.35, 0.8, "AirGated service\nDNS, HTTP(S), DHCP,\nface engine (NPU/GPU)", "green", fs=6.6)
    box(ax, bx + 1.58, 1.5, 1.25, 0.8, "Secure element:\nsigns attendance\nrecords", "purple", fs=6.6)
    box(ax, bx + 0.12, 0.45, 1.35, 0.8, "Local store\n(SQLite, audit)", "grey", fs=6.6)
    box(ax, bx + 1.58, 0.45, 1.25, 0.8, "Optional uplink:\nsync to institution\nafter class", "grey", fs=6.6, ls="--")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    save(fig, "fig_hardware")


if __name__ == "__main__":
    for f in (fig_architecture, fig_checkin, fig_student, fig_instructor, fig_hardware):
        f()
    print("figures written to", OUT)
