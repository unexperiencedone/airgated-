#!/usr/bin/env bash
# AirGated: Wi-Fi hotspot for Linux (uses the laptop's own Wi-Fi card).
#
#   sudo ./hotspot_linux.sh up        # create the AP at 192.168.137.1 + DHCP, open firewall ports
#   sudo .venv/bin/python server_linux.py   # then start AirGated
#   sudo ./hotspot_linux.sh down      # tear everything down, reconnect the previous Wi-Fi
#        ./hotspot_linux.sh status
#
# Why not NetworkManager's built-in "shared" hotspot? It starts its own dnsmasq on port 53, which
# would stop AirGated's DNS spoofer (the captive-portal popup) from answering. So the AP is
# created with a fixed address and no NM DNS/DHCP, and a DHCP-only dnsmasq (port=0) hands out
# leases that point phones at 192.168.137.1 for gateway and DNS.
#
# NOTE: the Wi-Fi card is used exclusively for the hotspot, so the laptop is offline (unless it has
# Ethernet) while the hotspot is up. AirGated needs no internet during class.
#
# Env overrides:
#   AIRGATED_SSID (AirGated)   AIRGATED_WIFI_PASS (AirGated123, min 8 chars; "open" = no password)
#   AIRGATED_LOCAL_IP (192.168.137.1)   AIRGATED_CHANNEL (6, 2.4 GHz)   AIRGATED_WIFI_IF (auto)
#   DRY_RUN=1  print the commands instead of running them

set -euo pipefail

SSID="${AIRGATED_SSID:-AirGated}"
PASS="${AIRGATED_WIFI_PASS:-AirGated123}"
IP="${AIRGATED_LOCAL_IP:-192.168.137.1}"
CHANNEL="${AIRGATED_CHANNEL:-6}"
CON="airgated-hotspot"
RUN_DIR="/run/airgated"
PIDFILE="$RUN_DIR/dnsmasq.pid"
PREV_FILE="$RUN_DIR/prev_connection"
DRY="${DRY_RUN:-0}"
PREFIX="24"
NET="${IP%.*}"                       # 192.168.137
FW_COMMENT="airgated-hotspot"

run() { if [[ "$DRY" == 1 ]]; then echo "+ $*"; else "$@"; fi; }
die() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ "$DRY" == 1 || $EUID -eq 0 ]] || die "run with sudo:  sudo $0 $1"; }

wifi_if() {
    if [[ -n "${AIRGATED_WIFI_IF:-}" ]]; then echo "$AIRGATED_WIFI_IF"; return; fi
    nmcli -t -f DEVICE,TYPE dev | awk -F: '$2=="wifi"{print $1; exit}'
}

fw_rules() {  # action: add|del
    command -v ufw >/dev/null 2>&1 || return 0
    ufw status 2>/dev/null | grep -q "Status: active" || return 0
    local IFACE="$1" action="$2" proto port
    for rule in udp:53 udp:67 tcp:80 tcp:443; do
        proto="${rule%%:*}"; port="${rule##*:}"
        if [[ "$action" == add ]]; then
            run ufw allow in on "$IFACE" proto "$proto" to any port "$port" comment "$FW_COMMENT" >/dev/null
        else
            run ufw delete allow in on "$IFACE" proto "$proto" to any port "$port" >/dev/null 2>&1 || true
        fi
    done
    local verb="opened"; [[ "$action" == del ]] && verb="closed"
    echo "   firewall (ufw): 53/udp 67/udp 80/tcp 443/tcp $verb on $IFACE"
}

cmd_up() {
    need_root up
    command -v nmcli >/dev/null || die "NetworkManager (nmcli) not found"
    command -v dnsmasq >/dev/null || die "dnsmasq not installed:  sudo apt install dnsmasq"
    [[ "$PASS" == open || ${#PASS} -ge 8 ]] || die "AIRGATED_WIFI_PASS must be at least 8 characters (or 'open')"
    local IFACE; IFACE="$(wifi_if)"
    [[ -n "$IFACE" ]] || die "no Wi-Fi interface found"
    echo "▶ Wi-Fi interface: $IFACE   SSID: $SSID   address: $IP/$PREFIX   channel: $CHANNEL (2.4 GHz)"

    run mkdir -p "$RUN_DIR"
    run rfkill unblock wifi || true

    # Remember what to reconnect to when we're done.
    local prev; prev="$(nmcli -g GENERAL.CONNECTION dev show "$IFACE" 2>/dev/null || true)"
    if [[ -n "$prev" && "$prev" != "$CON" && "$prev" != "--" && "$DRY" != 1 ]]; then
        echo "$prev" > "$PREV_FILE"
        echo "   will reconnect to '$prev' on 'down'"
    fi

    # Fresh profile every time so settings never drift.
    run nmcli con delete "$CON" >/dev/null 2>&1 || true
    local sec=()
    if [[ "$PASS" != open ]]; then
        sec=(wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$PASS" wifi-sec.proto rsn
             wifi-sec.pairwise ccmp wifi-sec.group ccmp wifi-sec.pmf disable)
    fi
    run nmcli con add type wifi ifname "$IFACE" con-name "$CON" ssid "$SSID" \
        802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel "$CHANNEL" \
        ipv4.method disabled ipv6.method disabled \
        connection.autoconnect no "${sec[@]}" >/dev/null
    run nmcli con up "$CON" ifname "$IFACE" >/dev/null
    # NetworkManager silently turns ipv4.method=manual into "shared" for AP profiles, which starts
    # its own dnsmasq on ports 53/67. "disabled" is kept as-is, so we assign the address ourselves.
    run ip addr flush dev "$IFACE" || true
    run ip addr add "$IP/$PREFIX" dev "$IFACE"
    echo "✔ Access point up at $IP/$PREFIX"
    if pgrep -f "nm-dnsmasq-$IFACE" >/dev/null 2>&1; then
        echo "⚠ NetworkManager started its own dnsmasq for $IFACE; this will conflict with AirGated" >&2
    fi

    # DHCP only (port=0 disables dnsmasq's DNS so AirGated can own port 53).
    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        run kill "$(cat "$PIDFILE")" || true
    fi
    local CONF="$RUN_DIR/dnsmasq.conf"
    if [[ "$DRY" == 1 ]]; then
        echo "+ write $CONF (port=0, interface=$IFACE, dhcp-range=$NET.10-$NET.250, router/dns=$IP)"
    else
        cat > "$CONF" <<EOF
port=0
interface=$IFACE
bind-interfaces
except-interface=lo
dhcp-range=$NET.10,$NET.250,255.255.255.0,12h
dhcp-option=3,$IP
dhcp-option=6,$IP
dhcp-leasefile=$RUN_DIR/dnsmasq.leases
dhcp-authoritative
pid-file=$PIDFILE
log-dhcp
log-facility=$RUN_DIR/dnsmasq.log
EOF
    fi
    run dnsmasq --conf-file="$CONF"
    echo "✔ DHCP server up ($NET.10 - $NET.250, gateway/DNS $IP)"

    fw_rules "$IFACE" add
    cat <<EOF

Hotspot ready.  Students join:  SSID "$SSID"   password "$([[ $PASS == open ]] && echo '(none)' || echo "$PASS")"
Now start AirGated:   sudo .venv/bin/python server_linux.py
Dashboard:            https://localhost/admin
EOF
}

cmd_down() {
    need_root down
    local IFACE; IFACE="$(wifi_if)"
    if [[ -f "$PIDFILE" ]]; then
        run kill "$(cat "$PIDFILE")" 2>/dev/null || true
        run rm -f "$PIDFILE"
    fi
    [[ -n "$IFACE" ]] && fw_rules "$IFACE" del
    run nmcli con down "$CON" >/dev/null 2>&1 || true
    run nmcli con delete "$CON" >/dev/null 2>&1 || true
    echo "✔ Hotspot removed"
    if [[ -f "$PREV_FILE" ]]; then
        local prev; prev="$(cat "$PREV_FILE")"
        echo "   reconnecting to '$prev'..."
        run nmcli con up "$prev" >/dev/null 2>&1 || echo "   (could not reconnect automatically; use your network menu)"
        run rm -f "$PREV_FILE"
    fi
}

cmd_status() {
    local IFACE; IFACE="$(wifi_if)"
    echo "Wi-Fi interface : ${IFACE:-none}"
    echo "Active profile  : $(nmcli -g GENERAL.CONNECTION dev show "$IFACE" 2>/dev/null || echo '?')"
    echo "Address         : $(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | paste -sd' ' || true)"
    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "DHCP (dnsmasq)  : running (pid $(cat "$PIDFILE"))"
    else
        echo "DHCP (dnsmasq)  : not running"
    fi
    if [[ -f "$RUN_DIR/dnsmasq.leases" ]]; then
        echo "Leases          :"; sed 's/^/   /' "$RUN_DIR/dnsmasq.leases"
    fi
}

case "${1:-}" in
    up) cmd_up ;;
    down) cmd_down ;;
    status) cmd_status ;;
    *) sed -n '2,11p' "$0"; exit 1 ;;
esac
