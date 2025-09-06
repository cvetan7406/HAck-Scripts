#!/usr/bin/env bash
set -euo pipefail

# ---- Config ----
INTERNET_IF="wlan0"      # uplink that's already online
AP_IF="wlan1"            # interface that will host the AP
SSID="A1_EC8C"           # network name
CHANNEL="6"
COUNTRY="BG"

GATEWAY_IP="10.0.0.1"
DHCP_START="10.0.0.10"
DHCP_END="10.0.0.50"

RUNTIME="/tmp/lab_open_ap"
HOSTAPD_CONF="$RUNTIME/hostapd.conf"
DNSMASQ_CONF="$RUNTIME/dnsmasq.conf"
IPTABLES_SAVE="$RUNTIME/iptables.save"
HOSTAPD_LOG="$RUNTIME/hostapd.log"
BETTERCAP_LOG="$RUNTIME/bettercap.log"
BETTERCAP_PCAP_DIR="$RUNTIME/sniff"
BETTERCAP_PID="$RUNTIME/bettercap.pid"

# Set during start by prompt_security()
SECURITY_MODE="${SECURITY_MODE:-open}"   # "open" or "wpa2"
PASSPHRASE="${PASSPHRASE:-}"

SCRIPT_NAME="$(basename "$0")"

print_help() {
  cat <<EOF
Usage:
  sudo $SCRIPT_NAME start
  sudo $SCRIPT_NAME stop
  sudo $SCRIPT_NAME help
  sudo $SCRIPT_NAME -h | --help

Description:
  Brings up a Wi-Fi AP on \$AP_IF and NATs traffic out via \$INTERNET_IF.
  Runs hostapd + dnsmasq and starts bettercap packet capture (pcap in: $BETTERCAP_PCAP_DIR).
  On 'start' you'll be asked whether to secure the AP with WPA2-PSK.

Current defaults:
  INTERNET_IF=$INTERNET_IF
  AP_IF=$AP_IF
  SSID=$SSID
  CHANNEL=$CHANNEL
  COUNTRY=$COUNTRY
  GATEWAY_IP=$GATEWAY_IP
  DHCP_START=$DHCP_START
  DHCP_END=$DHCP_END
  RUNTIME=$RUNTIME

Files/Logs:
  hostapd log: $HOSTAPD_LOG
  bettercap log: $BETTERCAP_LOG
  pcaps dir:   $BETTERCAP_PCAP_DIR

Examples:
  sudo $SCRIPT_NAME start
  sudo $SCRIPT_NAME stop

Notes:
  - Requires: hostapd, dnsmasq, iptables, ip, sysctl, bettercap
  - If NetworkManager manages \$AP_IF, the script sets it unmanaged during runtime.
EOF
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0 {start|stop|help}"; exit 1; fi
}

check_bins() {
  for b in hostapd dnsmasq iptables ip sysctl bettercap; do
    command -v "$b" >/dev/null || { echo "Missing $b. Install it."; exit 1; }
  done
}

prompt_security() {
  # Ask if we want WPA2-PSK; default is open if blank/Enter.
  local ans
  while true; do
    read -r -p "Use WPA2-PSK password? [y/N]: " ans || true
    ans="${ans,,}"  # lowercase
    if [[ -z "$ans" || "$ans" == "n" || "$ans" == "no" ]]; then
      SECURITY_MODE="open"
      echo "→ Open network selected (no password)."
      break
    elif [[ "$ans" == "y" || "$ans" == "yes" ]]; then
      SECURITY_MODE="wpa2"
      # Read and confirm passphrase (8–63 chars)
      while true; do
        read -r -s -p "Enter WPA2 passphrase (8–63 chars): " pw; echo
        read -r -s -p "Confirm passphrase: " pw2; echo
        if [[ "$pw" != "$pw2" ]]; then
          echo "Passphrases do not match. Try again."
          continue
        fi
        if (( ${#pw} < 8 || ${#pw} > 63 )); then
          echo "Invalid length (${#pw}). Must be 8–63 characters."
          continue
        fi
        PASSPHRASE="$pw"
        # Do not echo the actual password back.
        echo "→ Secured network selected (WPA2-PSK)."
        break
      done
      break
    else
      echo "Please answer y or n."
    fi
  done
}

write_confs() {
  mkdir -p "$RUNTIME" "$BETTERCAP_PCAP_DIR"

  # hostapd config
  # Common header
  {
    echo "interface=$AP_IF"
    echo "driver=nl80211"
    echo "ssid=$SSID"
    echo "country_code=$COUNTRY"
    echo "hw_mode=g"
    echo "channel=$CHANNEL"
    echo "ieee80211n=1"
    echo "wmm_enabled=1"
    echo "auth_algs=1"
    if [[ "$SECURITY_MODE" == "open" ]]; then
      cat <<'OPEN'
wpa=0
OPEN
    else
      # WPA2-PSK only, CCMP
      cat <<SECURE
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$PASSPHRASE
SECURE
    fi
  } > "$HOSTAPD_CONF"

  # dnsmasq config
  cat > "$DNSMASQ_CONF" <<EOF
interface=$AP_IF
bind-interfaces
domain-needed
bogus-priv
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,12h
dhcp-option=3,$GATEWAY_IP
dhcp-option=6,$GATEWAY_IP
log-queries
log-dhcp
EOF
}

start_bettercap() {
  mkdir -p "$BETTERCAP_PCAP_DIR"
  local ts="$(date +%Y%m%d-%H%M%S)"
  local pcap="$BETTERCAP_PCAP_DIR/sniff-$ts.pcap"

  # Headless + no TTY: redirect stdin from /dev/null so it never asks "Are you sure..."
  nohup bettercap -iface "$AP_IF" -no-colors -silent \
    -eval "set net.sniff.local true; set net.sniff.output $pcap; net.sniff on" \
    > "$BETTERCAP_LOG" 2>&1 < /dev/null &

  echo $! > "$BETTERCAP_PID"
  echo "Bettercap started on $AP_IF → $pcap (log: $BETTERCAP_LOG)"
}

stop_bettercap() {
  # Stop via PID if available, else best-effort pkill
  if [[ -f "$BETTERCAP_PID" ]]; then
    local pid
    pid="$(cat "$BETTERCAP_PID" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 0.5
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$BETTERCAP_PID"
  fi
  pkill -f "^bettercap .* -iface $AP_IF" 2>/dev/null || true
}

start_ap() {
  rfkill unblock all || true
  if command -v nmcli >/dev/null 2>&1; then nmcli dev set "$AP_IF" managed no || true; fi

  ip link set "$AP_IF" down || true
  ip addr flush dev "$AP_IF" || true
  ip addr add "$GATEWAY_IP/24" dev "$AP_IF"
  ip link set "$AP_IF" up

  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  iptables-save > "$IPTABLES_SAVE"
  iptables -t nat -A POSTROUTING -o "$INTERNET_IF" -j MASQUERADE
  iptables -A FORWARD -i "$INTERNET_IF" -o "$AP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A FORWARD -i "$AP_IF" -o "$INTERNET_IF" -j ACCEPT

  pkill dnsmasq 2>/dev/null || true
  dnsmasq -C "$DNSMASQ_CONF"

  nohup hostapd "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &

  # small settle
  sleep 1

  start_bettercap

  local mode_label="OPEN"
  [[ "$SECURITY_MODE" == "wpa2" ]] && mode_label="WPA2-PSK"
  echo "AP '$SSID' ($mode_label) on $AP_IF (GW $GATEWAY_IP). Internet via $INTERNET_IF."
  echo "DHCP: $DHCP_START – $DHCP_END"
  echo "hostapd log: $HOSTAPD_LOG"
}

stop_ap() {
  echo "Stopping services..."
  stop_bettercap
  pkill hostapd 2>/dev/null || true
  pkill dnsmasq 2>/dev/null || true

  if [[ -f "$IPTABLES_SAVE" ]]; then
    iptables-restore < "$IPTABLES_SAVE" || true
    rm -f "$IPTABLES_SAVE"
  else
    iptables -t nat -D POSTROUTING -o "$INTERNET_IF" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$INTERNET_IF" -o "$AP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$AP_IF" -o "$INTERNET_IF" -j ACCEPT 2>/dev/null || true
  fi

  sysctl -w net.ipv4.ip_forward=0 >/dev/null || true
  if command -v nmcli >/dev/null 2>&1; then nmcli dev set "$AP_IF" managed yes || true; fi
  ip addr flush dev "$AP_IF" || true
  ip link set "$AP_IF" down || true

  echo "Stopped. Logs and pcaps in: $RUNTIME"
}

# --- CLI parsing (help flags) ---
case "${1:-}" in
  -h|--help|help)
    print_help
    exit 0
    ;;
esac

case "${1:-}" in
  start)
    ensure_root
    check_bins
    prompt_security
    write_confs
    start_ap
    ;;
  stop)
    ensure_root
    stop_ap
    ;;
  *)
    echo "Usage: sudo $SCRIPT_NAME {start|stop|help}"
    echo "Try:   sudo $SCRIPT_NAME --help"
    exit 1
    ;;
esac