#!/bin/bash

# Usage: ./nmap_scan.sh <target_ip> [output_directory]
# Example: ./nmap_scan.sh 192.168.1.1 ./scans

TARGET_IP="$1"
OUTPUT_DIR="${2:-output}"
PROXY_NMAP="${3:-}"  # Optional proxy parameter

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Nmap scan against: $TARGET_IP"
echo "[*] Output directory: $OUTPUT_DIR"

# ==========================================
# STAGE 1: Find all open ports (fast scan)
# ==========================================
echo "[*] Stage 1: Scanning for all open ports..."

if [ -n "$PROXY_NMAP" ]; then
    PROXY_CMD="$PROXY_NMAP"
else
    PROXY_CMD=""
fi

# Fast port discovery (all ports, top speed)
PORTS_FILE="${OUTPUT_DIR}/open_ports.txt"
nmap -p- -T4 --min-rate=1000 $PROXY_CMD "$TARGET_IP" | \
    grep -E '^[0-9]+/tcp' | \
    cut -d '/' -f 1 | \
    tr '\n' ',' | \
    sed 's/,$//' > "$PORTS_FILE"

# Read the ports back
OPEN_PORTS=$(cat "$PORTS_FILE")

if [ -z "$OPEN_PORTS" ]; then
    echo "[-] No open ports found. Exiting."
    exit 1
fi

echo "[+] Open ports identified: $OPEN_PORTS"
echo "[+] Open ports saved to: $PORTS_FILE"

# ==========================================
# STAGE 2: Detailed scan on open ports
# ==========================================
echo "[*] Stage 2: Running detailed scan on open ports..."

nmap -sS -sV -O -p "$OPEN_PORTS" \
    -T4 -A \
    --script default,vuln,vulners \
    $PROXY_CMD \
    -oX "${OUTPUT_DIR}/nmap_scan.xml" \
    "$TARGET_IP"

# ==========================================
# Check results
# ==========================================
if [ $? -eq 0 ]; then
    echo "[+] Scan completed successfully!"
    echo "[+] XML report: ${OUTPUT_DIR}/nmap_scan.xml"
    echo "[+] Text report: ${OUTPUT_DIR}/nmap_scan.txt"

    # Extract summary from XML
    echo -e "\n[*] Scan Summary:"
    xmlstarlet sel -t -m "//port" -v "concat(@portid,'/',protocol,' ',state/@state)" -n "${OUTPUT_DIR}/nmap_scan.xml" 2>/dev/null || \
    echo "  (Install xmlstarlet for detailed summary)"
else
    echo "[-] Scan failed. Check your inputs."
    exit 1
fi