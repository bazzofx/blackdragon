#!/bin/bash

#===============================================================================
# Cyber Samurai - Vulnerability Fetch (fetchVuln.sh)
# Collects initial reconnaissance data for a target domain:
#   whatweb, nmap, dirsearch, nikto, nuclei, (optional wpscan)
#===============================================================================
# Usage:
#   ./fetchVuln.sh example.com
#   ./fetchVuln.sh -d example.com
#   ./fetchVuln.sh -domain example.com
#   ./fetchVuln.sh -d example.com -proxy 12.12.223.231:8080
#===============================================================================

set -e  # Exit on error

#--- Parse arguments ---
domain=""
proxy=""
skip_nikto=false
skip_nuclei=false
skip_wpscan=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|-domain)
            domain="$2"
            shift 2
            ;;
        -proxy)
            proxy="$2"
            shift 2
            ;;
        --skip-nikto)
            skip_nikto=true
            shift
            ;;
        --skip-nuclei)
            skip_nuclei=true
            shift
            ;;
        --skip-wpscan)
            skip_wpscan=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-d|-domain] <domain> [-proxy ip:port] [--skip-nikto] [--skip-nuclei] [--skip-wpscan]"
            echo ""
            echo "Examples:"
            echo "  $0 example.com"
            echo "  $0 -d example.com"
            echo "  $0 -d example.com -proxy 12.12.223.231:8080"
            echo "  $0 -d example.com --skip-nikto --skip-nuclei"
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Usage: $0 [-d|-domain] <domain> [-proxy ip:port]"
            exit 1
            ;;
        *)
            # Positional argument — treat as domain if not set yet
            if [[ -z "$domain" ]]; then
                domain="$1"
            else
                echo "Unexpected argument: $1"
                echo "Usage: $0 [-d|-domain] <domain> [-proxy ip:port]"
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$domain" ]]; then
    echo "Usage: $0 [-d|-domain] <domain> [-proxy ip:port]"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 -d example.com"
    echo "  $0 -domain example.com"
    echo "  $0 -d example.com -proxy 12.12.223.231:8080"
    exit 1
fi

echo "[*] Target domain: $domain"

#--- Check for required tools ---
required_tools=("whatweb" "nmap" "dirsearch" "nikto" "nuclei" "dig" "nslookup")
missing_tools=()

for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done

if [[ ${#missing_tools[@]} -gt 0 ]]; then
    echo "[!] Missing required tools: ${missing_tools[*]}"
    echo "[!] Please install them before running this script."
    exit 1
fi

#--- Build proxy argument string (prepend protocol if needed) ---
proxy_whatweb=""
proxy_dirsearch=""
proxy_nikto=""
proxy_nuclei=""
proxy_wpscan=""
proxy_nmap=""

if [[ -n "$proxy" ]]; then
    # Strip any existing scheme so we normalise it
    proxy_clean="${proxy#http://}"
    proxy_clean="${proxy_clean#https://}"
    proxy_clean="${proxy_clean#socks4://}"
    proxy_clean="${proxy_clean#socks5://}"
    proxy_clean="${proxy_clean#tcp://}"

    proxy_whatweb="--proxy http://${proxy_clean}"
    proxy_dirsearch="--proxy http://${proxy_clean}"
    proxy_nikto="-proxy http://${proxy_clean}"
    proxy_nuclei="-proxy-url http://${proxy_clean}"
    proxy_wpscan="--proxy tcp://${proxy_clean}"
    # nmap --proxies only works with HTTP-based probes (version detection / NSE),
    # NOT with SYN scan (-sS). Full TCP scanning through a proxy is not supported.
    proxy_nmap="--proxies http://${proxy_clean}"

    echo "[*] Proxy configured: http://${proxy_clean}"
fi

#--- Create output directory named after the domain ---
output_dir="./${domain}"
mkdir -p "$output_dir"
echo "[*] Output directory: $output_dir/"

#--- Perform NSLOOKUP to find the IP and save it to a variable called ip ---
echo "[*] Resolving IP for $domain..."
ip=$(dig +short "$domain" 2>/dev/null | head -1)
if [[ -z "$ip" ]]; then
    ip=$(nslookup "$domain" 2>/dev/null | grep -i "Address:" | tail -1 | awk '{print $2}')
fi
if [[ -z "$ip" ]]; then
    echo "[!] Could not resolve IP for $domain. Using domain directly for IP-based scans."
    ip="$domain"
fi
echo "[*] Resolved IP: $ip"

###############################
#           WHATWEB 
###############################
# Purpose:
# Gather information about the technology stack running on the target web server.
# Identifies CMS, web frameworks, server software, JavaScript libraries,
# analytics tools, and other technologies. Uses aggressive aggression level (-a 3)
# and follows redirects to map the full technology fingerprint.
echo ""
echo "[*] Running whatweb against $domain ..."
whatweb "http://$domain" -v -a 3 --follow-redirect=always $proxy_whatweb --log-json "${output_dir}/whatweb_rawReport.json" || {
    echo "[!] WhatWeb scan failed, but continuing..."
}

###############################
#           NMAP 
###############################
# Purpose:
# Comprehensive port scanning to identify open ports, running services, service
# versions, and the operating system of the target. Uses SYN scan (-sS), version
# detection (-sV), OS detection (-O), full port range (-p-), aggressive timing
# (-T4), and default NSE scripts (-A) for thorough infrastructure reconnaissance.
# NOTE: --proxies only affects HTTP-based version probes, not the SYN scan itself.
# ==========================================
# STAGE 1: Find all open ports (fast scan)
# ==========================================
echo ""
echo "[*] Stage 1: Scanning for all open ports..."

# Fast port discovery (all ports, top speed)
PORTS_FILE="${output_dir}/open_ports.txt"
nmap -p- -T4 --min-rate=1000 "$ip" | \
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
echo ""
echo "[*] Stage 2: Running detailed scan on open ports..."

# Build nmap command with or without proxy
nmap_cmd="nmap -sS -sV -O -p \"$OPEN_PORTS\" -T4 -A --script default,vuln,vulners"

if [[ -n "$proxy" ]]; then
    echo "[!] Note: nmap --proxies only affects HTTP-based probes, not SYN scans"
    nmap_cmd="$nmap_cmd $proxy_nmap"
fi

nmap_cmd="$nmap_cmd -oX \"${output_dir}/nmap_rawReport.xml\" \"$ip\""

# Execute nmap
eval "$nmap_cmd"

# ==========================================
# Check results
# ==========================================
if [ $? -eq 0 ]; then
    echo "[+] Scan completed successfully!"
    echo "[+] XML report: ${output_dir}/nmap_rawReport.xml"

    # Extract summary from XML if xmlstarlet is available
    if command -v xmlstarlet &> /dev/null; then
        echo -e "\n[*] Scan Summary:"
        xmlstarlet sel -t -m "//port" -v "concat(@portid,'/',protocol,' ',state/@state)" -n "${output_dir}/nmap_rawReport.xml" 2>/dev/null || \
        echo "  (No ports found in XML)"
    else
        echo "  (Install xmlstarlet for detailed summary)"
    fi
else
    echo "[-] Scan failed. Check your inputs."
    exit 1
fi

###############################
#           DIRSEARCH 
###############################
# Purpose:
# Directory and file brute-forcing to discover hidden paths, backup files,
# configuration files, source code leaks, and sensitive endpoints on the
# web server. Targets common web-application extensions and filters out
# rate-limiting responses (429) and server errors (500, 503) to reduce noise.
echo ""
echo "[*] Running dirsearch against $domain ..."
dirsearch -u "http://$domain" -e php,asp,aspx,jsp,html,js,txt,bak,old,zip,sql,conf,config,env,log,swp --random-agent -t 30 -x 429,500,503 $proxy_dirsearch --format=json -o "${output_dir}/dirsearch_rawReport.json" || {
    echo "[!] Dirsearch scan failed, but continuing..."
}

###############################
#           NIKTO 
###############################
# Purpose:
# Web server vulnerability scanner that checks for outdated server software,
# dangerous files/CGIs, misconfigurations, and over 6,700 potentially harmful
# files/programs. Uses SSL/TLS detection (-ssl), all tuning test types
# (1-6, 9a-b-c), verbose HTML output (-Display V), with a 60-minute timeout limit.
if [ "$skip_nikto" = false ]; then
    echo ""
    echo "[*] Running nikto against $domain ..."
    nikto -h "$domain" -ssl -Tuning 123456789abc $proxy_nikto -o "${output_dir}/nikto_report.html" -Format htm -Display V -timeout 15 -maxtime 3600 || {
        echo "[!] Nikto scan failed, but continuing..."
    }
else
    echo "[*] Skipping nikto scan (--skip-nikto specified)"
fi

###############################
#           NUCLEI
###############################
# Purpose:
# Fast vulnerability scanning using YAML-based templates, targeting known CVEs.
# Scans for critical-severity vulnerabilities using CVE-focused templates (-t cves/).
# Outputs raw results in text format (-o) and JSON format (-je) for further analysis.
if [ "$skip_nuclei" = false ]; then
    echo ""
    echo "[*] Running nuclei against $domain ..."
    nuclei -u "http://$domain" -t cves/ -severity critical $proxy_nuclei -o "${output_dir}/nuclei_rawReport.txt" -je "${output_dir}/nuclei_rawReport.json" || {
        echo "[!] Nuclei scan failed, but continuing..."
    }
else
    echo "[*] Skipping nuclei scan (--skip-nuclei specified)"
fi

###############################
#           WPScan (conditional)
###############################
# Purpose:
# WordPress-specific security scanner that enumerates plugins, themes, and users
# to identify known vulnerabilities, outdated components, and weak user accounts.
# Requires a valid WPVulnDB API token for vulnerability data lookup.
# Set WPSAN_API_TOKEN environment variable before running.
if [ "$skip_wpscan" = false ]; then
    # Check if target is WordPress
    echo ""
    echo "[*] Checking if target is WordPress..."
    if curl -s -L "http://$domain" | grep -qi "wp-content\|wordpress"; then
        echo "[+] Target appears to be WordPress. Running WPScan..."
        
        if [[ -z "${WPSAN_API_TOKEN:-}" ]]; then
            echo "[!] WPSAN_API_TOKEN environment variable not set"
            echo "[!] Skipping WPScan. Set token with: export WPSAN_API_TOKEN='your_token'"
        else
            wpscan --url "http://$domain" -e ap,at,u --api-token "$WPSAN_API_TOKEN" $proxy_wpscan -o "${output_dir}/wpscan_rawReport.json" -f json || {
                echo "[!] WPScan failed, but continuing..."
            }
        fi
    else
        echo "[*] Target does not appear to be WordPress. Skipping WPScan."
    fi
else
    echo "[*] Skipping wpscan (--skip-wpscan specified)"
fi

echo ""
echo "[+] All scans complete. Results saved in: ${output_dir}/"
echo "[*] Summary:"
echo "      whatweb   -> ${output_dir}/whatweb_rawReport.json"
echo "      nmap      -> ${output_dir}/nmap_rawReport.xml"
if [ "$skip_nikto" = false ]; then
    echo "      nikto     -> ${output_dir}/nikto_report.html"
fi
if [ "$skip_nuclei" = false ]; then
    echo "      nuclei    -> ${output_dir}/nuclei_rawReport.*"
fi

if [[ -n "$proxy" ]]; then
    echo "[*] Used proxy: http://${proxy_clean}"
fi

# Generate the fingerprint report
echo ""
echo "[*] Generating fingerprint report..."
python3 report.py "$output_dir" || {
    echo "[!] Report generation failed, but scans completed successfully"
}

echo ""
echo "END"