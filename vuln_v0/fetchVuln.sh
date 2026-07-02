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

#--- Parse arguments ---
domain=""
proxy=""

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
#Purpose:
# Gather information about the technology stack running on the target web server.
# Identifies CMS, web frameworks, server software, JavaScript libraries,
# analytics tools, and other technologies. Uses aggressive aggression level (-a 3)
# and follows redirects to map the full technology fingerprint.
echo ""
echo "[*] Running whatweb against $domain ..."
whatweb "http://$domain" -v -a 3 --follow-redirect=always $proxy_whatweb --log-json "${output_dir}/whatweb_rawReport.json"

###############################
#           NMAP 
###############################
#Purpose:
# Comprehensive port scanning to identify open ports, running services, service
# versions, and the operating system of the target. Uses SYN scan (-sS), version
# detection (-sV), OS detection (-O), full port range (-p-), aggressive timing
# (-T4), and default NSE scripts (-A) for thorough infrastructure reconnaissance.
# NOTE: --proxies only affects HTTP-based version probes, not the SYN scan itself.
echo ""
echo "[*] Running nmap against $ip ..."
nmap -sS -sV -O -p- -T4 -A $proxy_nmap -oA "${output_dir}/nmap_scan" "$ip"

###############################
#           DIRSEARCH 
###############################
#Purpose:
# Directory and file brute-forcing to discover hidden paths, backup files,
# configuration files, source code leaks, and sensitive endpoints on the
# web server. Targets common web-application extensions and filters out
# rate-limiting responses (429) and server errors (500, 503) to reduce noise.
echo ""
echo "[*] Running dirsearch against $domain ..."
dirsearch -u "http://$domain" -e php,asp,aspx,jsp,html,js,txt,bak,old,zip,sql,conf,config,env,log,swp --random-agent -t 30 -x 429,500,503 $proxy_dirsearch --format=json -o "${output_dir}/dirsearch_rawReport.json"

###############################
#           NIKTO 
###############################
#Purpose:
# Web server vulnerability scanner that checks for outdated server software,
# dangerous files/CGIs, misconfigurations, and over 6,700 potentially harmful
# files/programs. Uses SSL/TLS detection (-ssl), all tuning test types
# (1-6, 9a-b-c), verbose HTML output (-Display V), with a 60-minute timeout limit.
echo ""
echo "[*] Running nikto against $domain ..."
nikto -h "$domain" -ssl -Tuning 123456789abc $proxy_nikto -o "${output_dir}/nikto_report.html" -Format htm -Display V -timeout 15 -maxtime 3600

###############################
#           NUCLEI
###############################
#Purpose:
# Fast vulnerability scanning using YAML-based templates, targeting known CVEs.
# Scans for critical-severity vulnerabilities using CVE-focused templates (-t cves/).
# Outputs raw results in text format (-o) and JSON format (-je) for further analysis.
echo ""
echo "[*] Running nuclei against $domain ..."
nuclei -u "http://$domain" -t cves/ -severity critical $proxy_nuclei -o "${output_dir}/nuclei_rawReport.txt" -je "${output_dir}/nuclei_rawReport.json"

#--- If the server is identified as WordPress, run WPScan ---
###############################
#           WPScan (conditional)
###############################
#Purpose:
# WordPress-specific security scanner that enumerates plugins, themes, and users
# to identify known vulnerabilities, outdated components, and weak user accounts.
# Requires a valid WPVulnDB API token for vulnerability data lookup.
# Uncomment and set YOUR_API_TOKEN before using.
# echo ""
# echo "[*] Running wpscan against $domain ..."
# wpscan --url "$domain" -e ap,at,u --api-token YOUR_API_TOKEN $proxy_wpscan -o "${output_dir}/wpscan_rawReport.json" -f json

echo ""
echo "[+] All scans complete. Results saved in: ${output_dir}/"
echo "[*] Summary:"
echo "      whatweb   -> ${output_dir}/whatweb_rawReport.json"
echo "      nmap      -> ${output_dir}/nmap_scan.*"
echo "      dirsearch -> ${output_dir}/dirsearch_rawReport.json"
echo "      nikto     -> ${output_dir}/nikto_report.html"
echo "      nuclei    -> ${output_dir}/nuclei_rawReport.*"

if [[ -n "$proxy" ]]; then
    echo "[*] Used proxy: http://${proxy_clean}"
fi


python3 fingerprint_report.py "$domain"
echo "END"