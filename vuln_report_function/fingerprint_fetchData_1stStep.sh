#!/bin/bash

#===============================================================================
# Cyber Samurai - Fingerprint & Data Fetch (1st Step)
# Collects initial reconnaissance data for a target domain:
#   whatweb, nmap, dirsearch, nikto, nuclei, (optional wpscan)
#===============================================================================
# Usage:
#   ./fingerprint_fetchData_1stStep.sh example.com
#   ./fingerprint_fetchData_1stStep.sh -domain example.com
#===============================================================================

#--- Parse domain argument ---
if [[ "$1" == "-domain" && -n "$2" ]]; then
    domain="$2"
elif [[ -n "$1" && "$1" != -* ]]; then
    domain="$1"
else
    echo "Usage: $0 <domain>"
    echo "       $0 -domain <domain>"
    exit 1
fi

echo "[*] Target domain: $domain"

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
whatweb "http://$domain" -v -a 3 --follow-redirect=always --log-json "${output_dir}/whatweb_rawReport.json"

###############################
#           NMAP 
###############################
#Purpose:
# Comprehensive port scanning to identify open ports, running services, service
# versions, and the operating system of the target. Uses SYN scan (-sS), version
# detection (-sV), OS detection (-O), full port range (-p-), aggressive timing
# (-T4), and default NSE scripts (-A) for thorough infrastructure reconnaissance.
nmap -sS -sV -O -p- -T4 -A -oA "${output_dir}/nmap_scan" "$ip"

###############################
#           DIRSEARCH 
###############################
#Purpose:
# Directory and file brute-forcing to discover hidden paths, backup files,
# configuration files, source code leaks, and sensitive endpoints on the
# web server. Targets common web-application extensions and filters out
# rate-limiting responses (429) and server errors (500, 503) to reduce noise.
dirsearch -u "http://$domain" -e php,asp,aspx,jsp,html,js,txt,bak,old,zip,sql,conf,config,env,log,swp --random-agent -t 30 -x 429,500,503 --format=json -o "${output_dir}/dirsearch_rawReport.json"

###############################
#           NIKTO 
###############################
#Purpose:
# Web server vulnerability scanner that checks for outdated server software,
# dangerous files/CGIs, misconfigurations, and over 6,700 potentially harmful
# files/programs. Uses SSL/TLS detection (-ssl), all tuning test types
# (1-6, 9a-b-c), verbose HTML output (-Display V), with a 60-minute timeout limit.
nikto -h "$domain" -ssl -Tuning 123456789abc -o "${output_dir}/nikto_report.html" -Format htm -Display V -timeout 15 -maxtime 3600

###############################
#           NUCLEI
###############################
#Purpose:
# Fast vulnerability scanning using YAML-based templates, targeting known CVEs.
# Scans for critical-severity vulnerabilities using CVE-focused templates (-t cves/).
# Outputs raw results in text format (-o) and JSON format (-je) for further analysis.
nuclei -u "http://$domain" -t cves/ -severity critical -o "${output_dir}/nuclei_rawReport.txt" -je "${output_dir}/nuclei_rawReport.json"

#--- If the server is identified as WordPress, run WPScan ---
###############################
#           WPScan (conditional)
###############################
#Purpose:
# WordPress-specific security scanner that enumerates plugins, themes, and users
# to identify known vulnerabilities, outdated components, and weak user accounts.
# Requires a valid WPVulnDB API token for vulnerability data lookup.
# Uncomment and set YOUR_API_TOKEN before using.
# wpscan --url "$domain" -e ap,at,u --api-token YOUR_API_TOKEN -o "${output_dir}/wpscan_rawReport.json" -f json

echo ""
echo "[+] All scans complete. Results saved in: ${output_dir}/"
echo "[*] Summary:"
echo "      whatweb   -> ${output_dir}/whatweb_rawReport.json"
echo "      nmap      -> ${output_dir}/nmap_scan.*"
echo "      dirsearch -> ${output_dir}/dirsearch_rawReport.json"
echo "      nikto     -> ${output_dir}/nikto_report.html"
echo "      nuclei    -> ${output_dir}/nuclei_rawReport.*"