# fetch.sh — Automated Reconnaissance & Report Pipeline

**Script:** `vulv2/fetch.sh`
**Platform:** Linux / WSL (bash)

## What It Does

Runs a full reconnaissance pipeline against a target domain, then auto-generates the HTML vulnerability report:

1. Resolves domain to IP
2. Runs **whatweb** — technology fingerprint
3. Runs **nmap** (2-stage) — port discovery + detailed service/vuln scan
4. Runs **ffuf** — directory brute-force
5. Runs **report.py** — compiles HTML vulnerability report

All output lands in `./<domain>/`.

## Quick Start

```bash
cd vulv2
chmod +x fetch.sh

# Basic scan
./fetch.sh example.com

# With proxy
./fetch.sh -d example.com -proxy 127.0.0.1:8080
```

## Flags

| Flag | Example | Effect |
|---|---|---|
| `-d <domain>` | `-d example.com` | Explicit domain flag |
| `-domain <domain>` | `-domain example.com` | Same as `-d` |
| `-proxy <ip:port>` | `-proxy 127.0.0.1:8080` | Route all tools through proxy |
| (positional) | `./fetch.sh example.com` | Domain as first argument |

## Examples

```bash
# Simplest — just a domain
./fetch.sh acmecorp.com

# Explicit domain flag
./fetch.sh -d acmecorp.com

# Through a proxy (Burp, mitmproxy, etc.)
./fetch.sh -d acmecorp.com -proxy 127.0.0.1:8080

# Proxy with auth
./fetch.sh acmecorp.com -proxy user:pass@proxy.example.com:3128
```

## What Gets Created

After a successful run against `acmecorp.com`:

```
vulv2/acmecorp.com/
├── whatweb_rawReport.json    # Technology fingerprint
├── open_ports.txt            # Raw port list from stage 1
├── nmap_rawReport.xml        # Full Nmap XML (services, vulns, OS)
├── ffuf_rawReport.json       # Directory brute-force results
└── vulnReport.html           # Final HTML report (auto-generated)
```

## Scan Stages

### 1. WhatWeb (1–2 min)
Runs `whatweb` with aggression level 3 and redirect following. Identifies CMS, frameworks, server software, JS libraries.

### 2. Nmap Stage 1 — Port Discovery (1–5 min)
Fast SYN scan across all 65535 ports. Results saved to `open_ports.txt`.

### 3. Nmap Stage 2 — Deep Scan (5–30 min)
Detailed scan on discovered open ports only:
- `-sV` service/version detection
- `-O` OS fingerprinting
- `--script vuln,vulners` CVE database lookup
- `-A` OS detection + traceroute + default scripts
- Output: `nmap_rawReport.xml`

### 4. FFUF (1–10 min)
Directory brute-force against discovered endpoints. Filters out 403/404/429/500/503. Output: `ffuf_rawReport.json`.

### 5. Report Generation (< 1 min)
Auto-runs `python3 report.py ./<domain>/` to compile all JSON/XML into `vulnReport.html`.

## Requirements

| Tool | Install |
|---|---|
| `whatweb` | `sudo apt install whatweb` |
| `nmap` | `sudo apt install nmap` |
| `ffuf` | `go install github.com/ffuf/ffuf/v2@latest` |
| `python3` | Required for report generation |
| `dig` or `nslookup` | Pre-installed on most distros |
| `xmlstarlet` | Optional — for scan summary (`sudo apt install xmlstarlet`) |

## Notes

- The script is designed to run from inside the `vulv2/` directory
- ffuf uses the wordlist at `/home/kali/wordlist/pblist/fuzzing/common.txt` — update this path for your environment (line 199)
- nikto, nuclei, and wpscan are commented out — uncomment if needed
- Proxy support: `http://`, `https://`, `socks4://`, `socks5://` all normalized to `http://`
- nmap `--proxies` only affects HTTP probes, not SYN scan — true port scanning bypasses proxy
- The script exits with error if no open ports are found