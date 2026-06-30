#!/usr/bin/env python3
"""
fingerprint_report.py - Cyber Samurai Fingerprint & Vulnerability Report Generator
=============================================================================
Parses nmap_scan.xml, dirsearch_results.json, and whatWebResult.json to
extract actionable security findings, then compiles a professional HTML report
styled with the Cyber Samurai global_report.css theme.

Usage:
    python fingerprint_report.py
    (defaults: reads from vuln_report_function/ folder, outputs fingerprintReport.html)
"""

import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from html import escape as html_escape

# ─── Configuration ───────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NMAP_FILE = os.path.join(BASE_DIR, "nmap_scan.xml")
DIRSEARCH_FILE = os.path.join(BASE_DIR, "dirsearch_results.json")
WHATWEB_FILE = os.path.join(BASE_DIR, "whatWebResult.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "fingerprintReport.html")
CSS_PATH = os.path.join(BASE_DIR, "..", "reference", "global_report.css")
REPORT_TITLE = "Cyber Samurai — Fingerprint & Security Assessment Report"
SCAN_DATE = datetime.now().strftime("%d %B %Y, %H:%M")


# ─── Nmap Parsing ────────────────────────────────────────────────────────────

def parse_nmap_scan(file_path):
    """
    Parse nmap_scan.xml and extract:
      - Scan metadata (target, args, start/end time)
      - Open ports with service details
      - Discovered vulnerabilities (Slowloris, missing HSTS)
      - Security headers per port
      - Unusual port detections
      - Host information (uptime, distance, traceroute)

    Returns a structured dictionary.
    """
    if not os.path.exists(file_path):
        print(f"[-] Nmap XML not found: {file_path}")
        return None

    tree = ET.parse(file_path)
    root = tree.getroot()

    # ── Scan metadata ──
    scan_info = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", "N/A"),
        "start_time": root.get("startstr", "Unknown"),
        "version": root.get("version", "Unknown"),
    }

    # Finish time
    finish_el = root.find(".//finished")
    if finish_el is not None:
        scan_info["end_time"] = finish_el.get("timestr", "Unknown")
        scan_info["elapsed"] = finish_el.get("elapsed", "N/A")

    # Summary
    hosts_up = root.find(".//hosts")
    if hosts_up is not None:
        scan_info["hosts_up"] = hosts_up.get("up", "0")
        scan_info["hosts_total"] = hosts_up.get("total", "0")

    # ── Host data ──
    host_data = {
        "ip": "Unknown",
        "status": "unknown",
        "open_ports": [],
        "vulnerabilities": [],
        "security_notes": [],
        "unusual_ports": [],
        "extra_ports": {"filtered": 0, "filtered_ranges": []},
        "uptime": None,
        "distance": None,
        "traceroute": [],
        "dns_info": None,
        "asn_info": None,
    }

    # Find the first "up" host, fall back to first host
    host_el = None
    for h in root.findall(".//host"):
        st = h.find("status")
        if st is not None and st.get("state") == "up":
            host_el = h
            break
    if host_el is None:
        host_el = root.find(".//host")

    if host_el is not None:
        # IP address
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is not None:
            host_data["ip"] = addr_el.get("addr", "Unknown")

        # Status
        status_el = host_el.find("status")
        if status_el is not None:
            host_data["status"] = status_el.get("state", "unknown")

        # ── Parse open ports ──
        ports_el = host_el.find("ports")
        if ports_el is not None:
            # Extra ports (filtered)
            extra_el = ports_el.find("extraports")
            if extra_el is not None:
                host_data["extra_ports"]["filtered"] = int(
                    extra_el.get("count", 0)
                )
                host_data["extra_ports"]["filtered_ranges"] = (
                    extra_el.get("ports", "").split(",")
                )

            # Open ports
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_id = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")

                svc_el = port_el.find("service")
                service_name = ""
                service_product = ""
                service_tunnel = ""
                service_cpe = ""
                if svc_el is not None:
                    service_name = svc_el.get("name", "")
                    service_product = svc_el.get("product", "")
                    service_tunnel = svc_el.get("tunnel", "")
                    service_cpe = svc_el.get("cpe", "")

                # Parse scripts attached to this port
                port_scripts = {}
                vulns_found = []
                security_headers = {}
                unusual_flag = False

                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    script_output = script_el.get("output", "")

                    # ── Vulnerability detection ──
                    if script_id == "http-slowloris-check" and "VULNERABLE" in script_output:
                        # Extract CVE details from structured elements
                        cve_id = ""
                        cve_title = ""
                        cve_state = ""
                        cve_desc = ""
                        cve_refs = []

                        for table_el in script_el.findall(".//table"):
                            for elem_el in table_el.findall("elem"):
                                key = elem_el.get("key", "")
                                text = (elem_el.text or "").strip()
                                if key == "title":
                                    cve_title = text
                                elif key == "state":
                                    cve_state = text

                        # Get CVE IDs
                        ids_table = script_el.find(".//table[@key='ids']")
                        if ids_table is not None:
                            for e in ids_table.findall("elem"):
                                cve_id = (e.text or "").strip()

                        # Get description
                        desc_table = script_el.find(
                            ".//table[@key='description']"
                        )
                        if desc_table is not None:
                            desc_el = desc_table.find("elem")
                            if desc_el is not None:
                                cve_desc = (desc_el.text or "").strip()

                        # Get references
                        refs_table = script_el.find(".//table[@key='refs']")
                        if refs_table is not None:
                            for e in refs_table.findall("elem"):
                                cve_refs.append((e.text or "").strip())

                        vulns_found.append({
                            "type": "Vulnerability",
                            "script_id": script_id,
                            "cve_id": cve_id,
                            "title": cve_title,
                            "state": cve_state,
                            "description": cve_desc,
                            "references": cve_refs,
                        })

                    # ── Missing HSTS ──
                    if script_id == "http-security-headers":
                        if "HSTS not configured" in script_output:
                            vulns_found.append({
                                "type": "Missing Header",
                                "script_id": script_id,
                                "cve_id": "N/A",
                                "title": "HTTP Strict Transport Security (HSTS) Not Configured",
                                "state": "MISSING",
                                "description": (
                                    "HSTS is not enabled on this HTTPS port. "
                                    "Without HSTS, browsers may connect over "
                                    "unencrypted HTTP, exposing users to "
                                    "man-in-the-middle downgrade attacks."
                                ),
                                "references": [
                                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                                ],
                            })

                        # Extract present security headers
                        for table_el in script_el.findall("table"):
                            table_key = table_el.get("key", "")
                            for elem_el in table_el.findall("elem"):
                                text = (elem_el.text or "").strip()
                                if text and "not configured" not in text.lower():
                                    if table_key not in security_headers:
                                        security_headers[table_key] = []
                                    security_headers[table_key].append(text)

                    # ── Unusual port detection ──
                    if script_id == "unusual-port":
                        unusual_flag = True

                    # Store all scripts
                    port_scripts[script_id] = {
                        "output": script_output,
                        "id": script_id,
                    }

                port_info = {
                    "port": port_id,
                    "protocol": protocol,
                    "service_name": service_name,
                    "service_product": service_product,
                    "service_tunnel": service_tunnel,
                    "service_cpe": service_cpe,
                    "is_ssl": service_tunnel == "ssl",
                    "vulnerabilities": vulns_found,
                    "security_headers": security_headers,
                    "unusual": unusual_flag,
                }
                host_data["open_ports"].append(port_info)

                if unusual_flag:
                    host_data["unusual_ports"].append(port_id)

            # Collect all vulnerabilities
            for port_info in host_data["open_ports"]:
                for vuln in port_info.get("vulnerabilities", []):
                    if vuln not in host_data["vulnerabilities"]:
                        host_data["vulnerabilities"].append(vuln)

            # Collect security notes (headers summary)
            for port_info in host_data["open_ports"]:
                if port_info["security_headers"]:
                    note = {
                        "port": port_info["port"],
                        "headers": port_info["security_headers"],
                    }
                    host_data["security_notes"].append(note)

        # ── Uptime ──
        uptime_el = host_el.find("uptime")
        if uptime_el is not None:
            host_data["uptime"] = {
                "seconds": uptime_el.get("seconds", "0"),
                "lastboot": uptime_el.get("lastboot", "Unknown"),
            }

        # ── Distance ──
        dist_el = host_el.find("distance")
        if dist_el is not None:
            host_data["distance"] = dist_el.get("value", "N/A")

        # ── Traceroute ──
        trace_el = host_el.find("trace")
        if trace_el is not None:
            for hop_el in trace_el.findall("hop"):
                host_data["traceroute"].append({
                    "ttl": hop_el.get("ttl", "?"),
                    "ip": hop_el.get("ipaddr", "?"),
                    "rtt": hop_el.get("rtt", "?"),
                    "hostname": hop_el.get("host", ""),
                })

        # ── Host scripts ──
        host_scripts_el = host_el.find("hostscript")
        if host_scripts_el is not None:
            for script_el in host_scripts_el.findall("script"):
                sid = script_el.get("id", "")
                output = script_el.get("output", "")
                if sid == "asn-query" and output:
                    host_data["asn_info"] = output.strip()
                elif sid == "fcrdns":
                    host_data["dns_info"] = output.strip()

    return {
        "scan_info": scan_info,
        "host": host_data,
    }


# ─── Dirsearch Parsing ───────────────────────────────────────────────────────

def parse_dirsearch_results(file_path):
    """
    Parse dirsearch_results.json and extract:
      - Scan metadata (command, timestamp)
      - True positive findings (non-404 status codes)
      - .git exposure summary
      - Statistics (total scanned, breakdown by status code)

    Returns a structured dictionary.
    """
    if not os.path.exists(file_path):
        print(f"[-] Dirsearch JSON not found: {file_path}")
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    scan_info = data.get("info", {})
    all_results = data.get("results", [])

    # Classify results
    true_positives = []
    false_positives = []
    git_exposure = []
    status_counts = {}

    for entry in all_results:
        status = entry.get("status", 0)
        url = entry.get("url", "")
        content_type = entry.get("content-type", "")
        content_length = entry.get("content-length", 0)
        redirect = entry.get("redirect", "")

        status_counts[status] = status_counts.get(status, 0) + 1

        parsed = {
            "status": status,
            "url": url,
            "content_type": content_type,
            "content_length": content_length,
            "redirect": redirect if redirect else None,
        }

        # True positives: anything not 404
        if status != 404:
            true_positives.append(parsed)
            # Flag .git exposure
            if "/.git" in url or "/.github" in url:
                git_exposure.append(parsed)
        else:
            false_positives.append(parsed)

    # ── Summarize .git exposure ──
    git_summary = _summarize_git_exposure(git_exposure)

    return {
        "scan_info": scan_info,
        "total_results": len(all_results),
        "true_positives_count": len(true_positives),
        "false_positives_count": len(false_positives),
        "status_counts": status_counts,
        "true_positives": true_positives,
        "git_exposure": git_exposure,
        "git_summary": git_summary,
    }


def _summarize_git_exposure(git_entries):
    """Produce a human-readable summary of .git directory exposure."""
    if not git_entries:
        return None

    exposed_files = []
    directory_listings = []
    forbidden_dirs = []

    for entry in git_entries:
        url = entry["url"]
        status = entry["status"]
        path = url.split(".git")[-1] if ".git" in url else url

        if status == 200:
            exposed_files.append({
                "url": url,
                "path": path,
                "size_bytes": entry["content_length"],
                "content_type": entry["content_type"],
            })
        elif status == 301:
            directory_listings.append({
                "url": url,
                "path": path,
                "redirect": entry.get("redirect", ""),
            })
        elif status == 403:
            forbidden_dirs.append({
                "url": url,
                "path": path,
            })

    risk_level = "HIGH"
    if exposed_files:
        has_index = any("index" in f["path"] for f in exposed_files)
        has_config = any("config" in f["path"] for f in exposed_files)
        if has_index and has_config:
            risk_level = "CRITICAL"
        elif has_config or has_index:
            risk_level = "HIGH"

    return {
        "risk_level": risk_level,
        "exposed_file_count": len(exposed_files),
        "exposed_files": exposed_files,
        "directory_listings": directory_listings,
        "forbidden_dirs": forbidden_dirs,
        "total_git_hits": len(git_entries),
        "summary_text": (
            f"The target's .git directory is publicly accessible. "
            f"{len(exposed_files)} Git repository files are directly "
            f"downloadable, potentially exposing source code, "
            f"configuration secrets, and commit history. "
            f"This is a {risk_level} severity finding."
        ),
    }


# ─── WhatWeb Parsing ─────────────────────────────────────────────────────────

def parse_whatweb_results(file_path):
    """
    Parse whatWebResult.json and extract:
      - Target URL and HTTP status
      - Technology stack fingerprint
      - Server headers
      - Page metadata (title, encoding, etc.)

    Returns a structured dictionary.
    """
    if not os.path.exists(file_path):
        print(f"[-] WhatWeb JSON not found: {file_path}")
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []

    for entry in data:
        target = entry.get("target", "Unknown")
        http_status = entry.get("http_status", 0)
        plugins = entry.get("plugins", {})

        # Flatten plugins into readable findings
        tech_stack = []
        server_info = {}
        page_metadata = {}

        for plugin_name, plugin_data in plugins.items():
            finding = {
                "plugin": plugin_name,
                "strings": plugin_data.get("string", []),
                "module": plugin_data.get("module", []),
            }

            # Categorize
            if plugin_name in ("HTTPServer", "IP", "CloudFlare"):
                if plugin_name == "HTTPServer":
                    server_info["server"] = (
                        plugin_data.get("string", ["Unknown"])[0]
                    )
                elif plugin_name == "IP":
                    server_info["ip"] = (
                        plugin_data.get("string", ["Unknown"])[0]
                    )
                elif plugin_name == "CloudFlare":
                    server_info["cdn"] = "Cloudflare"
            elif plugin_name in ("Title", "X-UA-Compatible", "HTML5"):
                if plugin_name == "Title":
                    page_metadata["title"] = (
                        plugin_data.get("string", ["Untitled"])[0]
                    )
                elif plugin_name == "X-UA-Compatible":
                    page_metadata["x_ua_compatible"] = (
                        plugin_data.get("string", ["N/A"])[0]
                    )
                elif plugin_name == "HTML5":
                    page_metadata["html5"] = True
            else:
                tech_stack.append(finding)

            findings.append(finding)

        return {
            "target": target,
            "http_status": http_status,
            "server_info": server_info,
            "page_metadata": page_metadata,
            "technology_stack": tech_stack,
            "all_plugins": plugins,
        }

    return None


# ─── HTML Report Builder ─────────────────────────────────────────────────────

def build_html_report(nmap_data, dirsearch_data, whatweb_data, output_path):
    """
    Compile all parsed findings into a professional HTML report
    styled with the Cyber Samurai global_report.css theme.

    The report includes:
      - Executive summary / hero section
      - Open ports & services table
      - Vulnerability findings
      - .git exposure details
      - Technology fingerprint
      - Security header analysis
    """
    # Derive overall risk score
    risk_score, risk_label = _calculate_risk_score(
        nmap_data, dirsearch_data, whatweb_data
    )

    # ── Determine scan target ──
    target_ip = "Unknown"
    target_hostname = "Unknown"
    if nmap_data and nmap_data.get("host"):
        target_ip = nmap_data["host"]["ip"]
    if whatweb_data:
        target_hostname = whatweb_data.get("target", "Unknown")

    scan_start = "Unknown"
    if nmap_data and nmap_data.get("scan_info"):
        scan_start = nmap_data["scan_info"].get("start_time", "Unknown")
    if dirsearch_data and dirsearch_data.get("scan_info"):
        ds_time = dirsearch_data["scan_info"].get("time", "")
        if ds_time:
            # Format: "Tue Jun 30 18:19:53 2026"
            scan_start = ds_time

    # Resolve CSS path relative to output
    css_relative = os.path.relpath(CSS_PATH, os.path.dirname(output_path))
    css_relative = css_relative.replace("\\", "/")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{REPORT_TITLE}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Outfit:wght@500;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="{css_relative}">
    <style>
        /* ---- Report-specific extensions ---- */
        .finding-severity-critical {{ border-left: 3px solid var(--color-critical) !important; }}
        .finding-severity-high {{ border-left: 3px solid var(--color-warning) !important; }}
        .finding-severity-medium {{ border-left: 3px solid var(--color-info) !important; }}
        .finding-severity-low {{ border-left: 3px solid var(--color-pass) !important; }}

        .section-title {{
            font-family: 'Outfit', sans-serif;
            font-size: 22px;
            font-weight: 700;
            margin: 36px 0 16px 0;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .section-title::before {{
            content: '';
            display: inline-block;
            width: 5px;
            height: 20px;
            background: var(--accent-red);
            border-radius: 2px;
        }}

        .finding-row {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 12px 0;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            gap: 12px;
        }}
        .finding-row:last-child {{ border-bottom: none; }}
        .finding-label {{
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            min-width: 100px;
        }}
        .finding-value {{
            color: var(--text-primary);
            font-size: 13.5px;
            font-family: monospace;
            word-break: break-all;
            flex: 1;
        }}

        .port-badge {{
            display: inline-block;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border-color);
            padding: 3px 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            color: var(--text-primary);
            margin: 2px 4px;
        }}
        .port-badge.ssl {{ border-color: var(--color-info); color: var(--color-info); }}

        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        .data-table th {{
            text-align: left;
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        .data-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            color: var(--text-secondary);
            vertical-align: top;
        }}
        .data-table tr:hover td {{
            background: rgba(255,255,255,0.01);
        }}
        .data-table .mono {{
            font-family: monospace;
            color: var(--text-primary);
        }}

        .exposure-card {{
            background: var(--card-bg);
            backdrop-filter: var(--glass-blur);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 18px 20px;
            margin-bottom: 12px;
        }}
        .exposure-card.exposed-file {{
            border-left: 3px solid var(--color-critical);
        }}
        .exposure-card.dir-listing {{
            border-left: 3px solid var(--color-warning);
        }}
        .exposure-card.forbidden {{
            border-left: 3px solid var(--color-info);
        }}

        .highlight-box {{
            background: rgba(255,46,59,0.06);
            border: 1px solid rgba(255,46,59,0.15);
            border-radius: 8px;
            padding: 16px 20px;
            margin: 12px 0;
            font-size: 13.5px;
            line-height: 1.65;
            color: var(--text-secondary);
        }}

        .tech-tag {{
            display: inline-block;
            background: rgba(59,130,246,0.1);
            border: 1px solid rgba(59,130,246,0.25);
            color: var(--color-info);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin: 3px 4px;
        }}

        .summary-stat {{
            text-align: center;
            padding: 20px 12px;
        }}
        .summary-stat .stat-number {{
            font-family: 'Outfit', sans-serif;
            font-size: 28px;
            font-weight: 800;
            line-height: 1;
        }}
        .summary-stat .stat-desc {{
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        /* Print styles */
        @media print {{
            body {{ background: #fff; color: #000; }}
            .glass-card {{ background: #f8f8f8; border: 1px solid #ddd; box-shadow: none; }}
            .btn-print {{ display: none; }}
        }}

        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}
        .collapsible::after {{
            content: ' \\25BC';
            font-size: 10px;
            color: var(--text-muted);
        }}
        .collapsible.open::after {{
            content: ' \\25B2';
        }}
        .collapsible-content {{
            display: none;
            padding-top: 12px;
        }}
        .collapsible-content.open {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="container">

        <!-- ═══ Header Bar ═══ -->
        <div class="header-bar">
            <div class="brand">
                <span class="brand-logo">CYBER<span>SAMURAI</span></span>
                <span class="brand-japanese">サイバー侍</span>
            </div>
            <button class="btn-print" onclick="window.print()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9V2h12v7M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
                Print Report
            </button>
        </div>

        <!-- ═══ Hero Section ═══ -->
        <div class="hero-section">
            <div class="hero-overlay"></div>
            <div class="hero-content">
                <div class="hero-tagline">Security Fingerprint Assessment</div>
                <h1 class="hero-title">Fingerprint &amp;<br>Vulnerability Report</h1>
                <div class="hero-meta">
                    <div class="meta-item">
                        <span class="meta-label">Target</span>
                        <span class="meta-val">{html_escape(target_hostname)}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">IP Address</span>
                        <span class="meta-val">{html_escape(target_ip)}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Scan Date</span>
                        <span class="meta-val">{html_escape(scan_start)}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Report Generated</span>
                        <span class="meta-val">{html_escape(SCAN_DATE)}</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- ═══ Dashboard Summary ═══ -->
        <div class="dashboard-grid">
            <div class="glass-card card-red">
                <div class="card-title">Overall Risk Score</div>
                <div class="health-score-container">
                    <span class="score-num" style="color:{_risk_color(risk_score)}">{risk_score}%</span>
                    <span class="score-label" style="color:{_risk_color(risk_score)}">{risk_label}</span>
                </div>
                <div class="stat-grid" style="margin-top:16px">
                    <div class="stat-card">
                        <span class="stat-val stat-critical">{_vuln_count(nmap_data)}</span>
                        <span class="stat-lbl">Vulnerabilities</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-info">{_open_port_count(nmap_data)}</span>
                        <span class="stat-lbl">Open Ports</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-warning">{_git_exposed_count(dirsearch_data)}</span>
                        <span class="stat-lbl">.git Files Exposed</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-pass">{_tech_count(whatweb_data)}</span>
                        <span class="stat-lbl">Technologies</span>
                    </div>
                </div>
            </div>

            <div class="glass-card card-blue">
                <div class="card-title">Key Findings Summary</div>
                {_build_key_findings(nmap_data, dirsearch_data, whatweb_data)}
            </div>
        </div>

        <!-- ═══ Section: Open Ports & Services ═══ -->
        <h2 class="section-title">Open Ports &amp; Services</h2>
        {_build_ports_section(nmap_data)}

        <!-- ═══ Section: Vulnerability Findings ═══ -->
        <h2 class="section-title">Vulnerability Findings</h2>
        {_build_vulnerabilities_section(nmap_data)}

        <!-- ═══ Section: Directory Enumeration ═══ -->
        <h2 class="section-title">Directory &amp; File Enumeration</h2>
        {_build_dirsearch_section(dirsearch_data)}

        <!-- ═══ Section: .git Exposure Details ═══ -->
        {_build_git_exposure_section(dirsearch_data)}

        <!-- ═══ Section: Technology Fingerprint ═══ -->
        <h2 class="section-title">Technology Fingerprint</h2>
        {_build_tech_fingerprint_section(whatweb_data)}

        <!-- ═══ Section: Security Header Analysis ═══ -->
        <h2 class="section-title">Security Header Analysis</h2>
        {_build_security_headers_section(nmap_data)}

        <!-- ═══ Footer ═══ -->
        <div class="footer">
            <p>Cyber Samurai &mdash; Fingerprint &amp; Vulnerability Assessment Report</p>
            <p style="font-size:11px;margin-top:4px">Generated on {html_escape(SCAN_DATE)} | This report contains confidential security findings.</p>
        </div>
    </div>

    <script>
        // Collapsible sections
        document.querySelectorAll('.collapsible').forEach(el => {{
            el.addEventListener('click', function() {{
                this.classList.toggle('open');
                this.nextElementSibling.classList.toggle('open');
            }});
        }});
        // Open first collapsible by default
        document.querySelectorAll('.collapsible-content').forEach(el => el.classList.add('open'));
    </script>
</body>
</html>
"""

    # Write output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Report compiled successfully: {output_path}")
    return html


# ─── Helper: Risk Calculation ────────────────────────────────────────────────

def _risk_color(score):
    if score >= 70:
        return "var(--color-critical)"
    elif score >= 40:
        return "var(--color-warning)"
    return "var(--color-pass)"


def _calculate_risk_score(nmap_data, dirsearch_data, whatweb_data):
    """Compute a weighted risk score 0-100 from findings."""
    score = 0

    # Nmap vulnerabilities
    if nmap_data and nmap_data.get("host"):
        vulns = nmap_data["host"].get("vulnerabilities", [])
        for v in vulns:
            if v.get("state") == "LIKELY VULNERABLE":
                score += 12
            elif v.get("state") == "MISSING":
                score += 8

        # Unusual ports
        unusual = nmap_data["host"].get("unusual_ports", [])
        score += len(unusual) * 2

        # Open ports beyond standard
        open_ports = nmap_data["host"].get("open_ports", [])
        standard = {80, 443}
        non_standard = [p for p in open_ports if p["port"] not in standard]
        score += len(non_standard) * 3

    # .git exposure
    if dirsearch_data and dirsearch_data.get("git_exposure"):
        score += len(dirsearch_data["git_exposure"]) * 2
        if dirsearch_data.get("git_summary"):
            if dirsearch_data["git_summary"]["risk_level"] == "CRITICAL":
                score += 25
            elif dirsearch_data["git_summary"]["risk_level"] == "HIGH":
                score += 15

    score = min(score, 100)

    if score >= 70:
        label = "CRITICAL"
    elif score >= 40:
        label = "ELEVATED"
    elif score >= 15:
        label = "MODERATE"
    else:
        label = "LOW"

    return score, label


def _vuln_count(nmap_data):
    if nmap_data and nmap_data.get("host"):
        return len(nmap_data["host"].get("vulnerabilities", []))
    return 0


def _open_port_count(nmap_data):
    if nmap_data and nmap_data.get("host"):
        return len(nmap_data["host"].get("open_ports", []))
    return 0


def _git_exposed_count(dirsearch_data):
    if dirsearch_data and dirsearch_data.get("git_exposure"):
        return len(dirsearch_data["git_exposure"])
    return 0


def _tech_count(whatweb_data):
    if whatweb_data and whatweb_data.get("technology_stack"):
        return len(whatweb_data["technology_stack"])
    return 0


# ─── HTML Section Builders ───────────────────────────────────────────────────

def _build_key_findings(nmap_data, dirsearch_data, whatweb_data):
    """Build the key findings summary for the dashboard."""
    items = []

    # .git exposure
    if dirsearch_data and dirsearch_data.get("git_summary"):
        summary = dirsearch_data["git_summary"]
        items.append(f"""
            <div class="finding-row finding-severity-critical">
                <span class="finding-label">Git Exposure</span>
                <span class="finding-value">
                    <span class="badge badge-red">{summary['risk_level']}</span>
                    &nbsp;{summary['exposed_file_count']} Git files publicly accessible
                    &mdash; source code and config leakage risk.
                </span>
            </div>
        """)

    # Vulnerabilities from nmap
    if nmap_data and nmap_data.get("host"):
        vulns = nmap_data["host"].get("vulnerabilities", [])
        for v in vulns:
            sev = "badge-red" if "VULNERABLE" in v.get("state", "") else "badge-yellow"
            items.append(f"""
                <div class="finding-row finding-severity-high">
                    <span class="finding-label">Vulnerability</span>
                    <span class="finding-value">
                        <span class="badge {sev}">{v.get('state', 'FOUND')}</span>
                        &nbsp;{html_escape(v.get('title', 'Unknown finding'))}
                        {f"&nbsp;(<code>{html_escape(v.get('cve_id', ''))}</code>)" if v.get('cve_id') and v['cve_id'] != 'N/A' else ""}
                    </span>
                </div>
            """)

    # Unusual ports
    if nmap_data and nmap_data.get("host"):
        unusual = nmap_data["host"].get("unusual_ports", [])
        if unusual:
            items.append(f"""
                <div class="finding-row finding-severity-medium">
                    <span class="finding-label">Unusual Ports</span>
                    <span class="finding-value">
                        <span class="badge badge-blue">INFO</span>
                        &nbsp;{len(unusual)} non-standard HTTP ports detected: {', '.join(str(p) for p in unusual)}
                    </span>
                </div>
            """)

    # WhatWeb tech count
    if whatweb_data:
        tech = whatweb_data.get("technology_stack", [])
        if tech:
            tech_names = [t["plugin"] for t in tech]
            items.append(f"""
                <div class="finding-row finding-severity-low">
                    <span class="finding-label">Tech Stack</span>
                    <span class="finding-value">
                        <span class="badge badge-green">DETECTED</span>
                        &nbsp;{', '.join(tech_names)}
                    </span>
                </div>
            """)

    if not items:
        items.append('<p class="summary-text">No significant findings detected.</p>')

    return "\n".join(items)


def _build_ports_section(nmap_data):
    """Build the open ports table."""
    if not nmap_data or not nmap_data.get("host"):
        return '<div class="glass-card"><p class="summary-text">No port scan data available.</p></div>'

    host = nmap_data["host"]
    ports = host.get("open_ports", [])

    if not ports:
        return '<div class="glass-card"><p class="summary-text">No open ports detected.</p></div>'

    rows = ""
    for p in sorted(ports, key=lambda x: x["port"]):
        ssl_badge = '<span class="port-badge ssl">SSL/TLS</span>' if p["is_ssl"] else ""
        unusual_badge = '<span class="badge badge-yellow" style="font-size:10px">UNUSUAL</span>' if p["unusual"] else ""
        vuln_badge = ""
        if p.get("vulnerabilities"):
            vuln_badge = f'<span class="badge badge-red" style="font-size:10px">{len(p["vulnerabilities"])} FINDING(S)</span>'

        rows += f"""
            <tr>
                <td class="mono"><strong>{p['port']}/{p['protocol']}</strong></td>
                <td>{html_escape(p['service_name'])}</td>
                <td>{html_escape(p['service_product'])}</td>
                <td>{ssl_badge} {unusual_badge} {vuln_badge}</td>
            </tr>
        """

    return f"""
    <div class="glass-card">
        <div class="card-title">Discovered Services ({len(ports)} open ports)</div>
        <p class="summary-text" style="margin-bottom:12px">
            Nmap detected <strong>{len(ports)} open ports</strong> on {html_escape(host['ip'])}
            with <strong>{host['extra_ports']['filtered']:,} filtered ports</strong>.
            The target is behind Cloudflare's network (AS13335).
        </p>
        <div style="overflow-x:auto">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Flags</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </div>
    """


def _build_vulnerabilities_section(nmap_data):
    """Build the vulnerabilities findings section."""
    if not nmap_data or not nmap_data.get("host"):
        return '<div class="glass-card"><p class="summary-text">No vulnerability data available.</p></div>'

    vulns = nmap_data["host"].get("vulnerabilities", [])

    if not vulns:
        return """
        <div class="glass-card card-green">
            <div class="card-title">No Critical Vulnerabilities</div>
            <p class="summary-text">Nmap vulnerability scripts did not detect any exploitable vulnerabilities on the target host.</p>
        </div>
        """

    # Deduplicate by title
    seen = set()
    unique_vulns = []
    for v in vulns:
        key = v.get("title", "") + v.get("cve_id", "")
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    cards = ""
    for v in unique_vulns:
        sev_class = "card-red" if "VULNERABLE" in v.get("state", "") else "card-orange"
        refs_html = ""
        if v.get("references"):
            refs_html = "<br>".join(
                f'<a href="{html_escape(r)}" target="_blank" style="color:var(--color-info)">{html_escape(r)}</a>'
                for r in v["references"]
            )

        cards += f"""
        <div class="glass-card {sev_class}">
            <div class="card-title">{html_escape(v.get('title', 'Unknown Finding'))}</div>
            <div style="margin:8px 0">
                <span class="badge badge-red">{html_escape(v.get('state', 'FOUND'))}</span>
                {f'<code style="margin-left:8px;color:var(--text-muted)">{html_escape(v.get("cve_id", ""))}</code>' if v.get('cve_id') and v['cve_id'] != 'N/A' else ''}
            </div>
            <p class="summary-text">{html_escape(v.get('description', 'No description available.'))}</p>
            {f'<div style="margin-top:10px;font-size:12px;color:var(--text-muted)"><strong>References:</strong><br>{refs_html}</div>' if refs_html else ''}
        </div>
        """

    # Also add HSTS findings summary
    hsts_missing_ports = []
    if nmap_data.get("host", {}).get("open_ports"):
        for port_info in nmap_data["host"]["open_ports"]:
            for vuln in port_info.get("vulnerabilities", []):
                if "HSTS" in vuln.get("title", ""):
                    hsts_missing_ports.append(str(port_info["port"]))

    if hsts_missing_ports:
        cards += f"""
        <div class="glass-card card-orange">
            <div class="card-title">HSTS Missing on HTTPS Ports</div>
            <p class="summary-text">
                HTTP Strict Transport Security (HSTS) is not configured on the following
                HTTPS-enabled ports: <strong>{', '.join(hsts_missing_ports)}</strong>.
                Without HSTS, users are vulnerable to SSL stripping and man-in-the-middle
                downgrade attacks.
            </p>
            <p style="font-size:12px;color:var(--text-muted);margin-top:8px">
                <strong>Recommendation:</strong> Add the
                <code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code>
                header to all HTTPS responses.
            </p>
        </div>
        """

    return cards


def _build_dirsearch_section(dirsearch_data):
    """Build directory enumeration results summary."""
    if not dirsearch_data:
        return '<div class="glass-card"><p class="summary-text">No directory scan data available.</p></div>'

    tp_count = dirsearch_data.get("true_positives_count", 0)
    fp_count = dirsearch_data.get("false_positives_count", 0)
    total = dirsearch_data.get("total_results", 0)

    # Status code breakdown
    status_html = ""
    for status, count in sorted(dirsearch_data.get("status_counts", {}).items()):
        badge_class = "badge-red" if status == 200 else (
            "badge-yellow" if status in (301, 403) else "badge-blue"
        )
        status_html += f'<span class="badge {badge_class}">{status}: {count}</span> '

    # True positives table
    tp = dirsearch_data.get("true_positives", [])
    tp_rows = ""
    for entry in tp[:100]:  # Limit to 100 rows to keep report manageable
        sc = entry["status"]
        sc_badge = "badge-red" if sc == 200 else "badge-yellow"
        tp_rows += f"""
            <tr>
                <td><span class="badge {sc_badge}" style="font-size:10px">{sc}</span></td>
                <td class="mono" style="font-size:11px">{html_escape(entry['url'])}</td>
                <td>{html_escape(entry.get('content_type', ''))}</td>
                <td>{entry.get('content_length', 0):,}</td>
            </tr>
        """

    if len(tp) > 100:
        tp_rows += f'<tr><td colspan="4" style="color:var(--text-muted);text-align:center">... and {len(tp) - 100} more findings</td></tr>'

    return f"""
    <div class="glass-card">
        <div class="card-title">Dirsearch Scan Results</div>
        <p class="summary-text" style="margin-bottom:12px">
            Scanned <strong>{total:,} paths</strong> on the target.
            <strong style="color:var(--color-critical)">{tp_count} true positive hits</strong>
            (non-404 responses) and {fp_count:,} false positives (404).
        </p>
        <div style="margin-bottom:12px">
            <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px">Status Breakdown: </span>
            {status_html}
        </div>
        <div style="overflow-x:auto;max-height:500px;overflow-y:auto">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>URL</th>
                        <th>Content Type</th>
                        <th>Size (bytes)</th>
                    </tr>
                </thead>
                <tbody>
                    {tp_rows}
                </tbody>
            </table>
        </div>
    </div>
    """


def _build_git_exposure_section(dirsearch_data):
    """Build detailed .git exposure section."""
    if not dirsearch_data or not dirsearch_data.get("git_summary"):
        return ""

    summary = dirsearch_data["git_summary"]
    risk_class = "card-red" if summary["risk_level"] == "CRITICAL" else "card-orange"

    # Exposed files
    exposed_html = ""
    for f in summary.get("exposed_files", []):
        exposed_html += f"""
        <div class="exposure-card exposed-file">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <strong style="font-family:monospace;font-size:12px;color:var(--color-critical)">{html_escape(f['path'])}</strong>
                <span class="badge badge-red">EXPOSED</span>
            </div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px">
                Size: {f['size_bytes']:,} bytes | Type: {html_escape(f['content_type'])}
            </div>
            <div style="font-size:11px;color:var(--text-muted);word-break:break-all;margin-top:2px">
                {html_escape(f['url'])}
            </div>
        </div>
        """

    # Directory listings
    for d in summary.get("directory_listings", []):
        exposed_html += f"""
        <div class="exposure-card dir-listing">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <strong style="font-family:monospace;font-size:12px;color:var(--color-warning)">{html_escape(d['path'])}</strong>
                <span class="badge badge-yellow">REDIRECT</span>
            </div>
            <div style="font-size:11px;color:var(--text-muted);word-break:break-all;margin-top:4px">
                Redirects to: {html_escape(d.get('redirect', ''))}
            </div>
        </div>
        """

    return f"""
    <h2 class="section-title">.git Repository Exposure <span class="badge badge-red">{summary['risk_level']}</span></h2>

    <div class="glass-card card-red">
        <div class="card-title">Critical Finding: Publicly Accessible Git Repository</div>
        <div class="highlight-box">
            {html_escape(summary['summary_text'])}
        </div>

        <h4 style="color:var(--text-secondary);font-size:14px;margin:16px 0 8px 0">
            Directly Accessible Files ({summary['exposed_file_count']} files)
        </h4>
        {exposed_html}

        <div class="highlight-box" style="margin-top:16px;background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15)">
            <strong style="color:var(--color-info)">Impact:</strong> An exposed .git directory
            allows attackers to download the entire Git repository history, including source code,
            hardcoded credentials, API keys, and historical changes. Tools like
            <code>git-dumper</code> can reconstruct the full repository.
        </div>
        <div class="highlight-box" style="background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.15)">
            <strong style="color:var(--color-pass)">Remediation:</strong>
            <ol style="margin:8px 0 0 16px;font-size:13px;color:var(--text-secondary)">
                <li>Block access to <code>/.git/</code> at the web server or WAF level</li>
                <li>Ensure <code>.git</code> is not deployed to production</li>
                <li>Rotate any credentials that may have been in the repository</li>
                <li>Review Git history for sensitive data with tools like <code>git-secrets</code></li>
            </ol>
        </div>
    </div>
    """


def _build_tech_fingerprint_section(whatweb_data):
    """Build technology fingerprint section."""
    if not whatweb_data:
        return '<div class="glass-card"><p class="summary-text">No technology fingerprint data available.</p></div>'

    tech_stack = whatweb_data.get("technology_stack", [])
    server_info = whatweb_data.get("server_info", {})
    page_meta = whatweb_data.get("page_metadata", {})

    tech_tags = ""
    for tech in tech_stack:
        strings = ", ".join(tech.get("strings", []))
        name = tech["plugin"]
        tech_tags += f'<span class="tech-tag">{html_escape(name)}</span> '

    rows = ""
    # Server info
    if server_info.get("server"):
        rows += f"""
            <tr>
                <td><strong>Server</strong></td>
                <td class="mono">{html_escape(server_info['server'])}</td>
            </tr>
        """
    if server_info.get("ip"):
        rows += f"""
            <tr>
                <td><strong>IP Address</strong></td>
                <td class="mono">{html_escape(server_info['ip'])}</td>
            </tr>
        """
    if server_info.get("cdn"):
        rows += f"""
            <tr>
                <td><strong>CDN / WAF</strong></td>
                <td class="mono">{html_escape(server_info['cdn'])}</td>
            </tr>
        """
    if page_meta.get("title"):
        rows += f"""
            <tr>
                <td><strong>Page Title</strong></td>
                <td>{html_escape(page_meta['title'])}</td>
            </tr>
        """
    if page_meta.get("x_ua_compatible"):
        rows += f"""
            <tr>
                <td><strong>X-UA-Compatible</strong></td>
                <td class="mono">{html_escape(page_meta['x_ua_compatible'])}</td>
            </tr>
        """
    if page_meta.get("html5"):
        rows += f"""
            <tr>
                <td><strong>HTML5</strong></td>
                <td><span class="badge badge-green">Yes</span></td>
            </tr>
        """

    # Uncommon headers
    all_plugins = whatweb_data.get("all_plugins", {})
    uncommon = all_plugins.get("UncommonHeaders", {})
    if uncommon.get("string"):
        rows += f"""
            <tr>
                <td><strong>Uncommon Headers</strong></td>
                <td class="mono" style="font-size:11px">{html_escape(', '.join(uncommon['string']))}</td>
            </tr>
        """

    return f"""
    <div class="glass-card">
        <div class="card-title">Web Technology Stack</div>
        <p class="summary-text" style="margin-bottom:12px">
            WhatWeb fingerprinting identified the following technologies and characteristics
            on <code>{html_escape(whatweb_data.get('target', 'Unknown'))}</code>.
        </p>
        <div style="margin-bottom:16px">
            <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px">Detected Technologies: </span>
            {tech_tags}
        </div>
        <table class="cert-table">
            {rows}
        </table>
    </div>
    """


def _build_security_headers_section(nmap_data):
    """Build security headers analysis section."""
    if not nmap_data or not nmap_data.get("host"):
        return '<div class="glass-card"><p class="summary-text">No header analysis available.</p></div>'

    ports = nmap_data["host"].get("open_ports", [])

    # Collect unique headers across all ports
    header_data = {}
    hsts_missing = []
    for port_info in ports:
        port_id = port_info["port"]
        headers = port_info.get("security_headers", {})
        if headers:
            header_data[port_id] = headers

        for vuln in port_info.get("vulnerabilities", []):
            if "HSTS" in vuln.get("title", ""):
                hsts_missing.append(port_id)

    if not header_data and not hsts_missing:
        return """
        <div class="glass-card card-blue">
            <div class="card-title">Security Headers</div>
            <p class="summary-text">No security headers were detected on any open port.</p>
        </div>
        """

    cards = ""

    # HSTS missing
    if hsts_missing:
        cards += f"""
        <div class="glass-card card-orange">
            <div class="card-title">Missing: HTTP Strict Transport Security (HSTS)</div>
            <p class="summary-text">
                <span class="badge badge-yellow">MISSING</span>
                &nbsp;HSTS is not configured on ports: <strong>{', '.join(str(p) for p in sorted(hsts_missing))}</strong>.
                This enables SSL stripping attacks.
            </p>
        </div>
        """

    # Present headers
    for port_id, headers in sorted(header_data.items()):
        header_rows = ""
        for header_name, values in headers.items():
            header_rows += f"""
                <tr>
                    <td><strong>{html_escape(header_name)}</strong></td>
                    <td class="mono" style="font-size:12px">{html_escape('; '.join(values))}</td>
                    <td><span class="badge badge-green">PRESENT</span></td>
                </tr>
            """

        cards += f"""
        <div class="glass-card card-green">
            <div class="card-title">Security Headers on Port {port_id}</div>
            <table class="data-table">
                <thead>
                    <tr><th>Header</th><th>Value</th><th>Status</th></tr>
                </thead>
                <tbody>
                    {header_rows}
                </tbody>
            </table>
        </div>
        """

    return cards


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    """Main entry point: parse all data sources and generate the report."""

    print("╔══════════════════════════════════════════════════╗")
    print("║   Cyber Samurai — Fingerprint Report Generator  ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    # ── Step 1: Parse Nmap XML ──
    print("[*] Parsing Nmap scan results...")
    nmap_data = parse_nmap_scan(NMAP_FILE)
    if nmap_data:
        open_ports = len(nmap_data.get("host", {}).get("open_ports", []))
        vulns = len(nmap_data.get("host", {}).get("vulnerabilities", []))
        print(f"    → Found {open_ports} open ports, {vulns} vulnerability findings")
    else:
        print("    ⚠ No Nmap data loaded")

    # ── Step 2: Parse Dirsearch JSON ──
    print("[*] Parsing Dirsearch results...")
    dirsearch_data = parse_dirsearch_results(DIRSEARCH_FILE)
    if dirsearch_data:
        tp = dirsearch_data.get("true_positives_count", 0)
        git = len(dirsearch_data.get("git_exposure", []))
        print(f"    → Found {tp} true positives, {git} .git exposure hits")
    else:
        print("    ⚠ No Dirsearch data loaded")

    # ── Step 3: Parse WhatWeb JSON ──
    print("[*] Parsing WhatWeb results...")
    whatweb_data = parse_whatweb_results(WHATWEB_FILE)
    if whatweb_data:
        tech_count = len(whatweb_data.get("technology_stack", []))
        print(f"    → Identified {tech_count} technologies on {whatweb_data.get('target', 'Unknown')}")
    else:
        print("    ⚠ No WhatWeb data loaded")

    # ── Step 4: Build HTML Report ──
    print(f"[*] Compiling HTML report → {OUTPUT_FILE}")
    build_html_report(nmap_data, dirsearch_data, whatweb_data, OUTPUT_FILE)

    # ── Summary ──
    print()
    print("════════════════════════════════════════════════")
    print("  Report generation complete.")
    print(f"  Output: {OUTPUT_FILE}")
    print("════════════════════════════════════════════════")


if __name__ == "__main__":
    main()
