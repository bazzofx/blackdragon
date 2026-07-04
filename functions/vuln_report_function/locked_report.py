#!/usr/bin/env python3
"""
Version :2.0
report.py - Cyber Samurai Fingerprint & Vulnerability Report Generator
=============================================================================
Parses nmap scan data, dirsearch results, and whatweb results to
extract actionable security findings, then compiles a professional HTML report
styled with the Cyber Samurai global_report.css theme.

Usage:
    python report.py <domain>
    (reads from vuln_report_function/<domain>/ folder)

    python report.py </absolute/path>
    (reads from the given path directly — used by fetchVuln.sh)

    python report.py
    (reads from vuln_report_function/ folder — legacy fallback)
"""

import os
import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from html import escape as html_escape

# ─── Configuration ───────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Accept domain or path as optional CLI argument
if len(sys.argv) > 1:
    domain_arg = sys.argv[1].strip()
    # If it's an absolute path, use it directly; otherwise treat as domain name
    if os.path.isabs(domain_arg):
        DATA_DIR = domain_arg
    else:
        DATA_DIR = os.path.join(BASE_DIR, domain_arg)
else:
    DATA_DIR = BASE_DIR

NMAP_FILE = os.path.join(DATA_DIR, "nmap_rawReport.xml")
DIRSEARCH_FILE = os.path.join(DATA_DIR, "dirsearch_rawReport.json")
WHATWEB_FILE = os.path.join(DATA_DIR, "whatweb_rawReport.json")
FFUF_FILE = os.path.join(DATA_DIR, "ffuf_rawReport.json")
OUTPUT_FILE = os.path.join(DATA_DIR, "vulnReport.html")
CSS_PATH = os.path.join(BASE_DIR, "..", "reference", "global_report.css")
REPORT_TITLE = "Cyber Samurai — Fingerprint & Security Assessment Report"
SCAN_DATE = datetime.now().strftime("%d %B %Y, %H:%M")
PAYWALL_PASSWORD = "cybersamurai2024"  # Change this to set the unlock password for gated content
FREE_PREVIEW_COUNT = 2  # Number of items shown free before paywall in each locked section


# ─── Nmap Parsing ────────────────────────────────────────────────────────────

def parse_nmap_scan(file_path):
    """
    Comprehensive Nmap XML parser. Extracts:
      - Scan metadata (scanner, args, timestamps)
      - Open ports with full service details (name, product, version, CPE, extrainfo)
      - Port-level scripts: vulners (CVSS scores, exploit flags, CVE IDs),
        http-vuln-* (any CVE-tagged vulnerability), http-git (repo exposure),
        http-enum, http-title, http-server-header, ssh-hostkey,
        http-security-headers, http-slowloris-check, unusual-port
      - Aggregated vulnerability assessment with severity classification
      - OS detection results (matches, accuracy, CPE)
      - Host info (uptime, distance, traceroute, DNS, ASN)

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

    finish_el = root.find(".//finished")
    if finish_el is not None:
        scan_info["end_time"] = finish_el.get("timestr", "Unknown")
        scan_info["elapsed"] = finish_el.get("elapsed", "N/A")

    hosts_up = root.find(".//hosts")
    if hosts_up is not None:
        scan_info["hosts_up"] = hosts_up.get("up", "0")
        scan_info["hosts_total"] = hosts_up.get("total", "0")

    # ── Host data ──
    host_data = {
        "ip": "Unknown",
        "hostname": "Unknown",
        "status": "unknown",
        "open_ports": [],
        "vulnerabilities": [],         # Aggregated vuln dicts
        "vulners_entries": [],          # Raw vulners tables per port
        "security_notes": [],
        "unusual_ports": [],
        "git_exposure_nmap": None,      # http-git findings
        "os_detection": None,           # OS fingerprint
        "extra_ports": {"filtered": 0, "filtered_ranges": []},
        "uptime": None,
        "distance": None,
        "traceroute": [],
        "dns_info": None,
        "asn_info": None,
    }

    # Find host
    host_el = None
    for h in root.findall(".//host"):
        st = h.find("status")
        if st is not None and st.get("state") == "up":
            host_el = h
            break
    if host_el is None:
        host_el = root.find(".//host")

    if host_el is not None:
        # ── IP & hostname ──
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is not None:
            host_data["ip"] = addr_el.get("addr", "Unknown")

        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                host_data["hostname"] = hn.get("name", "Unknown")

        status_el = host_el.find("status")
        if status_el is not None:
            host_data["status"] = status_el.get("state", "unknown")

        # ── OS Detection ──
        os_el = host_el.find("os")
        if os_el is not None:
            os_matches = []
            for om in os_el.findall("osmatch"):
                os_classes = []
                for oc in om.findall("osclass"):
                    os_classes.append({
                        "type": oc.get("type", ""),
                        "vendor": oc.get("vendor", ""),
                        "osfamily": oc.get("osfamily", ""),
                        "osgen": oc.get("osgen", ""),
                        "accuracy": oc.get("accuracy", ""),
                        "cpe": [c.text for c in oc.findall("cpe") if c.text],
                    })
                os_matches.append({
                    "name": om.get("name", ""),
                    "accuracy": om.get("accuracy", "0"),
                    "classes": os_classes,
                })
            host_data["os_detection"] = {
                "matches": os_matches,
                "best_match": os_matches[0]["name"] if os_matches else "Unknown",
                "best_accuracy": os_matches[0]["accuracy"] if os_matches else "0",
            }

        # ── Parse ports ──
        ports_el = host_el.find("ports")
        if ports_el is not None:
            extra_el = ports_el.find("extraports")
            if extra_el is not None:
                host_data["extra_ports"]["filtered"] = int(extra_el.get("count", 0))
                host_data["extra_ports"]["filtered_ranges"] = extra_el.get("ports", "").split(",")

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_id = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")

                svc_el = port_el.find("service")
                service_name = ""
                service_product = ""
                service_version = ""
                service_extrainfo = ""
                service_tunnel = ""
                service_cpe = ""
                service_ostype = ""
                if svc_el is not None:
                    service_name = svc_el.get("name", "")
                    service_product = svc_el.get("product", "")
                    service_version = svc_el.get("version", "")
                    service_extrainfo = svc_el.get("extrainfo", "")
                    service_tunnel = svc_el.get("tunnel", "")
                    service_cpe = svc_el.get("cpe", "")
                    service_ostype = svc_el.get("ostype", "")

                # Parse scripts
                port_scripts = {}
                vulns_found = []
                vulners_for_port = []
                security_headers = {}
                unusual_flag = False
                git_nmap_finding = None
                http_enum_findings = []
                title_finding = None
                server_header = None
                ssh_keys = []

                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    script_output = script_el.get("output", "")

                    # ── vulners: CVE database lookup (structured tables) ──
                    if script_id == "vulners":
                        for table_el in script_el.findall(".//table"):
                            row = {}
                            for elem_el in table_el.findall("elem"):
                                key = elem_el.get("key", "")
                                text = (elem_el.text or "").strip()
                                if key:
                                    row[key] = text
                            if row:
                                cvss_val = float(row.get("cvss", 0))
                                is_exploit = row.get("is_exploit", "false") == "true"
                                entry_type = row.get("type", "unknown")
                                entry_id = row.get("id", "UNKNOWN")

                                # Severity label
                                if cvss_val >= 9.0:
                                    severity = "CRITICAL"
                                elif cvss_val >= 7.0:
                                    severity = "HIGH"
                                elif cvss_val >= 4.0:
                                    severity = "MEDIUM"
                                else:
                                    severity = "LOW"

                                vulners_for_port.append({
                                    "id": entry_id,
                                    "cvss": cvss_val,
                                    "severity": severity,
                                    "is_exploit": is_exploit,
                                    "type": entry_type,
                                    "port": port_id,
                                    "service": f"{service_name} {service_version}".strip(),
                                })

                        # Top 5 vulners as port-level vulns
                        sorted_vulns = sorted(vulners_for_port, key=lambda x: -x["cvss"])[:5]
                        for sv in sorted_vulns:
                            vulns_found.append({
                                "type": "CVE / Vulners",
                                "script_id": "vulners",
                                "cve_id": sv["id"],
                                "cvss": sv["cvss"],
                                "severity": sv["severity"],
                                "title": f"{sv['id']} (CVSS {sv['cvss']})",
                                "state": "EXPLOIT AVAILABLE" if sv["is_exploit"] else "VULNERABLE",
                                "description": (
                                    f"Vulnerability {sv['id']} with CVSS score {sv['cvss']} "
                                    f"affects {sv['service']} on port {sv['port']}. "
                                    f"{'Public exploit available.' if sv['is_exploit'] else 'No public exploit identified.'}"
                                ),
                                "references": [f"https://vulners.com/{sv['type']}/{sv['id']}"],
                            })

                    # ── Generic http-vuln-* scripts ──
                    elif script_id.startswith("http-vuln-") and "VULNERABLE" in script_output:
                        cve_ids = []
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

                        ids_table = script_el.find(".//table[@key='ids']")
                        if ids_table is not None:
                            for e in ids_table.findall("elem"):
                                cve_ids.append((e.text or "").strip())

                        desc_table = script_el.find(".//table[@key='description']")
                        if desc_table is not None:
                            desc_el = desc_table.find("elem")
                            if desc_el is not None:
                                cve_desc = (desc_el.text or "").strip()

                        refs_table = script_el.find(".//table[@key='refs']")
                        if refs_table is not None:
                            for e in refs_table.findall("elem"):
                                cve_refs.append((e.text or "").strip())

                        vulns_found.append({
                            "type": "Vulnerability",
                            "script_id": script_id,
                            "cve_id": cve_ids[0] if cve_ids else script_id.replace("http-vuln-", "").upper(),
                            "cvss": 0,
                            "severity": "HIGH",
                            "title": cve_title or script_id.replace("http-vuln-", "").upper(),
                            "state": cve_state or "VULNERABLE",
                            "description": cve_desc or script_output[:300],
                            "references": cve_refs,
                        })

                    # ── http-slowloris-check ──
                    elif script_id == "http-slowloris-check" and "VULNERABLE" in script_output:
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
                        ids_table = script_el.find(".//table[@key='ids']")
                        if ids_table is not None:
                            for e in ids_table.findall("elem"):
                                cve_id = (e.text or "").strip()
                        desc_table = script_el.find(".//table[@key='description']")
                        if desc_table is not None:
                            desc_el = desc_table.find("elem")
                            if desc_el is not None:
                                cve_desc = (desc_el.text or "").strip()
                        refs_table = script_el.find(".//table[@key='refs']")
                        if refs_table is not None:
                            for e in refs_table.findall("elem"):
                                cve_refs.append((e.text or "").strip())
                        vulns_found.append({
                            "type": "Vulnerability",
                            "script_id": script_id,
                            "cve_id": cve_id,
                            "cvss": 0,
                            "severity": "MEDIUM",
                            "title": cve_title,
                            "state": cve_state,
                            "description": cve_desc,
                            "references": cve_refs,
                        })

                    # ── http-git: Git repository exposure ──
                    elif script_id == "http-git":
                        git_files = {}
                        git_remotes = []
                        git_desc = ""
                        for table_el in script_el.findall(".//table"):
                            tkey = table_el.get("key", "")
                            if tkey == "files-found":
                                for elem_el in table_el.findall("elem"):
                                    fkey = elem_el.get("key", "")
                                    fval = (elem_el.text or "").strip()
                                    git_files[fkey] = fval == "true"
                            elif tkey == "remotes":
                                for elem_el in table_el.findall("elem"):
                                    git_remotes.append((elem_el.text or "").strip())
                        desc_el = script_el.find(".//elem[@key='repository-description']")
                        if desc_el is not None:
                            git_desc = (desc_el.text or "").strip()

                        exposed = [k for k, v in git_files.items() if v]
                        git_nmap_finding = {
                            "exposed_files": exposed,
                            "all_files": git_files,
                            "remotes": git_remotes,
                            "description": git_desc,
                            "risk_level": "CRITICAL" if (".git/config" in exposed or ".git/HEAD" in exposed) else "HIGH",
                        }
                        # Add as a vulnerability
                        vulns_found.append({
                            "type": "Git Exposure",
                            "script_id": "http-git",
                            "cve_id": "N/A",
                            "cvss": 0,
                            "severity": git_nmap_finding["risk_level"],
                            "title": "Publicly Accessible .git Repository",
                            "state": "EXPOSED",
                            "description": (
                                f"Nmap discovered an accessible .git repository. "
                                f"{len(exposed)} files exposed: {', '.join(exposed)}. "
                                f"Remote origin: {', '.join(git_remotes) if git_remotes else 'unknown'}."
                            ),
                            "references": git_remotes,
                        })

                    # ── http-enum ──
                    elif script_id == "http-enum" and script_output.strip():
                        for line in script_output.strip().split("\n"):
                            line = line.strip()
                            if line:
                                http_enum_findings.append(line)

                    # ── http-title ──
                    elif script_id == "http-title":
                        title_el = script_el.find("elem[@key='title']")
                        if title_el is not None:
                            title_finding = (title_el.text or "").strip()
                        elif script_output:
                            title_finding = script_output.strip()

                    # ── http-server-header ──
                    elif script_id == "http-server-header":
                        elem = script_el.find("elem")
                        if elem is not None and elem.text:
                            server_header = elem.text.strip()
                        elif script_output:
                            server_header = script_output.strip()

                    # ── ssh-hostkey ──
                    elif script_id == "ssh-hostkey":
                        for table_el in script_el.findall("table"):
                            key_info = {}
                            for elem_el in table_el.findall("elem"):
                                k = elem_el.get("key", "")
                                v = (elem_el.text or "").strip()
                                if k:
                                    key_info[k] = v
                            if key_info:
                                ssh_keys.append(key_info)

                    # ── http-security-headers ──
                    elif script_id == "http-security-headers":
                        if "HSTS not configured" in script_output:
                            vulns_found.append({
                                "type": "Missing Header",
                                "script_id": script_id,
                                "cve_id": "N/A",
                                "cvss": 0,
                                "severity": "MEDIUM",
                                "title": "HSTS Not Configured",
                                "state": "MISSING",
                                "description": (
                                    "HTTP Strict Transport Security is not enabled. "
                                    "Without HSTS, browsers may connect over unencrypted HTTP, "
                                    "exposing users to MITM downgrade attacks."
                                ),
                                "references": [
                                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                                ],
                            })
                        for table_el in script_el.findall("table"):
                            table_key = table_el.get("key", "")
                            for elem_el in table_el.findall("elem"):
                                text = (elem_el.text or "").strip()
                                if text and "not configured" not in text.lower():
                                    if table_key not in security_headers:
                                        security_headers[table_key] = []
                                    security_headers[table_key].append(text)

                    # ── unusual-port ──
                    elif script_id == "unusual-port":
                        unusual_flag = True

                    # Store script
                    port_scripts[script_id] = {
                        "output": script_output,
                        "id": script_id,
                    }

                # Build service version string
                version_parts = []
                if service_product:
                    version_parts.append(service_product)
                if service_version:
                    version_parts.append(service_version)
                if service_extrainfo:
                    version_parts.append(f"({service_extrainfo})")
                service_full_version = " ".join(version_parts) if version_parts else service_name

                port_info = {
                    "port": port_id,
                    "protocol": protocol,
                    "service_name": service_name,
                    "service_product": service_product,
                    "service_version": service_version,
                    "service_extrainfo": service_extrainfo,
                    "service_full_version": service_full_version,
                    "service_tunnel": service_tunnel,
                    "service_cpe": service_cpe,
                    "service_ostype": service_ostype,
                    "is_ssl": service_tunnel == "ssl",
                    "vulnerabilities": vulns_found,
                    "security_headers": security_headers,
                    "unusual": unusual_flag,
                    "http_title": title_finding,
                    "server_header": server_header,
                    "http_enum": http_enum_findings,
                    "ssh_keys": ssh_keys,
                }
                host_data["open_ports"].append(port_info)

                if unusual_flag:
                    host_data["unusual_ports"].append(port_id)

                # Store vulners per port (raw)
                if vulners_for_port:
                    host_data["vulners_entries"].extend(vulners_for_port)

                # Store git exposure from nmap
                if git_nmap_finding:
                    host_data["git_exposure_nmap"] = git_nmap_finding

            # Aggregate vulnerabilities across ports
            seen = set()
            for port_info in host_data["open_ports"]:
                for vuln in port_info.get("vulnerabilities", []):
                    key = vuln.get("cve_id", "") + vuln.get("title", "")
                    if key not in seen:
                        seen.add(key)
                        host_data["vulnerabilities"].append(vuln)

            # ── Deduplicate vulners: group exploits under their CVEs ──
            if host_data["vulners_entries"]:
                host_data["vulners_deduped"] = _dedup_vulners(
                    host_data["vulners_entries"]
                )

            # Security notes
            for port_info in host_data["open_ports"]:
                if port_info["security_headers"]:
                    host_data["security_notes"].append({
                        "port": port_info["port"],
                        "headers": port_info["security_headers"],
                    })

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



def _dedup_vulners(vulners_entries):
    """Group vulners entries by (service, cvss) — merge exploits under CVEs."""
    from collections import defaultdict

    # Group by (service, cvss)
    groups = defaultdict(lambda: {"cves": [], "exploits": [], "max_cvss": 0})
    for v in vulners_entries:
        key = (v.get("service", ""), v.get("cvss", 0))
        g = groups[key]
        g["max_cvss"] = max(g["max_cvss"], v.get("cvss", 0))
        if v.get("type") == "cve":
            g["cves"].append(v)
        else:
            g["exploits"].append(v)

    deduped = []
    seen_cve_ids = set()

    for (svc, cvss), g in sorted(groups.items(), key=lambda x: -x[1]["max_cvss"]):
        exploit_count = len(g["exploits"])

        # If we have real CVEs, show them with exploit count
        for cve in g["cves"]:
            cid = cve["id"]
            if cid in seen_cve_ids:
                continue
            seen_cve_ids.add(cid)

            # Severity label
            if cvss >= 9.0:
                severity = "CRITICAL"
            elif cvss >= 7.0:
                severity = "HIGH"
            elif cvss >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            deduped.append({
                "id": cid,
                "cvss": cvss,
                "severity": severity,
                "is_exploit": exploit_count > 0,
                "type": "cve",
                "port": cve.get("port", ""),
                "service": svc,
                "exploit_count": exploit_count,
            })

        # If only exploits (no CVE), show the first exploit as representative
        if not g["cves"] and g["exploits"]:
            rep = g["exploits"][0]
            if cvss >= 9.0:
                severity = "CRITICAL"
            elif cvss >= 7.0:
                severity = "HIGH"
            elif cvss >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            deduped.append({
                "id": f"{len(g['exploits'])} exploits for {svc}",
                "cvss": cvss,
                "severity": severity,
                "is_exploit": True,
                "type": "exploit_group",
                "port": rep.get("port", ""),
                "service": svc,
                "exploit_count": exploit_count,
            })

    return deduped


# ─── Dirsearch Parsing ───────────────────────────────────────────────────────

def parse_dirsearch_results(file_path):
    """
    Parse dirsearch_rawReport.json and extract:
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
    Parse whatweb_rawReport.json and extract:
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
        raw = f.read().strip()

        # WhatWeb --log-json outputs newline-delimited JSON (NDJSON), not a
        # single JSON array.  Try to parse as a proper array first; if that
        # fails, treat each non-empty line as a standalone JSON object.
        if raw.startswith("["):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = []
                for line in raw.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            print(f"    [!] Skipping unparseable whatweb line: {e}")
        else:
            data = []
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"    [!] Skipping unparseable whatweb line: {e}")

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


# ─── FFUF Parsing ─────────────────────────────────────────────────────────

def parse_ffuf_results(file_path):
    """
    Parse ffuf_rawReport.json and extract:
      - Scan metadata (command, timestamp)
      - Discovered endpoints with categorised risk levels
      - Sensitive file exposure (.git, .env, backups, configs)
      - Statistics by content type and status

    Returns a structured dictionary.
    """
    if not os.path.exists(file_path):
        print(f"[-] FFUF JSON not found: {file_path}")
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    commandline = data.get("commandline", "N/A")
    scan_time = data.get("time", "Unknown")
    all_results = data.get("results", [])

    # ── Categorise findings by risk ──
    critical = []    # .git exposure, .env, config leaks
    high = []        # Backup files, database dumps, credentials
    medium = []      # Admin panels, debug endpoints, info disclosure
    low = []         # Standard pages (index, robots, sitemap, etc.)

    # Known sensitive patterns
    critical_patterns = [
        ".git/", ".svn/", ".hg/", ".env", "id_rsa", "id_ed25519",
        "wp-config.php", "config.php", "credentials", "password",
    ]
    high_patterns = [
        ".bak", ".backup", ".sql", ".dump", ".tar.gz", ".zip",
        "phpinfo", "wp-admin", "administrator", "admin.php",
        "debug", "test.php", ".log",
    ]
    medium_patterns = [
        "login", "signin", "dashboard", "panel", "console",
        ".htaccess", ".htpasswd", "crossdomain.xml", "clientaccesspolicy.xml",
    ]

    content_type_counts = {}
    status_counts = {}

    for entry in all_results:
        inp = entry.get("input", {})
        # Extract the actual fuzzed value (exclude FFUFHASH)
        fuzz_values = {k: v for k, v in inp.items() if k != "FFUFHASH"}
        fuzz_word = list(fuzz_values.values())[0] if fuzz_values else "?"

        status = entry.get("status", 0)
        length = entry.get("length", 0)
        words = entry.get("words", 0)
        lines = entry.get("lines", 0)
        content_type = entry.get("content-type", "")
        redirect = entry.get("redirectlocation", "")
        url = entry.get("url", "")
        host = entry.get("host", "")
        duration_ns = entry.get("duration", 0)

        # Count by status and content type
        status_counts[status] = status_counts.get(status, 0) + 1
        ct_key = content_type.split(";")[0].strip() if content_type else "unknown"
        content_type_counts[ct_key] = content_type_counts.get(ct_key, 0) + 1

        finding = {
            "fuzz_word": fuzz_word,
            "url": url,
            "host": host,
            "status": status,
            "length": length,
            "words": words,
            "lines": lines,
            "content_type": content_type,
            "redirect": redirect if redirect else None,
            "duration_ms": round(duration_ns / 1e6, 1) if duration_ns else 0,
        }

        # Classify risk level
        fuzz_lower = fuzz_word.lower()
        url_lower = url.lower()

        is_critical = any(p in url_lower for p in critical_patterns)
        is_high = any(p in fuzz_lower for p in high_patterns)
        is_medium = any(p in fuzz_lower for p in medium_patterns)

        if is_critical:
            critical.append(finding)
        elif is_high:
            high.append(finding)
        elif is_medium:
            medium.append(finding)
        else:
            low.append(finding)

    # ── Build .git exposure summary (cross-check with FFUF) ──
    git_findings = [f for f in critical if ".git" in f.get("url", "")]
    git_summary = _summarize_ffuf_git_exposure(git_findings)

    # ── Build overall risk summary ──
    total_findings = len(all_results)
    sensitive_count = len(critical) + len(high)

    return {
        "scan_info": {
            "command": commandline,
            "time": scan_time,
        },
        "total_findings": total_findings,
        "sensitive_count": sensitive_count,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "git_findings": git_findings,
        "git_summary": git_summary,
        "status_counts": status_counts,
        "content_type_counts": content_type_counts,
        "all_results": all_results,
    }


def _summarize_ffuf_git_exposure(git_findings):
    """Produce a human-readable summary of .git exposure from FFUF results."""
    if not git_findings:
        return None

    exposed_files = []
    for f in git_findings:
        path = f["url"].split(".git")[-1] if ".git" in f["url"] else f["url"]
        exposed_files.append({
            "url": f["url"],
            "path": path,
            "size_bytes": f["length"],
            "content_type": f["content_type"],
            "status": f["status"],
        })

    # Determine risk level
    risk_level = "HIGH"
    has_head = any("HEAD" in f["path"] for f in exposed_files)
    has_config = any("config" in f["path"] for f in exposed_files)
    has_description = any("description" in f["path"] for f in exposed_files)

    if has_head and has_config:
        risk_level = "CRITICAL"
    elif has_head or (has_config and has_description):
        risk_level = "HIGH"

    return {
        "risk_level": risk_level,
        "exposed_file_count": len(exposed_files),
        "exposed_files": exposed_files,
        "total_git_hits": len(git_findings),
        "summary_text": (
            f"The Security Assessment revealed there are  {len(exposed_files)} publicly "
            f"accessible Git repository files on the target. These files expose "
            f"internal repository structure, commit history, and metadata. "
            f"This is a {risk_level} severity finding."
        ),
    }


# ─── HTML Report Builder ─────────────────────────────────────────────────────

def build_html_report(nmap_data, dirsearch_data, whatweb_data, ffuf_data, output_path):
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
        nmap_data, dirsearch_data, whatweb_data, ffuf_data
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
            padding: 14px 0 14px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            gap: 20px;
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
            display: flex;
            align-items: flex-start;
            gap: 8px;
            flex: 1;
        }}
        .finding-text {{
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

        .key-findings-subsection {{
            font-family: 'Outfit', sans-serif;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-secondary);
            margin: 16px 0 6px 0;
            padding-bottom: 4px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            text-transform: uppercase;
            letter-spacing: 0.6px;
        }}

        .pie-chart-container {{
            margin-bottom: 18px;
            padding: 14px 0;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }}
        .pie-chart-title {{
            font-family: 'Outfit', sans-serif;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .inner-tabs-nav {{
            display: flex;
            gap: 4px;
            margin-bottom: 0;
        }}
        .inner-tab-btn {{
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            padding: 6px 14px;
            border-radius: 6px 6px 0 0;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            font-family: 'Inter', sans-serif;
            transition: all 0.15s;
        }}
        .inner-tab-btn.active {{
            background: var(--card-bg);
            color: var(--text-primary);
            border-bottom-color: transparent;
            font-weight: 600;
        }}
        .inner-tab-btn:hover {{
            color: var(--text-primary);
        }}
        .inner-tab-content {{
            display: none;
        }}
        .inner-tab-content.active {{
            display: block;
        }}

        /* ---- Executive Summary ---- */
                .exec-summary {{
                    background: var(--card-bg);
                    border: 1px solid var(--border-color);
                    border-radius: 12px;
                    padding: 28px 32px;
                    margin-bottom: 28px;
                }}
                .exec-summary h2 {{
                    font-family: 'Outfit', sans-serif;
                    font-size: 20px;
                    font-weight: 700;
                    margin: 0 0 16px 0;
                    color: var(--text-primary);
                }}
                .exec-summary .risk-narrative {{
                    font-size: 14px;
                    line-height: 1.75;
                    color: var(--text-secondary);
                    margin-bottom: 20px;
                }}
                .exec-summary .risk-narrative strong {{
                    color: var(--text-primary);
                }}
                .exec-summary .impact-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                    gap: 14px;
                    margin-top: 16px;
                }}
                .impact-item {{
                    background: rgba(255,255,255,0.03);
                    border: 1px solid rgba(255,255,255,0.06);
                    border-radius: 8px;
                    padding: 16px 18px;
                }}
                .impact-item .impact-icon {{
                    font-size: 18px;
                    margin-bottom: 6px;
                }}
                .impact-item .impact-title {{
                    font-family: 'Outfit', sans-serif;
                    font-size: 13px;
                    font-weight: 600;
                    color: var(--text-primary);
                    margin-bottom: 4px;
                }}
                .impact-item .impact-desc {{
                    font-size: 12px;
                    color: var(--text-muted);
                    line-height: 1.5;
                }}

                /* ---- Remediation / Business Impact ---- */
                .vuln-business-impact {{
                    background: rgba(255,193,7,0.06);
                    border: 1px solid rgba(255,193,7,0.12);
                    border-radius: 6px;
                    padding: 12px 14px;
                    margin: 12px 0 8px 0;
                    font-size: 13px;
                    color: var(--text-secondary);
                    line-height: 1.55;
                }}
                .vuln-business-impact strong {{
                    color: var(--color-warning);
                }}
                .vuln-remediation {{
                    background: rgba(16,185,129,0.06);
                    border: 1px solid rgba(16,185,129,0.12);
                    border-radius: 6px;
                    padding: 12px 14px;
                    margin: 8px 0;
                    font-size: 13px;
                    color: var(--text-secondary);
                    line-height: 1.55;
                }}
                .vuln-remediation strong {{
                    color: var(--color-pass);
                }}

                /* ---- Paywall / Gated Content (partial blur) ---- */
                        .paywall-gated {{
                            position: relative;
                            margin-top: 12px;
                        }}
                        .paywall-gated .gated-content {{
                            filter: blur(6px);
                            pointer-events: none;
                            user-select: none;
                            opacity: 0.4;
                            transition: filter 0.3s, opacity 0.3s;
                        }}
                        .paywall-gated.unlocked .gated-content {{
                            filter: none;
                            pointer-events: auto;
                            user-select: auto;
                            opacity: 1;
                        }}
                        .paywall-gated .gated-overlay {{
                            position: absolute;
                            inset: 0;
                            display: flex;
                            flex-direction: column;
                            align-items: center;
                            justify-content: center;
                            background: rgba(10,12,18,0.6);
                            border-radius: 8px;
                            z-index: 5;
                            gap: 10px;
                            border: 1px dashed rgba(255,46,59,0.25);
                        }}
                        .paywall-gated.unlocked .gated-overlay {{
                            display: none;
                        }}
                        .paywall-gated .gated-overlay .lock-text {{
                            font-family: 'Outfit', sans-serif;
                            font-size: 15px;
                            color: var(--text-primary);
                        }}
                        .paywall-gated .gated-overlay .lock-sub {{
                            font-size: 12px;
                            color: var(--text-muted);
                        }}
                        .paywall-gated .gated-overlay .btn-unlock {{
                            background: var(--accent-red);
                            color: #fff;
                            border: none;
                            border-radius: 6px;
                            padding: 8px 20px;
                            font-size: 13px;
                            font-weight: 600;
                            cursor: pointer;
                        }}
                        .paywall-gated .gated-overlay .btn-unlock:hover {{
                            background: #e02b35;
                        }}
                        .paywall-gated .gated-overlay .pw-input {{
                            background: rgba(255,255,255,0.08);
                            border: 1px solid var(--border-color);
                            border-radius: 4px;
                            padding: 6px 12px;
                            color: var(--text-primary);
                            font-size: 13px;
                            font-family: monospace;
                            width: 200px;
                            text-align: center;
                        }}
                        .paywall-gated .gated-overlay .pw-error {{
                            color: var(--color-critical);
                            font-size: 11px;
                            display: none;
                        }}

                /* ---- Severity Risk Matrix ---- */
                .risk-matrix {{
                    display: grid;
                    grid-template-columns: 80px repeat(4, 1fr);
                    gap: 1px;
                    background: var(--border-color);
                    border: 1px solid var(--border-color);
                    border-radius: 8px;
                    overflow: hidden;
                    margin: 12px 0;
                }}
                .risk-matrix .rm-cell {{
                    background: var(--bg-primary);
                    padding: 8px 10px;
                    text-align: center;
                    font-size: 11px;
                }}
                .risk-matrix .rm-header {{
                    background: rgba(255,255,255,0.04);
                    font-weight: 700;
                    color: var(--text-secondary);
                    font-size: 10px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                .risk-matrix .rm-filled {{
                    font-weight: 700;
                    font-size: 14px;
                    font-family: 'Outfit', sans-serif;
                }}
                .rm-sev-critical {{ background: rgba(255,46,59,0.25) !important; color: var(--color-critical); }}
                .rm-sev-high     {{ background: rgba(255,140,0,0.20) !important; color: var(--color-warning); }}
                .rm-sev-medium   {{ background: rgba(59,130,246,0.15) !important; color: var(--color-info); }}
                .rm-sev-low      {{ background: rgba(16,185,129,0.10) !important; color: var(--color-pass); }}

                /* Print styles */
                        @media print {{
                    body {{ background: #fff; color: #000; }}
                    .glass-card {{ background: #f8f8f8; border: 1px solid #ddd; box-shadow: none; }}
                    .btn-print {{ display: none; }}
                    .tabs-nav {{ display: none; }}
                    .tab-content {{ display: block !important; opacity: 1 !important; }}
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

                <!-- ═══ Executive Summary ═══ -->
                <div class="exec-summary">
                    <h2>Executive Summary</h2>
                    <div class="risk-narrative">
                        This security assessment evaluated <strong>{html_escape(target_hostname)}</strong> and identified
                        <strong style="color:{_risk_color(risk_score)}">{_vuln_count(nmap_data)} security vulnerabilities</strong>
                        across {_open_port_count(nmap_data)} exposed services.
                        The overall risk posture is rated <strong style="color:{_risk_color(risk_score)}">{risk_label}</strong>.
                    </div>
                    <div class="risk-narrative">
                        The most critical concern is the <strong>public exposure of Git repository files</strong>, which
                        could allow attackers to access your source code, configuration secrets, and development history.
                        Additionally, {_cve_unique_count(nmap_data)} known CVEs were matched against your service versions,
                        {_cve_critical_breakout(nmap_data)}.
                    </div>
                    <div class="impact-grid">
                        {_build_impact_grid(nmap_data, dirsearch_data, whatweb_data, ffuf_data)}
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
                    <div class="stat-card" style="grid-column:1/-1;text-align:center;padding:8px 12px">
                        <span class="stat-lbl" style="font-size:13px;color:var(--text-secondary);text-transform:none;letter-spacing:0">
                            {_cve_breakdown_text(nmap_data)}
                        </span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-critical">{_cve_unique_count(nmap_data)}</span>
                        <span class="stat-lbl">Unique CVEs</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-info">{_open_port_count(nmap_data)}</span>
                        <span class="stat-lbl">Open Ports</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-warning">{_git_exposed_count(dirsearch_data, ffuf_data)}</span>
                        <span class="stat-lbl">.git Files Exposed</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-critical">{_vuln_count(nmap_data)}</span>
                        <span class="stat-lbl">Vulnerabilities</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-pass">{_tech_count(whatweb_data)}</span>
                        <span class="stat-lbl">Technologies</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-info">{_ffuf_endpoint_count(ffuf_data)}</span>
                        <span class="stat-lbl">Assets Discovered</span>
                    </div>
                </div>
            </div>

            <div class="glass-card card-blue">
                <div class="card-title">Key Findings Summary</div>
                {_build_key_findings(nmap_data, dirsearch_data, whatweb_data, ffuf_data)}
            </div>
        </div>

        <!-- ═══ Tab Navigation ═══ -->
                <div class="tabs-nav">
                    <button class="tab-btn active" onclick="switchTab('tab-os')">OS Detection</button>
                    <button class="tab-btn" onclick="switchTab('tab-ports')">Open Ports</button>
                    <button class="tab-btn" onclick="switchTab('tab-tech')">Tech Findings</button>
                    <button class="tab-btn locked-tab" onclick="switchTab('tab-ffuf')">Asset Discovery &#x1F512;</button>
                    <button class="tab-btn locked-tab" onclick="switchTab('tab-vulners')">CVE Database &#x1F512;</button>
                    <button class="tab-btn locked-tab" onclick="switchTab('tab-vulns')">Vulnerabilities &#x1F512;</button>
                </div>

                <!-- Paywall promotion banner -->
                        <div class="highlight-box paywall-banner" style="background:rgba(255,46,59,0.08);border:1px solid rgba(255,46,59,0.2);margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
                            <span style="font-size:13px">&#x1F512; <strong style="color:var(--color-critical)">Premium Content Locked</strong> — The first {FREE_PREVIEW_COUNT} findings in each section are free. Enter the password to reveal all results.</span>
                            <span style="font-size:11px;color:var(--text-muted)">Contact Cyber Samurai to obtain your unlock code.</span>
                        </div>

        <!-- ═══ Tab: Open Ports & Services ═══ -->
        <div class="tab-content" id="tab-ports">
            <h2 class="section-title">Open Ports &amp; Services</h2>
            {_build_ports_section(nmap_data)}
        </div>

        <!-- ═══ Tab: Technology Fingerprint ═══ -->
        <div class="tab-content" id="tab-tech">
            <h2 class="section-title">Technology Fingerprint</h2>
            {_build_tech_fingerprint_section(whatweb_data)}
        </div>

        <!-- ═══ Tab: Asset Discovery (FFUF) ═══ -->
                <div class="tab-content" id="tab-ffuf">
                    <h2 class="section-title">Asset &amp; Endpoint Discovery</h2>
                    {_build_ffuf_section(ffuf_data)}
                </div>

        <!-- ═══ Tab: CVE Vulnerability Database ═══ -->
                <div class="tab-content" id="tab-vulners">
                    <h2 class="section-title">CVE Vulnerability Assessment</h2>
                    {_build_vulners_section(nmap_data)}
                </div>

        <!-- ═══ Tab: OS Detection ═══ -->
        <div class="tab-content active" id="tab-os">
            <h2 class="section-title">Operating System Detection</h2>
            {_build_os_section(nmap_data)}
        </div>

        <!-- ═══ Tab: Vulnerability Findings ═══ -->
                <div class="tab-content" id="tab-vulns">
                    <h2 class="section-title">Vulnerability Findings</h2>
                    {_build_vulnerabilities_section(nmap_data)}
                </div>

        <!-- ═══ Footer ═══ -->
        <div class="footer">
            <p>Cyber Samurai &mdash; Fingerprint &amp; Vulnerability Assessment Report</p>
            <p style="font-size:11px;margin-top:4px">Generated on {html_escape(SCAN_DATE)} | This report contains confidential security findings.</p>
        </div>
    </div>

    <script>
            function switchInnerTab(btn, contentId) {{
                var parent = btn.parentElement;
                var container = parent.parentElement;
                parent.querySelectorAll('.inner-tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
                btn.classList.add('active');
                container.querySelectorAll('.inner-tab-content').forEach(function(c) {{ c.classList.remove('active'); }});
                var target = document.getElementById(contentId);
                if (target) target.classList.add('active');
            }}
            function switchTab(tabId) {{
                            document.querySelectorAll('.tab-btn').forEach(function(btn) {{ btn.classList.remove('active'); }});
                            document.querySelectorAll('.tab-content').forEach(function(tc) {{ tc.classList.remove('active'); }});
                            var target = document.getElementById(tabId);
                            if (target) {{ target.classList.add('active'); }}
                            var allBtns = document.querySelectorAll('.tab-btn');
                            for (var i = 0; i < allBtns.length; i++) {{
                                if (allBtns[i].getAttribute('onclick') && allBtns[i].getAttribute('onclick').indexOf(tabId) !== -1) {{
                                    allBtns[i].classList.add('active');
                                }}
                            }}
                        }}
                        function unlockGate(containerId) {{
                            var container = document.getElementById(containerId);
                            if (!container) return;
                            var overlay = container.querySelector('.gated-overlay');
                            var input = overlay.querySelector('.pw-input');
                            var error = overlay.querySelector('.pw-error');
                            var pw = input.value.trim();
                            if (pw === '{PAYWALL_PASSWORD}') {{
                                container.classList.add('unlocked');
                            }} else {{
                                error.style.display = 'block';
                                input.value = '';
                                input.focus();
                            }}
                        }}
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


def _calculate_risk_score(nmap_data, dirsearch_data, whatweb_data, ffuf_data=None):
    """Compute a weighted risk score 0-100 from findings."""
    score = 0

    # Nmap vulnerabilities (including vulners CVSS-based scoring)
    if nmap_data and nmap_data.get("host"):
        vulns = nmap_data["host"].get("vulnerabilities", [])
        for v in vulns:
            sev = v.get("severity", "")
            if sev == "CRITICAL":
                score += 15
            elif sev == "HIGH":
                score += 10
            elif sev == "MEDIUM":
                score += 5
            elif sev == "LOW":
                score += 2
            # Legacy fallback
            elif v.get("state") == "LIKELY VULNERABLE":
                score += 12
            elif v.get("state") == "MISSING":
                score += 8

        # Vulners entries with CVSS scores
        for ve in nmap_data["host"].get("vulners_entries", []):
            cvss = ve.get("cvss", 0)
            if cvss >= 9.0:
                score += 6
            elif cvss >= 7.0:
                score += 4
            elif cvss >= 4.0:
                score += 2

        # Nmap git exposure
        if nmap_data["host"].get("git_exposure_nmap"):
            score += 20

        # Unusual ports
        unusual = nmap_data["host"].get("unusual_ports", [])
        score += len(unusual) * 2

        # Open ports beyond standard
        open_ports = nmap_data["host"].get("open_ports", [])
        standard = {80, 443}
        non_standard = [p for p in open_ports if p["port"] not in standard]
        score += len(non_standard) * 3

    # .git exposure (dirsearch)
    if dirsearch_data and dirsearch_data.get("git_exposure"):
        score += len(dirsearch_data["git_exposure"]) * 2
        if dirsearch_data.get("git_summary"):
            if dirsearch_data["git_summary"]["risk_level"] == "CRITICAL":
                score += 25
            elif dirsearch_data["git_summary"]["risk_level"] == "HIGH":
                score += 15

    # FFUF findings — critical exposures (.git, .env, etc.)
    if ffuf_data:
        critical_count = len(ffuf_data.get("critical", []))
        high_count = len(ffuf_data.get("high", []))
        score += critical_count * 6
        score += high_count * 3
        # FFUF .git exposure
        if ffuf_data.get("git_summary"):
            if ffuf_data["git_summary"]["risk_level"] == "CRITICAL":
                score += 20
            elif ffuf_data["git_summary"]["risk_level"] == "HIGH":
                score += 12

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


def _cve_breakdown_text(nmap_data):
    """Return text like '12 unique CVEs across 1 service: 3 Critical, 5 High, 4 Medium, 3 Low'"""
    if not nmap_data or not nmap_data.get("host"):
        return ""
    dd = nmap_data["host"].get("vulners_deduped", [])
    if not dd:
        return ""
    cves = [v for v in dd if v.get("type") == "cve"]
    services = sorted(set(v.get("service", "Unknown") for v in dd))
    crit = sum(1 for v in dd if v.get("cvss", 0) >= 9.0)
    high = sum(1 for v in dd if 7.0 <= v.get("cvss", 0) < 9.0)
    med  = sum(1 for v in dd if 4.0 <= v.get("cvss", 0) < 7.0)
    low  = sum(1 for v in dd if v.get("cvss", 0) < 4.0)
    svc_word = "service" if len(services) == 1 else "services"
    return f"{len(cves)} unique CVEs across {len(services)} {svc_word}: {crit} Critical, {high} High, {med} Medium, {low} Low"


def _cve_unique_count(nmap_data):
    """Count unique CVEs from deduped vulners data."""
    if nmap_data and nmap_data.get("host"):
        dd = nmap_data["host"].get("vulners_deduped", [])
        cves = [v for v in dd if v.get("type") == "cve"]
        if cves:
            return len(cves)
        # fallback to raw if no deduped
        raw = nmap_data["host"].get("vulners_entries", [])
        return len(raw)
    return 0


def _vuln_count(nmap_data):
    """Total vulnerability count including vulners entries."""
    if nmap_data and nmap_data.get("host"):
        host = nmap_data["host"]
        aggregated = len(host.get("vulnerabilities", []))
        vulners = len(host.get("vulners_entries", []))
        # Return the larger of the two to reflect actual vuln scope
        return max(aggregated, vulners)
    return 0


def _open_port_count(nmap_data):
    if nmap_data and nmap_data.get("host"):
        return len(nmap_data["host"].get("open_ports", []))
    return 0


def _git_exposed_count(dirsearch_data, ffuf_data=None):
    """Count .git file exposures from both dirsearch and FFUF (Asset Discovery)."""
    count = 0
    if dirsearch_data and dirsearch_data.get("git_exposure"):
        count += len(dirsearch_data["git_exposure"])
    if ffuf_data and ffuf_data.get("git_findings"):
        count += len(ffuf_data["git_findings"])
    return count


def _vuln_count(nmap_data):
    """Count unique vulnerability findings from the Vulnerabilities tab."""
    if not nmap_data or not nmap_data.get("host"):
        return 0
    vulns = nmap_data["host"].get("vulnerabilities", [])
    seen = set()
    for v in vulns:
        key = v.get("title", "") + v.get("cve_id", "")
        if key not in seen:
            seen.add(key)
    return len(seen)


def _git_exposed_from_ffuf_count(ffuf_data):
    """Count .git exposures from FFUF findings only."""
    if ffuf_data and ffuf_data.get("git_findings"):
        return len(ffuf_data["git_findings"])
    return 0


def _tech_count(whatweb_data):
    if whatweb_data and whatweb_data.get("technology_stack"):
        return len(whatweb_data["technology_stack"])
    return 0


# ─── HTML Section Builders ───────────────────────────────────────────────────

def _ffuf_endpoint_count(ffuf_data):
    """Count total FFUF-discovered endpoints."""
    if ffuf_data:
        return ffuf_data.get("total_findings", 0)
    return 0


def _ffuf_git_exposed_count(ffuf_data):
    """Count .git exposures from FFUF findings."""
    if ffuf_data and ffuf_data.get("git_findings"):
        return len(ffuf_data["git_findings"])
    return 0


def _cve_critical_breakout(nmap_data):
    """Return a short text like 'including 3 critical and 5 high severity'."""
    if not nmap_data or not nmap_data.get("host"):
        return ""
    dd = nmap_data["host"].get("vulners_deduped", [])
    if not dd:
        return ""
    crit = sum(1 for v in dd if v.get("cvss", 0) >= 9.0)
    high = sum(1 for v in dd if 7.0 <= v.get("cvss", 0) < 9.0)
    parts = []
    if crit:
        parts.append(f"{crit} critical")
    if high:
        parts.append(f"{high} high")
    if parts:
        return f"including {' and '.join(parts)} severity"
    return ""


def _build_impact_grid(nmap_data, dirsearch_data, whatweb_data, ffuf_data):
    """Build the business impact summary grid for the Executive Summary."""
    items = []

    # Reputation risk (if git exposed)
    git_count = _git_exposed_count(dirsearch_data, ffuf_data)
    if git_count > 0:
        items.append({
            "icon": "&#x1F6AB;", "title": "Source Code Exposure",
            "desc": f"{git_count} Git repository file(s) are publicly accessible. This exposes your source code, API keys, and development secrets — a direct threat to intellectual property and brand trust."
        })
    else:
        items.append({
            "icon": "&#x1F512;", "title": "Source Code Protected",
            "desc": "No Git repository files were found exposed. Your source code and development secrets are not directly accessible to the public."
        })

    # Operational risk
    ports = _open_port_count(nmap_data)
    items.append({
        "icon": "&#x1F310;", "title": "Attack Surface",
        "desc": f"{ports} Internet-facing service(s) are reachable. Each open port is a potential entry point. Reducing unnecessary services is the most effective risk reduction measure."
    })

    # Compliance / data risk
    cves = _cve_unique_count(nmap_data)
    if cves > 0:
        crit = sum(1 for v in (nmap_data or {}).get("host", {}).get("vulners_deduped", []) if v.get("cvss", 0) >= 9.0)
        items.append({
            "icon": "&#x26A0;&#xFE0F;", "title": "Known Vulnerabilities",
            "desc": f"{cves} CVE(s) matched against your services, with {crit} at critical severity. Unpatched vulnerabilities are the leading cause of data breaches."
        })
    else:
        items.append({
            "icon": "&#x2705;", "title": "Vulnerability Status",
            "desc": "No known CVEs were matched against your service versions. While this is positive, regular scanning is recommended as new vulnerabilities are discovered daily."
        })

    # Business continuity
    items.append({
        "icon": "&#x1F4C8;", "title": "Business Impact",
        "desc": "Addressing these findings now prevents costly incident response later. The average data breach costs organisations £3.4M (IBM 2024). Proactive security is a business enabler, not a cost centre."
    })

    html = ""
    for it in items:
        html += f"""<div class="impact-item">
            <div class="impact-icon">{it['icon']}</div>
            <div class="impact-title">{html_escape(it['title'])}</div>
            <div class="impact-desc">{it['desc']}</div>
        </div>"""
    return html


def _build_risk_matrix(nmap_data, ffuf_data):
    """Build a severity risk matrix showing findings across categories."""
    # Count by severity
    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    if nmap_data and nmap_data.get("host"):
        for v in nmap_data["host"].get("vulnerabilities", []):
            sev = v.get("severity", "MEDIUM")
            severities[sev] = severities.get(sev, 0) + 1
        # Add vulners deduped
        for v in nmap_data["host"].get("vulners_deduped", []):
            sev = v.get("severity", "MEDIUM")
            severities[sev] = severities.get(sev, 0) + 1

    if ffuf_data:
        severities["CRITICAL"] += len(ffuf_data.get("critical", []))
        severities["HIGH"] += len(ffuf_data.get("high", []))
        severities["MEDIUM"] += len(ffuf_data.get("medium", []))

    total = sum(severities.values())
    if total == 0:
        return ""

    def cell(sev, count):
        if count == 0:
            return f'<div class="rm-cell">—</div>'
        cls = {"CRITICAL": "rm-sev-critical", "HIGH": "rm-sev-high",
               "MEDIUM": "rm-sev-medium", "LOW": "rm-sev-low"}.get(sev, "")
        return f'<div class="rm-cell rm-filled {cls}">{count}</div>'

    return f"""
    <h4 class="key-findings-subsection">Risk Exposure Matrix</h4>
    <div class="risk-matrix">
        <div class="rm-cell"></div>
        <div class="rm-cell rm-header">Critical</div>
        <div class="rm-cell rm-header">High</div>
        <div class="rm-cell rm-header">Medium</div>
        <div class="rm-cell rm-header">Low</div>
        <div class="rm-cell rm-header" style="text-align:left;padding-left:12px">Findings</div>
        {cell("CRITICAL", severities["CRITICAL"])}
        {cell("HIGH", severities["HIGH"])}
        {cell("MEDIUM", severities["MEDIUM"])}
        {cell("LOW", severities["LOW"])}
    </div>
    <p class="summary-text" style="font-size:11px;margin-top:6px;color:var(--text-muted)">
        {total} total findings across all severity levels. Higher counts in Critical/High columns indicate urgent attention needed.
    </p>
    """


def _build_key_findings(nmap_data, dirsearch_data, whatweb_data, ffuf_data=None):
    """Build the key findings summary with subsections and severity pie chart."""
    sections = []  # List of (section_title, items_list)

    def section(title, items_list):
        if items_list:
            sections.append((title, items_list))

    # ── HOST section (Nmap) ──
    host_items = []
    if nmap_data and nmap_data.get("host"):
        # OS
        osd = nmap_data["host"].get("os_detection")
        if osd:
            host_items.append(
                f"""<div class="finding-row"><span class="finding-label">OS</span><span class="finding-value"><span class="badge badge-blue">DETECTED</span><span class="finding-text">{html_escape(osd['best_match'])} ({osd['best_accuracy']}% accuracy)</span></span></div>""")





        # Unusual ports
        unusual = nmap_data["host"].get("unusual_ports", [])
        if unusual:
            host_items.append(
                f"""<div class="finding-row finding-severity-medium"><span class="finding-label">Unusual Ports</span><span class="finding-value"><span class="badge badge-yellow">WARNING</span><span class="finding-text">{len(unusual)} non-standard port(s): {', '.join(str(p) for p in unusual)}</span></span></div>""")



    # ── VULNERABILITIES section ──
    vuln_items = []
    if nmap_data and nmap_data.get("host"):
        # Vulners CVE summary
        dedup = nmap_data["host"].get("vulners_deduped", [])
        raw = nmap_data["host"].get("vulners_entries", [])
        if dedup:
            cves = [v for v in dedup if v["type"] == "cve"]
            exploits = sum(v.get("exploit_count", 0) for v in dedup)
            crit_c = sum(1 for v in dedup if v.get("cvss", 0) >= 9.0)
            high_c = sum(1 for v in dedup if 7.0 <= v.get("cvss", 0) < 9.0)
            med_c  = sum(1 for v in dedup if 4.0 <= v.get("cvss", 0) < 7.0)
            low_c  = sum(1 for v in dedup if v.get("cvss", 0) < 4.0)
            vuln_items.append(
                f"""<div class="finding-row finding-severity-high"><span class="finding-label">CVE Database</span><span class="finding-value"><span class="badge badge-red">{crit_c + high_c} HIGH+</span><span class="finding-text">{len(cves)} unique CVEs across services — {crit_c} critical, {high_c} high, {med_c} medium, {low_c} low. {exploits} public exploits catalogued.</span></span></div>""")

        # Active vulnerabilities (http-vuln, git, etc.)
        agg = nmap_data["host"].get("vulnerabilities", [])
        for v in agg:
            sev = v.get("severity", "HIGH")
            badge = "badge-red" if sev == "CRITICAL" else ("badge-yellow" if sev == "HIGH" else "badge-blue")
            vuln_items.append(
                f"""<div class="finding-row finding-severity-high"><span class="finding-label">{html_escape(v.get('type','Vuln'))}</span><span class="finding-value"><span class="badge {badge}">{html_escape(v.get('state','FOUND'))}</span><span class="finding-text">{html_escape(v.get('title',''))}</span></span></div>""")

        # Git exposed (nmap)
        gex = nmap_data["host"].get("git_exposure_nmap")
        if gex:
            vuln_items.append(
                f"""<div class="finding-row finding-severity-critical"><span class="finding-label">Git Exposed</span><span class="finding-value"><span class="badge badge-red">CRITICAL</span><span class="finding-text">Nmap http-git: {len(gex['exposed_files'])} files exposed ({', '.join(gex['exposed_files'][:3])})</span></span></div>""")

    section("Vulnerabilities &amp; Exposures", vuln_items)

    # ── WEB / DISCOVERY section (FFUF + WhatWeb + Dirsearch) ──
    web_items = []
    if ffuf_data:
        total = ffuf_data.get("total_findings", 0)
        if total:
            web_items.append(
                f"""<div class="finding-row"><span class="finding-label">Endpoints</span><span class="finding-value"><span class="badge badge-blue">INFO</span><span class="finding-text">{total} endpoints discovered via FFUF directory brute-force.</span></span></div>""")

        git_sum = ffuf_data.get("git_summary")
        if git_sum:
            web_items.append(
                f"""<div class="finding-row finding-severity-high"><span class="finding-label">Git Files</span><span class="finding-value"><span class="badge badge-yellow">{git_sum['risk_level']}</span><span class="finding-text">{git_sum['exposed_file_count']} .git files via FFUF.</span></span></div>""")

        critical = ffuf_data.get("critical", [])
        non_git = [c for c in critical if ".git" not in c.get("url", "")]
        if non_git:
            web_items.append(
                f"""<div class="finding-row finding-severity-critical"><span class="finding-label">Sensitive</span><span class="finding-value"><span class="badge badge-red">CRITICAL</span><span class="finding-text">{len(non_git)} sensitive endpoint(s): {', '.join(c['fuzz_word'] for c in non_git[:4])}</span></span></div>""")

    # Dirsearch
    if dirsearch_data and dirsearch_data.get("true_positives_count", 0) > 0:
        tp = dirsearch_data["true_positives_count"]
        web_items.append(
            f"""<div class="finding-row"><span class="finding-label">Dir Enum</span><span class="finding-value"><span class="badge badge-blue">INFO</span><span class="finding-text">{tp} non-404 paths found via directory enumeration.</span></span></div>""")

    # WhatWeb tech
    if whatweb_data:
        tech = whatweb_data.get("technology_stack", [])
        if tech:
            names = ", ".join(t["plugin"] for t in tech)
            web_items.append(
                f"""<div class="finding-row"><span class="finding-label">Tech Stack</span><span class="finding-value"><span class="badge badge-green">DETECTED</span><span class="finding-text">{names}</span></span></div>""")



    # ── Build HTML ──
        subsections_html = ""
        for title, items in sections:
            subsections_html += f'<h4 class="key-findings-subsection">{title}</h4>' + "\n"
            subsections_html += "\n".join(items) + "\n"

        if not sections:
            subsections_html = '<p class="summary-text">No significant findings detected.</p>'

        # ── Severity Risk Matrix ──
        matrix = _build_risk_matrix(nmap_data, ffuf_data)

        return subsections_html + matrix



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
            Black Dragon detected <strong>{len(ports)} open ports</strong> on {html_escape(host['ip'])}
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


def _gated_section(container_id, items, label, free_count=2):
    """Wrap items in a paywall gate: show first `free_count` free, blur the rest behind a password."""
    if len(items) <= free_count:
        return "".join(items)

    free_html = "".join(items[:free_count])
    gated_html = "".join(items[free_count:])

    return free_html + f"""
    <div class="paywall-gated" id="{container_id}">
        <div class="gated-content">
            {gated_html}
        </div>
        <div class="gated-overlay">
            <span class="lock-text">&#x1F512; {len(items) - free_count} More {label} Locked</span>
            <span class="lock-sub">Enter password to reveal all {len(items)} {label.lower()}</span>
            <input type="password" class="pw-input" placeholder="Password" onkeydown="if(event.key==='Enter')unlockGate('{container_id}')">
            <span class="pw-error">Incorrect password</span>
            <button class="btn-unlock" onclick="unlockGate('{container_id}')">Unlock</button>
        </div>
    </div>"""


def _vuln_business_context(vuln):
    """Return (business_impact, remediation) strings for a vulnerability based on its type."""
    vtype = vuln.get("type", "")
    title = vuln.get("title", "").lower()

    # Git Exposure
    if vtype == "Git Exposure" or "git" in title:
        return (
            "Your source code, API keys, database passwords, and proprietary business logic may be exposed to anyone on the Internet. Competitors or attackers could extract intellectual property, find hardcoded credentials, and map your infrastructure — leading to full system compromise.",
            "Immediately restrict access to /.git/ in your web server or CDN configuration. Rotate ALL credentials and secrets that were ever committed to the repository. Use git-secrets or truffleHog to scan history for sensitive data."
        )
    # HSTS / security headers
    if "hsts" in title:
        return (
            "Without HSTS, your customers' connections can be silently downgraded from HTTPS to HTTP by attackers on public Wi-Fi or compromised networks. This enables credential theft, session hijacking, and injection of malicious content into your website.",
            "Enable the Strict-Transport-Security HTTP header on your web server with a max-age of at least 1 year and includeSubDomains. This tells browsers to always use HTTPS, even if the user types http://."
        )
    # Slowloris / DoS
    if "slowloris" in title or "denial" in title.lower():
        return (
            "An attacker can take your website offline using minimal resources — as little as a single laptop. Every minute of downtime costs your business revenue, damages customer trust, and may trigger SLA penalties with your own clients.",
            "Configure your web server (nginx/Apache) with rate limiting, lower timeout values for incomplete requests, and consider deploying a Web Application Firewall (WAF) or CDN that provides DDoS protection."
        )
    # CVE / Vulners
    if vtype == "CVE / Vulners" or "cve" in title.lower():
        cvss = vuln.get("cvss", 0)
        if cvss >= 9.0:
            return (
                "This is a critical-severity known vulnerability. Public exploits likely exist. If exploited, attackers could gain full control of your server, steal customer data, or use your infrastructure to attack others — causing regulatory fines and irreversible reputational damage.",
                "Patch the affected service to the latest version immediately. If patching is not possible, implement compensating controls: network segmentation, WAF rules, or disabling the vulnerable feature until a patch can be applied."
            )
        return (
            "Known vulnerabilities in your software stack are the most common entry point for ransomware and data breaches. Attackers actively scan the Internet for unpatched systems — your website is visible in these scans.",
            "Apply the latest security updates for the affected service. Subscribe to vendor security advisories. Establish a regular patch management cycle to stay ahead of threats."
        )
    # http-vuln / generic
    if vtype == "Vulnerability" or "vuln" in title.lower():
        return (
            "An exploitable condition was detected on your server. This could allow attackers to access restricted data, modify your website content, or use your server as a launchpad for further attacks.",
            "Follow the specific remediation steps in the references below. In general: update affected software, restrict access with firewall rules, and validate that the fix resolves the vulnerability by re-scanning."
        )
    # Missing Header
    if vtype == "Missing Header":
        return (
            "Missing security headers leave your visitors exposed to common web attacks like clickjacking, cross-site scripting, and MIME-type confusion. While not directly exploitable, these gaps weaken your overall security posture.",
            "Configure your web server to send modern security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."
        )
    # Default fallback
    return (
        "This finding represents a weakness in your security posture that could be exploited under certain conditions. Every unresolved vulnerability increases the cumulative risk to your organisation.",
        "Review the finding details and apply the appropriate fix. Re-scan after remediation to confirm the vulnerability is resolved. If you need assistance, Cyber Samurai provides managed remediation services."
    )


def _build_vulnerabilities_section(nmap_data):
    """Build the vulnerabilities findings section with business impact & remediation."""
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

    card_items = []
    for v in unique_vulns:
        sev_class = "card-red" if v.get("severity", "") in ("CRITICAL", "HIGH") else "card-orange"
        refs_html = ""
        if v.get("references"):
            refs_html = "<br>".join(
                f'<a href="{html_escape(r)}" target="_blank" style="color:var(--color-info)">{html_escape(r)}</a>'
                for r in v["references"]
            )

        # Business impact & remediation
        impact, remediation = _vuln_business_context(v)

        card_items.append(f"""
        <div class="glass-card {sev_class}">
            <div class="card-title">{html_escape(v.get('title', 'Unknown Finding'))}</div>
            <div style="margin:8px 0">
                <span class="badge badge-red">{html_escape(v.get('state', 'FOUND'))}</span>
                {f'<code style="margin-left:8px;color:var(--text-muted)">{html_escape(v.get("cve_id", ""))}</code>' if v.get('cve_id') and v['cve_id'] != 'N/A' else ''}
            </div>
            <p class="summary-text">{html_escape(v.get('description', 'No description available.'))}</p>
            <div class="vuln-business-impact"><strong>Business Impact:</strong> {impact}</div>
            <div class="vuln-remediation"><strong>Remediation:</strong> {remediation}</div>
            {f'<div style="margin-top:10px;font-size:12px;color:var(--text-muted)"><strong>References:</strong><br>{refs_html}</div>' if refs_html else ''}
        </div>
        """)

    # Also add HSTS findings summary
    hsts_missing_ports = []
    if nmap_data.get("host", {}).get("open_ports"):
        for port_info in nmap_data["host"]["open_ports"]:
            for vuln in port_info.get("vulnerabilities", []):
                if "HSTS" in vuln.get("title", ""):
                    hsts_missing_ports.append(str(port_info["port"]))

    if hsts_missing_ports:
        card_items.append(f"""
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
        """)

    return _gated_section("gate-vulns", card_items, "Vulnerabilities", FREE_PREVIEW_COUNT)


def _build_dirsearch_section(dirsearch_data):
    """Build directory enumeration results summary."""
    if not dirsearch_data:
        return '<div class="glass-card"><p class="summary-text">No directory scan data available.</p></div>'

    tp_count = dirsearch_data.get("true_positives_count", 0)
    fp_count = dirsearch_data.get("false_positives_count", 0)
    total = dirsearch_data.get("total_results", 0)

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
            The fingerpprint of your website reaveal the following information and technologies and characteristics
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


def _build_ffuf_section(ffuf_data):
    """Build the Asset Discovery section from FFUF results."""
    if not ffuf_data:
        return '<div class="glass-card"><p class="summary-text">No FFUF directory brute-force data available.</p></div>'

    total = ffuf_data.get("total_findings", 0)
    critical = ffuf_data.get("critical", [])
    high = ffuf_data.get("high", [])
    medium = ffuf_data.get("medium", [])
    low = ffuf_data.get("low", [])
    git_summary = ffuf_data.get("git_summary")
    scan_info = ffuf_data.get("scan_info", {})

    # ── .git exposure banner (if applicable) ──
    git_html = ""
    if git_summary:
        git_html = f"""
        <div class="glass-card card-red" style="margin-bottom:20px">
            <div class="card-title">.git Repository <span class="badge badge-red">{git_summary['risk_level']}</span></div>
            <div class="highlight-box">
                {html_escape(git_summary['summary_text'])}
            </div>
            <h4 style="color:var(--text-secondary);font-size:14px;margin:16px 0 8px 0">
                Exposed Git Files ({git_summary['exposed_file_count']} files)
            </h4>
    """

        for f in git_summary.get("exposed_files", []):
            git_html += f"""
            <div class="exposure-card exposed-file">
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <strong style="font-family:monospace;font-size:12px;color:var(--color-critical)">{html_escape(f['path'])}</strong>
                    <span class="badge badge-red">EXPOSED</span>
                </div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">
                    Size: {f['size_bytes']:,} bytes | Type: {html_escape(f['content_type'])} | Status: {f['status']}
                </div>
                <div style="font-size:11px;color:var(--text-muted);word-break:break-all;margin-top:2px">
                    {html_escape(f['url'])}
                </div>
            </div>
        """

        git_html += """
            <div class="highlight-box" style="margin-top:16px;background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.15)">
                <strong style="color:var(--color-pass)">Remediation:</strong> Block access to <code>/.git/</code> at the web server level.
                Never deploy <code>.git</code> directories to production. Rotate any credentials potentially exposed in commit history.
            </div>
        </div>
        """

    # ── Build categorized results table ──
    def _build_finding_rows(findings, severity_label, badge_class):
        if not findings:
            return ""
        rows = ""
        for entry in findings:
            sc = entry["status"]
            sc_badge = "badge-red" if sc == 200 else "badge-yellow"
            rows += f"""
                <tr>
                    <td><span class="badge {sc_badge}" style="font-size:10px">{sc}</span></td>
                    <td class="mono" style="font-size:11px">{html_escape(entry['url'])}</td>
                    <td>{html_escape(entry.get('content_type', ''))}</td>
                    <td>{entry['length']:,}</td>
                    <td>{entry.get('duration_ms', 0)}ms</td>
                </tr>
            """
        header_color = {
            "CRITICAL": "var(--color-critical)",
            "HIGH": "var(--color-warning)",
            "MEDIUM": "var(--color-info)",
            "LOW": "var(--color-pass)",
        }.get(severity_label, "var(--text-secondary)")

        return f"""
        <div style="margin-bottom:20px">
            <h4 style="color:{header_color};font-size:14px;margin:12px 0 6px 0">
                <span class="badge {badge_class}">{severity_label}</span> — {len(findings)} finding(s)
            </h4>
            <div style="overflow-x:auto;max-height:400px;overflow-y:auto">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>URL</th>
                            <th>Content Type</th>
                            <th>Size (bytes)</th>
                            <th>Response</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
        """

    # Status breakdown
    status_html = ""
    for status, count in sorted(ffuf_data.get("status_counts", {}).items()):
        badge_class = "badge-red" if status == 200 else "badge-yellow"
        status_html += f'<span class="badge {badge_class}">{status}: {count}</span> '

    # Content type breakdown
    ct_html = ""
    for ct, count in sorted(ffuf_data.get("content_type_counts", {}).items(), key=lambda x: -x[1]):
        ct_html += f'<span class="tech-tag">{html_escape(ct)} ({count})</span> '

    # Gate detailed findings — collect individual endpoint rows, gate beyond preview count
    all_finding_rows = []
    for entry in critical + high + medium + low:
        sc = entry["status"]
        sc_badge = "badge-red" if sc == 200 else "badge-yellow"
        all_finding_rows.append(f"""
                <tr>
                    <td><span class="badge {sc_badge}" style="font-size:10px">{sc}</span></td>
                    <td class="mono" style="font-size:11px">{html_escape(entry['url'])}</td>
                    <td>{html_escape(entry.get('content_type', ''))}</td>
                    <td>{entry['length']:,}</td>
                    <td>{entry.get('duration_ms', 0)}ms</td>
                </tr>
        """)

    free_finding_rows = "".join(all_finding_rows[:FREE_PREVIEW_COUNT])
    gated_findings_block = ""
    if len(all_finding_rows) > FREE_PREVIEW_COUNT:
        gated_rows_html = "".join(all_finding_rows[FREE_PREVIEW_COUNT:])
        gated_findings_block = f"""
    <div class="paywall-gated" id="gate-ffuf" style="margin-top:8px">
        <div class="gated-content">
            <div class="glass-card" style="margin-top:0">
                <div class="card-title">Detailed Findings — <span class="badge badge-red">LOCKED</span></div>
                <div style="overflow-x:auto;max-height:400px;overflow-y:auto">
                    <table class="data-table">
                        <thead>
                            <tr><th>Status</th><th>URL</th><th>Content Type</th><th>Size (bytes)</th><th>Response</th></tr>
                        </thead>
                        <tbody>{gated_rows_html}</tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="gated-overlay">
            <span class="lock-text">&#x1F512; {len(all_finding_rows) - FREE_PREVIEW_COUNT} More Endpoints Locked</span>
            <span class="lock-sub">Enter password to reveal all {len(all_finding_rows)} endpoints</span>
            <input type="password" class="pw-input" placeholder="Password" onkeydown="if(event.key==='Enter')unlockGate('gate-ffuf')">
            <span class="pw-error">Incorrect password</span>
            <button class="btn-unlock" onclick="unlockGate('gate-ffuf')">Unlock</button>
        </div>
    </div>
"""

    return f"""
    <div class="glass-card">
        <div class="card-title">Web Discovery</div>
        <p class="summary-text" style="margin-bottom:12px">
            During the scan the following was identified:
            <strong style="color:var(--color-info)">{total} endpoints</strong>.
            <strong style="color:var(--color-critical)">{len(critical)} critical</strong>,
            <strong style="color:var(--color-warning)">{len(high)} high</strong>,
            <strong style="color:var(--color-info)">{len(medium)} medium</strong>, and
            {len(low)} low-severity findings.
        </p>
        <div style="margin-bottom:12px">
            <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px">Content Types: </span>
            {ct_html}
        </div>
        <div style="overflow-x:auto;max-height:400px;overflow-y:auto">
            <table class="data-table">
                <thead>
                    <tr><th>Status</th><th>URL</th><th>Content Type</th><th>Size (bytes)</th><th>Response</th></tr>
                </thead>
                <tbody>{free_finding_rows}</tbody>
            </table>
        </div>
    </div>

    {git_html}
    {gated_findings_block}
    """ 


# ─── Main ────────────────────────────────────────────────────────────────────


def _build_vulners_section(nmap_data):
    """Build the Vulnerability Assessment table from vulners NSE script."""
    if not nmap_data or not nmap_data.get("host"):
        return '<div class="glass-card"><p class="summary-text">No vulnerability assessment data available.</p></div>'

    vulners = nmap_data["host"].get("vulners_deduped") or nmap_data["host"].get("vulners_entries", [])
    if not vulners:
        return '<div class="glass-card card-green"><div class="card-title">No CVEs Detected</div><p class="summary-text">Vulners NSE script found no known CVEs matching the detected service versions.</p></div>'

    vulners_sorted = sorted(vulners, key=lambda x: -x.get("cvss", 0))
    real_cves = [v for v in vulners_sorted if v.get("type") == "cve"]
    crit = sum(1 for v in vulners_sorted if v.get("cvss", 0) >= 9.0)
    high = sum(1 for v in vulners_sorted if 7.0 <= v.get("cvss", 0) < 9.0)
    med  = sum(1 for v in vulners_sorted if 4.0 <= v.get("cvss", 0) < 7.0)
    low  = sum(1 for v in vulners_sorted if v.get("cvss", 0) < 4.0)
    total_exploits = sum(v.get("exploit_count", 0) for v in vulners_sorted)
    services = sorted(set(v.get("service", "Unknown") for v in vulners_sorted))

    row_items = []
    for v in vulners_sorted:
        cvss = v.get("cvss", 0)
        if cvss >= 9.0:
            sev_badge = "badge-red"
        elif cvss >= 7.0:
            sev_badge = "badge-yellow"
        elif cvss >= 4.0:
            sev_badge = "badge-blue"
        else:
            sev_badge = "badge-green"

        exploit_count = v.get("exploit_count", 0)
        if exploit_count > 0:
            exploit_badge = f'<span class="badge badge-red" style="font-size:9px">{exploit_count} EXPLOIT{"S" if exploit_count > 1 else ""}</span>'
        else:
            exploit_badge = ""

        cve_marker = '<span class="badge badge-blue" style="font-size:9px">CVE</span>' if v.get("type") == "cve" else ""
        vid = v['id']
        vuln_url = f'https://vulners.com/search?query={vid}'

        row_items.append(f"""
            <tr>
                <td><span class="badge {sev_badge}" style="font-size:10px">{v['severity']}</span></td>
                <td class="mono" style="font-size:11px"><a href="{vuln_url}" target="_blank" style="color:var(--color-info)"><strong>{html_escape(vid)}</strong></a></td>
                <td>{cvss}</td>
                <td>{html_escape(v.get('service', 'N/A'))}</td>
                <td>{exploit_badge} {cve_marker}</td>
            </tr>
        """)

    free_rows = "".join(row_items[:FREE_PREVIEW_COUNT])
    gated_block = ""
    if len(row_items) > FREE_PREVIEW_COUNT:
        gated_rows_html = "".join(row_items[FREE_PREVIEW_COUNT:])
        gated_block = f"""
    <div class="paywall-gated" id="gate-vulners" style="margin-top:8px">
        <div class="gated-content">
            <div class="glass-card" style="margin-top:0">
                <div style="overflow-x:auto;max-height:600px;overflow-y:auto">
                    <table class="data-table">
                        <thead>
                            <tr><th>Severity</th><th>Vulnerability ID</th><th>CVSS</th><th>Service</th><th>Exploits</th></tr>
                        </thead>
                        <tbody>{gated_rows_html}</tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="gated-overlay">
            <span class="lock-text">&#x1F512; {len(row_items) - FREE_PREVIEW_COUNT} More CVEs Locked</span>
            <span class="lock-sub">Enter password to reveal all {len(row_items)} CVEs</span>
            <input type="password" class="pw-input" placeholder="Password" onkeydown="if(event.key==='Enter')unlockGate('gate-vulners')">
            <span class="pw-error">Incorrect password</span>
            <button class="btn-unlock" onclick="unlockGate('gate-vulners')">Unlock</button>
        </div>
    </div>
"""

    html = f"""
    <div class="glass-card">
        <div class="card-title">Vulnerability Assessment — Vulners CVE Database</div>
        <p class="summary-text" style="margin-bottom:12px">
            Black Dragon detected service versions against the CVE database.
            <strong style="color:var(--color-info)">{len(real_cves)} unique CVEs</strong>
            identified across {len(services)} service(s):
            <strong style="color:var(--color-critical)">{crit} Critical</strong>,
            <strong style="color:var(--color-warning)">{high} High</strong>,
            <strong style="color:var(--color-info)">{med} Medium</strong>,
            <strong style="color:var(--color-pass)">{low} Low</strong>.
            <strong style="color:var(--color-critical)">{total_exploits} public exploits available</strong> across all CVEs.
        </p>
        <p class="summary-text" style="margin-bottom:16px;font-size:12px">
            Affected services: <strong>{', '.join(services)}</strong><br>
            <span style="color:var(--text-muted)">IDs link to vulners.com search. Exploit counts show known public exploits per CVE.</span>
        </p>
        <div style="overflow-x:auto;max-height:600px;overflow-y:auto">
            <table class="data-table">
                <thead>
                    <tr><th>Severity</th><th>Vulnerability ID</th><th>CVSS</th><th>Service</th><th>Exploits</th></tr>
                </thead>
                <tbody>{free_rows}</tbody>
            </table>
        </div>
    </div>
    {gated_block}

    <!-- ═══ Inner Tab: All Vulners Raw Entries ═══ -->
    <div class="inner-tabs-nav" style="margin-top:16px">
        <button class="inner-tab-btn active" onclick="switchInnerTab(this, 'inner-vulners-all')">All Vulners Entries</button>
    </div>
    """

    html += _build_all_vulners_table(nmap_data)

    return html




def _build_all_vulners_table(nmap_data):
    """Build detailed table of ALL raw vulners entries with vulners.com links."""
    if not nmap_data or not nmap_data.get("host"):
        return ""

    vulners = nmap_data["host"].get("vulners_entries", [])
    if not vulners:
        return ""

    vulners_sorted = sorted(vulners, key=lambda x: -x.get("cvss", 0))

    rows = ""
    for v in vulners_sorted:
        cvss = v.get("cvss", 0)
        if cvss >= 9.0:
            sev_badge = "badge-red"
        elif cvss >= 7.0:
            sev_badge = "badge-yellow"
        elif cvss >= 4.0:
            sev_badge = "badge-blue"
        else:
            sev_badge = "badge-green"

        vid = v['id']
        vtype = v.get('type', 'unknown')
        is_cve = vtype == 'cve'
        cve_badge = '<span class="badge badge-blue" style="font-size:9px">CVE</span>' if is_cve else '<span class="badge" style="font-size:9px;background:rgba(255,255,255,0.05)">{}</span>'.format(vtype)
        vuln_url = f'https://vulners.com/search?query={vid}'

        rows += f"""
            <tr>
                <td><span class="badge {sev_badge}" style="font-size:10px">{v['severity']}</span></td>
                <td class="mono" style="font-size:10px"><a href="{vuln_url}" target="_blank" style="color:var(--color-info)">{html_escape(vid)}</a></td>
                <td>{cvss}</td>
                <td>{cve_badge}</td>
                <td style="font-size:11px">{html_escape(v.get('service', 'N/A'))}</td>
                <td><a href="{vuln_url}" target="_blank" style="color:var(--color-info);font-size:10px">vulners.com &nearr;</a></td>
            </tr>
        """

    return f"""
    <div class="inner-tab-content active" id="inner-vulners-all" style="margin-top:0">
        <div class="glass-card">
            <div class="card-title">All Vulners Entries ({len(vulners_sorted)} raw)</div>
            <p class="summary-text" style="margin-bottom:12px;font-size:12px">
                Complete list of all vulnerability database entries matched against detected service versions.
                Each ID links to its vulners.com page for full details including exploit code and remediation guidance.
            </p>
            <div style="overflow-x:auto;max-height:500px;overflow-y:auto">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Vulners ID</th>
                            <th>CVSS</th>
                            <th>Type</th>
                            <th>Service</th>
                            <th>Link</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    """


def _build_os_section(nmap_data):
    """Build OS Detection card."""
    if not nmap_data or not nmap_data.get("host"):
        return '<div class="glass-card"><p class="summary-text">No OS detection data available.</p></div>'

    os_data = nmap_data["host"].get("os_detection")
    if not os_data or not os_data.get("matches"):
        return '<div class="glass-card"><p class="summary-text">OS detection inconclusive.</p></div>'

    matches = os_data["matches"][:3]
    rows = ""
    for m in matches:
        accuracy_pct = int(m["accuracy"])
        acc_color = "var(--color-pass)" if accuracy_pct >= 90 else "var(--color-warning)"
        classes_html = ""
        for c in m.get("classes", []):
            classes_html += f'<span class="tech-tag">{html_escape(c.get("vendor", ""))} {html_escape(c.get("osfamily", ""))} {html_escape(c.get("osgen", ""))}</span> '
        rows += f"""
            <tr>
                <td><strong>{html_escape(m['name'])}</strong></td>
                <td><span style="color:{acc_color};font-weight:700">{accuracy_pct}%</span></td>
                <td>{classes_html}</td>
            </tr>
        """

    # ── Services summary ──
    svc_html = ""
    ports = nmap_data["host"].get("open_ports", [])
    if ports:
        svc_rows = ""
        for p in sorted(ports, key=lambda x: x["port"]):
            svc_rows += f"""
                <tr>
                    <td class="mono"><strong>{p['port']}/{p['protocol']}</strong></td>
                    <td>{html_escape(p.get('service_name',''))}</td>
                    <td>{html_escape(p.get('service_full_version',''))}</td>
                </tr>
            """
        svc_html = f"""
        <div class="glass-card" style="margin-top:16px">
            <div class="card-title">Running Services ({len(ports)} open ports)</div>
            <table class="data-table">
                <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
                <tbody>{svc_rows}</tbody>
            </table>
        </div>"""

    # ── SSH Host Keys ──
    ssh_html = ""
    for p in ports:
        keys = p.get("ssh_keys", [])
        if keys:
            key_rows = ""
            for k in keys:
                key_rows += f"""
                    <tr>
                        <td class="mono" style="font-size:11px">{html_escape(k.get('type','?'))}</td>
                        <td class="mono" style="font-size:11px">{html_escape(k.get('bits','?'))} bits</td>
                        <td class="mono" style="font-size:11px;word-break:break-all">{html_escape(k.get('fingerprint',''))}</td>
                    </tr>
                """
            ssh_html = f"""
            <div class="glass-card" style="margin-top:16px">
                <div class="card-title">SSH Host Keys (Port {p['port']})</div>
                <table class="data-table">
                    <thead><tr><th>Algorithm</th><th>Bits</th><th>Fingerprint</th></tr></thead>
                    <tbody>{key_rows}</tbody>
                </table>
            </div>"""
            break  # Only first SSH port



    return f"""
    <div class="glass-card card-blue">
        <div class="card-title">Operating System Detection</div>
        <p class="summary-text" style="margin-bottom:12px">
            OS fingerprinting identified the following likely operating systems
            on <code>{html_escape(nmap_data['host']['ip'])}</code>.
        </p>
        <table class="data-table">
            <thead><tr><th>OS Match</th><th>Accuracy</th><th>Classification</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
    {svc_html}
    {ssh_html}
    """


def _build_nmap_git_section(nmap_data):
    """Build .git exposure section from Nmap http-git script."""
    if not nmap_data or not nmap_data.get("host"):
        return ""
    gex = nmap_data["host"].get("git_exposure_nmap")
    if not gex:
        return ""

    exposed_html = ""
    for fname in gex.get("exposed_files", []):
        exposed_html += f"""
        <div class="exposure-card exposed-file">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <strong style="font-family:monospace;font-size:12px;color:var(--color-critical)">{html_escape(fname)}</strong>
                <span class="badge badge-red">EXPOSED</span>
            </div>
        </div>
        """

    remotes_html = ""
    for r in gex.get("remotes", []):
        remotes_html += f'<li><code>{html_escape(r)}</code></li>'

    return f"""
    <div class="glass-card card-red">
        <div class="card-title">.git Repository Exposed via Nmap <span class="badge badge-red">{gex['risk_level']}</span></div>
        <div class="highlight-box">
            Nmap\'s <code>http-git</code> script discovered a publicly accessible Git repository.
            {len(gex['exposed_files'])} repository files are directly downloadable.
            {f'Remote origin: {", ".join(gex.get("remotes", []))}.' if gex.get("remotes") else ''}
        </div>
        <h4 style="color:var(--text-secondary);font-size:14px;margin:16px 0 8px 0">
            Exposed Files ({len(gex['exposed_files'])} files)
        </h4>
        {exposed_html}
        {f'<h4 style="color:var(--text-secondary);font-size:14px;margin:16px 0 8px 0">Remote Origins</h4><ul style="color:var(--text-secondary);font-size:13px">{remotes_html}</ul>' if gex.get("remotes") else ''}
        <div class="highlight-box" style="margin-top:16px;background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.15)">
            <strong style="color:var(--color-pass)">Remediation:</strong> Block <code>/.git/</code> at the web server level.
            Never deploy <code>.git</code> directories to production.
        </div>
    </div>
    """


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


    # ── Step 2: Parse WhatWeb JSON ──
    print("[*] Parsing WhatWeb results...")
    whatweb_data = parse_whatweb_results(WHATWEB_FILE)
    if whatweb_data:
        tech_count = len(whatweb_data.get("technology_stack", []))
        print(f"    → Identified {tech_count} technologies on {whatweb_data.get('target', 'Unknown')}")
    else:
        print("    ⚠ No WhatWeb data loaded")

    # ── Step 3: Parse FFUF JSON ──
    print("[*] Parsing Web Discovery...")
    ffuf_data = parse_ffuf_results(FFUF_FILE)
    if ffuf_data:
        total = ffuf_data.get("total_findings", 0)
        critical = len(ffuf_data.get("critical", []))
        git = len(ffuf_data.get("git_findings", []))
        print(f"    → Discovered {total} endpoints, {critical} critical, {git} .git exposures")
    else:
        print("    ⚠ No FFUF data loaded")

    # ── Step 4: Build HTML Report ──
    print(f"[*] Compiling HTML report → {OUTPUT_FILE}")
    build_html_report(nmap_data, None, whatweb_data, ffuf_data, OUTPUT_FILE)

    # ── Summary ──
    print()
    print("════════════════════════════════════════════════")
    print("  Report generation complete.")
    print(f"  Output: {OUTPUT_FILE}")
    print("════════════════════════════════════════════════")


if __name__ == "__main__":
    main()
