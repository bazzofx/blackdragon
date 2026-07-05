# 🛡️ SSL/TLS Report Function Module

This module automates the execution of comprehensive SSL/TLS security audits and HTTP header assessments, compiling the findings into client-ready, high-fidelity security reports.

---

## 🔍 Purpose

The main purpose of the tools in this folder is to perform an end-to-end security assessment of a target domain. It verifies DNS settings, performs a containerized SSL/TLS scan via `testssl.sh`, assesses HTTP security headers/cookies, and parses and enhances the output into a premium client-facing HTML dashboard.

---

## 🚀 How to Run

You run the scan orchestrator by executing the [runTLSReport.sh](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/runTLSReport.sh) script.

```bash
./runTLSReport.sh <domain>
```

### Example
```bash
./runTLSReport.sh cybersamurai.co.uk
```

### Dependencies & Setup
- **Docker**: Must be running to pull and execute the `testssl.sh` container scanner (`ghcr.io/testssl/testssl.sh`).
- **Python 3**: Used for processing raw reports and parsing security metrics.
- **nslookup** or **ping**: Used for pre-flight domain DNS validation.

---

## ✨ Features

- **Automated DNS Verification**: Pre-checks that the target domain successfully resolves to prevent starting scans on unreachable hosts.
- **Containerized TLS Scanning**: Utilizes a lightweight, transient Docker container running `testssl.sh` with custom user agents and request headers (`X-Custom-Header`).
- **HTTP Header & Cookie Assessment**: Audits security controls like HSTS, Content-Security-Policy (CSP), Clickjacking protection, server banners, and cookie security flags (Secure, HttpOnly, SameSite).
- **Fallback Capability**: Includes cached local scan files to facilitate offline testing or fallback execution for specific development targets.
- **Unified Premium Report**: Combines all security findings, protocol analysis, and vulnerability reviews into a styled client-facing HTML document with health score ratings.

---

## 📂 Folder Structure

- [runTLSReport.sh](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/runTLSReport.sh) - Orchestrator bash script.
- [fetch.sh](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/fetch.sh) - Wrapper to trigger the HTTP assessment Python module.
- [generateTLSReport.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/generateTLSReport.py) - Main HTML parsing, scoring, and report enhancement script.
- [docs/](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/docs) - Consolidated folder containing all script user guides and technical logic walkthroughs.
- [test_units/](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/test_units) - Folder containing unit tests and test assets.
- [archive/](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/archive) - Directory for legacy/unused openSSL and curl scripts.

