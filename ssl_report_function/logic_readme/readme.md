# 📋 Logic Documentation Index

This directory contains the detailed technical specifications, scoring algorithms, and logic walkthroughs for the individual components of the SSL/TLS report module.

---

## 🚀 Orchestration & Execution

To run the complete SSL/TLS and HTTP headers security assessment suite, call the orchestrator script:

```bash
runTLSReport.sh <domain>
```

For example, to run the assessment on `cybersamurai.co.uk`:
```bash
./runTLSReport.sh cybersamurai.co.uk
```

For a step-by-step walkthrough of the orchestrator script's execution path and logic flow, see [run_tls_report_readme.md](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/logic_readme/run_tls_report_readme.md).

---

## 🔍 Detailed Component Walkthroughs

Click on the files below to view the technical specifications and logic for specific features:

### 1. [TLS Security Health Score Logic](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/logic_readme/score_logic_readme.md)
Detailed walkthrough of how vulnerabilities, protocol versions, and cipher suite grades are analyzed to produce a percentage-based security health score (e.g., `SECURE`, `STRONG`, `WARNING`, `CRITICAL`).

### 2. [Certificate Retrieval & Chain Validation Logic](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/logic_readme/cert_fetch_logic_readme.md)
Technical details of using OpenSSL `s_client` to retrieve complete certificate parameters, identify issuer attributes, verify the certificate trust chain, and display it in the enhanced HTML report.

### 3. [Website Security Assessment & HTTP Header Analysis](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/ssl_report_function/logic_readme/curl_report_logic_readme.md)
Detailed breakdown of curl-based security checks, including missing security headers (HSTS, CSP, X-Frame-Options), cookie settings (Secure, HttpOnly, SameSite flag validation), information leakage checks, and risk scoring metrics.
