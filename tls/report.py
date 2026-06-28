#!/usr/bin/env python3
"""
testssl_report_enhancer.py - Parse testssl.sh HTML report and generate
a modern, branded summary with key findings highlighted.
"""

import re
import sys
import os
import argparse
import base64
from datetime import datetime
from html import escape
from typing import Dict, List, Tuple, Optional

# Rich details for known vulnerabilities to show in the detailed breakdown
VULN_DETAILS = {
    'Heartbleed': {
        'name': 'Heartbleed (CVE-2014-0160)',
        'description': 'A serious vulnerability in the popular OpenSSL cryptographic software library. It allows stealing information protected, under normal conditions, by the SSL/TLS encryption.',
        'remediation': 'Upgrade OpenSSL to version 1.0.1g or newer. Reissue SSL certificates that may have been compromised, and revoke the old ones.'
    },
    'CCS': {
        'name': 'OpenSSL MITM CCS Injection (CVE-2014-0224)',
        'description': 'Allows man-in-the-middle attackers to decrypt and modify traffic between a vulnerable client and server by injecting a ChangeCipherSpec message before the handshake is complete.',
        'remediation': 'Upgrade OpenSSL to the latest stable release (at least 1.0.1h, 1.0.0m, or 0.9.8za).'
    },
    'Ticketbleed': {
        'name': 'Ticketbleed (CVE-2016-9244)',
        'description': 'An information disclosure vulnerability in the TLS session ticket resumption implementation in certain F5 BIG-IP products. It allows remote attackers to leak up to 31 bytes of memory.',
        'remediation': 'Apply the vendor patch from F5 Networks, or disable TLS session tickets if patches cannot be applied.'
    },
    'Opossum': {
        'name': 'Opossum (CVE-2025-49812)',
        'description': 'A vulnerability that could lead to session hijacking or sensitive data exposure due to weak session key generation in older TLS implementations.',
        'remediation': 'Apply system patches and upgrade the server TLS stack to modern versions.'
    },
    'ROBOT': {
        'name': 'ROBOT (Return Of Bleichenbacher\'s Oracle Threat)',
        'description': 'Allows attackers to perform RSA decryption and signing operations using the private key of the TLS server by observing server responses to invalid RSA ciphertexts.',
        'remediation': 'Disable RSA key transport cipher suites (those starting with TLS_RSA_). Configure the server to use ECDHE or DHE key exchange ciphers.'
    },
    'Secure Renegotiation': {
        'name': 'Secure Renegotiation (RFC 5746)',
        'description': 'Insecure renegotiation allows an attacker to inject arbitrary plaintext at the beginning of the TLS stream in a man-in-the-middle scenario.',
        'remediation': 'Ensure the server supports and requires RFC 5746 Secure Renegotiation. Disable renegotiation entirely if not needed.'
    },
    'Client-Initiated Renegotiation': {
        'name': 'Secure Client-Initiated Renegotiation',
        'description': 'Allowing clients to initiate renegotiation consumes significant server resources (CPU) and can be abused for DoS attacks.',
        'remediation': 'Disable client-initiated renegotiation on the server. Most web servers (Nginx, Apache, IIS) support this configuration.'
    },
    'CRIME': {
        'name': 'CRIME (CVE-2012-4929)',
        'description': 'Allows man-in-the-middle attackers to decrypt HTTPS cookies and hijack sessions by exploiting TLS compression.',
        'remediation': 'Disable SSL/TLS level compression. Modern browsers and servers do not use TLS compression by default.'
    },
    'BREACH': {
        'name': 'BREACH (CVE-2013-3587)',
        'description': 'Exploits HTTP-level compression (gzip/deflate) combined with user-controlled input and secrets in the response body to extract sensitive data like CSRF tokens.',
        'remediation': 'Disable HTTP compression for sensitive pages containing secrets. Alternatively, use anti-CSRF token masking, randomize padding length, or disable compression dynamically based on request path.'
    },
    'POODLE': {
        'name': 'POODLE (CVE-2014-3566)',
        'description': 'An exploit that targets the SSLv3 protocol, allowing an attacker to decrypt ciphertext by exploiting block cipher padding oracle vulnerabilities.',
        'remediation': 'Completely disable SSLv3 on the server. Configure servers to only allow TLSv1.2 and TLSv1.3.'
    },
    'TLS_FALLBACK_SCSV': {
        'name': 'TLS_FALLBACK_SCSV (RFC 7507)',
        'description': 'Prevents protocol downgrade attacks by signalling to the server that a client is falling back to a lower protocol version due to connection failure.',
        'remediation': 'Ensure the server supports the TLS_FALLBACK_SCSV extension (built into modern OpenSSL versions).'
    },
    'SWEET32': {
        'name': 'SWEET32 (CVE-2016-2183)',
        'description': 'Affects 64-bit block ciphers like 3DES and Blowfish. In a long-lived TLS session, an attacker can capture enough ciphertexts to recover plaintext blocks via collision attacks.',
        'remediation': 'Disable 3DES and Blowfish cipher suites. Rely on AES (Advanced Encryption Standard) or ChaCha20.'
    },
    'FREAK': {
        'name': 'FREAK (CVE-2015-0204)',
        'description': 'Allows man-in-the-middle attackers to force clients to use weak export-grade RSA keys (typically 512-bit), which can then be factored and broken in real-time.',
        'remediation': 'Disable export-grade RSA key exchange and weak ciphers. Upgrade browser client software.'
    },
    'DROWN': {
        'name': 'DROWN (CVE-2016-0800)',
        'description': 'A cross-protocol attack that allows decrypting TLS traffic by making connections to an SSLv2 server that shares the same private key.',
        'remediation': 'Disable SSLv2 on all servers. Ensure that any server sharing the same certificate/private key also has SSLv2 disabled.'
    },
    'LOGJAM': {
        'name': 'LOGJAM (CVE-2015-4000)',
        'description': 'Allows man-in-the-middle attackers to downgrade vulnerable TLS connections to 512-bit export-grade Diffie-Hellman cryptography, which can then be broken.',
        'remediation': 'Disable export-grade Diffie-Hellman ciphers. Configure the server to use strong Diffie-Hellman groups of at least 2048 bits.'
    },
    'BEAST': {
        'name': 'BEAST (CVE-2011-3389)',
        'description': 'An attack against TLS 1.0 that decrypts HTTPS cookies by exploiting initialization vector predictability in CBC cipher suites.',
        'remediation': 'Disable TLS 1.0 (and TLS 1.1) on the server. Prioritize GCM ciphers (which use TLS 1.2+) or ChaCha20-Poly1305.'
    },
    'LUCKY13': {
        'name': 'LUCKY13 (CVE-2013-0169)',
        'description': 'A timing attack against TLS implementations using Cipher Block Chaining (CBC) mode, allowing remote attackers to recover plaintext bytes from TLS sessions.',
        'remediation': 'Configure the server to prefer AES-GCM or ChaCha20-Poly1305 ciphers over CBC-based ciphers. Disable TLS 1.0 and 1.1.'
    },
    'Winshock': {
        'name': 'Winshock (CVE-2014-6321)',
        'description': 'Allows remote code execution on Windows servers running Schannel due to improper packet handling during handshakes.',
        'remediation': 'Apply Microsoft security update MS14-066 immediately for Windows Server platforms.'
    },
    'RC4': {
        'name': 'RC4 Biases (CVE-2013-2566, CVE-2015-2808)',
        'description': 'RC4 has known statistical biases that allow an attacker to recover plaintexts (like session cookies) by sniffing a large amount of encrypted traffic.',
        'remediation': 'Disable all RC4-based cipher suites on the server.'
    }
}

class TestSSLReportParser:
    """Parse and extract key findings from testssl.sh HTML output."""

    def __init__(self, content: str):
        self.content = content
        self.findings = {
            'target': '',
            'ip_addresses': [],
            'service': '',
            'certificate': {},
            'protocols': {'supported': [], 'vulnerable': []},
            'ciphers': {'strong': [], 'weak': [], 'forward_secrecy': []},
            'vulnerabilities': {},
            'ocsp_stapling': 'Not tested',
            'breach': False
        }
        self._parse()

    def _clean_html(self, text: str) -> str:
        """Remove HTML tags from text for clean display."""
        # Remove span tags with their content preserved
        text = re.sub(r'<span[^>]*>', '', text)
        text = re.sub(r'</span>', '', text)
        text = re.sub(r'<u>', '', text)
        text = re.sub(r'</u>', '', text)
        text = re.sub(r'<i>', '', text)
        text = re.sub(r'</i>', '', text)
        text = re.sub(r'<a[^>]*>', '', text)
        text = re.sub(r'</a>', '', text)
        # Remove any remaining HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        # Remove common entities
        text = text.replace('&quot;', '"').replace('&apos;', "'").replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        return text.strip()

    def _determine_severity(self, status: str, detail: str) -> str:
        """
        Determine severity based on status text and detail.
        Only marks as CRITICAL if explicitly vulnerable.
        """
        combined = f"{status} {detail}".lower()

        # Check for negations FIRST
        if 'not vulnerable' in combined or 'not vuln' in combined:
            return 'PASS'
        if 'no rc4' in combined:
            return 'PASS'
        if 'no cipher' in combined:
            return 'PASS'
        if 'does not support' in combined:
            return 'PASS'

        # CRITICAL: Vulnerable indicators
        if 'vulnerable' in combined or 'vuln' in combined:
            return 'CRITICAL'

        if 'not ok' in combined:
            # Check if it is a potential vulnerability
            if 'potentially' in combined:
                return 'WARNING'
            return 'CRITICAL'

        # WARNING: Potentially vulnerable
        if 'potentially' in combined:
            return 'WARNING'

        # WARNING: Needs attention
        if 'check patches' in combined:
            return 'WARNING'

        # WARNING: Likely mitigated but still flagged
        if 'likely mitigated' in combined:
            return 'WARNING'

        # PASS: Everything else is OK
        return 'PASS'

    def _parse(self):
        """Parse the HTML content for key findings."""
        lines = self.content.split('\n')

        # Track which vulnerabilities we've already processed
        processed_vulns = set()

        for i, line in enumerate(lines):
            clean_line = self._clean_html(line)
            if not clean_line:
                continue
            
            # Target and IP
            # Domain capture using regex
            if '--&gt;&gt;' in line or '-->>' in line:
                domain_match = re.search(r'(?<=\()[^)]+\.[^)]+(?=\))', clean_line)
                if domain_match:
                    self.findings['target'] = domain_match.group(0)

            # IP capture using regex
            ip_match = re.match(r'^Testing all IP addresses.*:\s*(\d{1,3}(?:\.\d{1,3}){3}(?:\s+\d{1,3}(?:\.\d{1,3}){3})*)$', clean_line)
            if ip_match:
                ips = ip_match.group(1).split()
                for ip in ips:
                    if ip not in self.findings['ip_addresses']:
                        self.findings['ip_addresses'].append(ip)

            # Service detection
            if 'Service detected' in line:
                match = re.search(r'Service detected[:\s]+(\w+)', line)
                if match:
                    self.findings['service'] = match.group(1)

            # Protocol detection - look for TLS versions
            if '<u>TLSv' in line:
                proto_match = re.search(r'TLSv([\d.]+)', line)
                if proto_match:
                    proto = f"TLSv{proto_match.group(1)}"
                    if proto not in self.findings['protocols']['supported']:
                        self.findings['protocols']['supported'].append(proto)

            # Vulnerability findings
            vuln_patterns = {
                'Heartbleed': r'Heartbleed.*?(not vulnerable|vulnerable|OK)',
                'CCS': r'CCS.*?(not vulnerable|vulnerable|OK)',
                'Ticketbleed': r'Ticketbleed.*?(not vulnerable|vulnerable|OK)',
                'Opossum': r'Opossum.*?(not vulnerable|vulnerable|OK)',
                'ROBOT': r'ROBOT.*?(does not support|not vulnerable|vulnerable|OK)',
                'Secure Renegotiation': r'Secure Renegotiation.*?(supported|not supported|OK)',
                'Client-Initiated Renegotiation': r'Client-Initiated Renegotiation.*?(not vulnerable|vulnerable|OK)',
                'CRIME': r'CRIME.*?(not vulnerable|vulnerable|OK)',
                'BREACH': r'BREACH.*?(not vulnerable|OK|NOT ok|potentially)',
                'POODLE': r'POODLE.*?(not vulnerable|vulnerable|OK)',
                'TLS_FALLBACK_SCSV': r'TLS_FALLBACK_SCSV.*?(supported|not supported)',
                'SWEET32': r'SWEET32.*?(not vulnerable|vulnerable|OK)',
                'FREAK': r'FREAK.*?(not vulnerable|vulnerable|OK)',
                'DROWN': r'DROWN.*?(not vulnerable|vulnerable|OK)',
                'LOGJAM': r'LOGJAM.*?(not vulnerable|vulnerable|OK)',
                'BEAST': r'BEAST.*?(VULNERABLE|not vulnerable|OK)',
                'LUCKY13': r'LUCKY13.*?(VULNERABLE|not vulnerable|OK)',
                'Winshock': r'Winshock.*?(not vulnerable|vulnerable|OK)',
                'RC4': r'RC4.*?(detected|not vulnerable|OK|no RC4)',
            }

            for vuln_name, pattern in vuln_patterns.items():
                if vuln_name in processed_vulns:
                    continue

                if vuln_name in line:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        status = match.group(1)
                        status = self._clean_html(status)
                        detail = self._clean_html(line)
                        severity = self._determine_severity(status, detail)

                        # Special cases
                        if 'BREACH' in vuln_name:
                            if 'potentially' in detail.lower():
                                severity = 'WARNING'
                                self.findings['breach'] = True
                            elif 'not ok' in detail.lower() or 'NOT ok' in detail:
                                severity = 'CRITICAL'
                                self.findings['breach'] = True
                        
                        if 'LUCKY13' in vuln_name:
                            if 'potentially VULNERABLE' in detail or 'potentially' in detail.lower():
                                severity = 'CRITICAL'  # LUCKY13 timing vulnerability CBC is critical in practice

                        if 'BEAST' in vuln_name and 'VULNERABLE' in detail:
                            cipher_match = re.search(r'TLS1:\s*([^\s]+(?:\s+[^\s]+)*)', detail)
                            if cipher_match:
                                detail = f"BEAST vulnerable ciphers: {cipher_match.group(1)}"

                        clean_match = re.search(pattern, clean_line, re.IGNORECASE)
                        if clean_match:
                            status_start = clean_match.start(1)
                            original_info = clean_line[:status_start].strip()
                            original_info = re.sub(r'\s+potentially$', '', original_info)
                            original_info = re.sub(r'\s+server$', '', original_info, flags=re.IGNORECASE)
                        else:
                            original_info = vuln_name

                        self.findings['vulnerabilities'][vuln_name] = {
                            'status': status,
                            'severity': severity,
                            'detail': detail,
                            'original_info': original_info
                        }
                        processed_vulns.add(vuln_name)

            # Check for TLS 1.0 and 1.1 (deprecated)
            if 'TLSv1</u>' in line or '<u>TLSv1.1' in line:
                if 'TLSv1' not in self.findings['protocols']['vulnerable']:
                    self.findings['protocols']['vulnerable'].append('TLSv1')
                if 'TLSv1.1' not in self.findings['protocols']['vulnerable']:
                    self.findings['protocols']['vulnerable'].append('TLSv1.1')

            # Parse cipher suites correctly
            # Check if this is an actual cipher suite line in the report
            # A cipher suite line starts with spaces followed by a hex code (e.g. xc00a or x1302)
            is_cipher_line = bool(re.search(r'^\s+x[0-9a-fA-F]{2,4}\s+', line))
            if is_cipher_line:
                clean_cipher = self._clean_html(line)
                if clean_cipher:
                    # Check for Forward Secrecy (Perfect Forward Secrecy ciphers ECDHE / DHE)
                    if 'ECDHE' in clean_cipher or 'DHE' in clean_cipher:
                        if clean_cipher not in self.findings['ciphers']['forward_secrecy']:
                            self.findings['ciphers']['forward_secrecy'].append(clean_cipher)
                    else:
                        if clean_cipher not in self.findings['ciphers']['strong']:
                            self.findings['ciphers']['strong'].append(clean_cipher)

                    # Check for weak ciphers (RC4, 3DES, DES, IDEA, MD5, NULL, EXPORT)
                    if re.search(r'RC4|3DES|DES|IDEA|MD5|NULL|EXPORT', clean_cipher, re.IGNORECASE):
                        if clean_cipher not in self.findings['ciphers']['weak']:
                            self.findings['ciphers']['weak'].append(clean_cipher)

    def get_summary(self) -> Dict:
        """Return structured summary of findings."""
        return self.findings


def generate_html_report(findings: Dict, input_file: str) -> str:
    """Generate a premium, branded HTML report from findings."""

    # Count issues by severity
    critical_vulns = {k: v for k, v in findings['vulnerabilities'].items() if v['severity'] == 'CRITICAL'}
    warning_vulns = {k: v for k, v in findings['vulnerabilities'].items() if v['severity'] == 'WARNING'}
    pass_vulns = {k: v for k, v in findings['vulnerabilities'].items() if v['severity'] == 'PASS'}

    critical_count = len(critical_vulns)
    warning_count = len(warning_vulns)
    pass_count = len(pass_vulns)
    total_protocols = len(findings['protocols']['supported'])

    # Deprecated protocols
    deprecated_protos = [p for p in findings['protocols']['vulnerable'] if p in ['TLSv1', 'TLSv1.1']]

    # Calculate Security Health Score
    score = 100
    # Deduct points for issues
    score -= (critical_count * 20)
    score -= (warning_count * 10)
    score -= (len(deprecated_protos) * 10)
    if findings['ciphers']['weak']:
        score -= 5
    score = max(10, score)  # Cap floor at 10%

    if score >= 90:
        score_rating = "SECURE"
        score_color = "#10b981"  # Cyber Green
        score_class = "secure"
    elif score >= 75:
        score_rating = "STRONG"
        score_color = "#3b82f6"  # Cyber Blue
        score_class = "strong"
    elif score >= 50:
        score_rating = "WARNING"
        score_color = "#f59e0b"  # Cyber Yellow/Orange
        score_class = "warning"
    else:
        score_rating = "CRITICAL"
        score_color = "#ff2e3b"  # Cyber Red
        score_class = "critical"

    # Try to load and base64-encode the samurai hero image
    image_base64 = ""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    image_path = os.path.join(script_dir, 'reference', 'cyber_samurai_illustration.jpg')
    if os.path.exists(image_path):
        try:
            with open(image_path, 'rb') as img_file:
                image_base64 = base64.b64encode(img_file.read()).decode('utf-8')
        except Exception:
            pass

    # Read base HTML template string
    # We will use simple placeholders to inject data to avoid f-string escaping bugs with CSS/JS
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CYBER SAMURAI | TLS Security Assessment</title>
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --bg-primary: #070709;
            --bg-secondary: #0f0f13;
            --bg-tertiary: #16161e;
            --accent-red: #ff2e3b;
            --accent-red-glow: rgba(255, 46, 59, 0.45);
            --accent-red-dim: rgba(255, 46, 59, 0.1);
            --text-primary: #ffffff;
            --text-secondary: #9ea2b0;
            --text-muted: #5f6377;
            --border-color: rgba(255, 255, 255, 0.06);
            --card-bg: rgba(15, 15, 19, 0.75);
            --glass-blur: blur(12px);
            
            --color-critical: #ff2e3b;
            --color-critical-glow: rgba(255, 46, 59, 0.2);
            --color-warning: #f59e0b;
            --color-warning-glow: rgba(245, 158, 11, 0.2);
            --color-pass: #10b981;
            --color-pass-glow: rgba(16, 185, 129, 0.2);
            --color-info: #3b82f6;
            --color-info-glow: rgba(59, 130, 246, 0.2);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
            overflow-x: hidden;
            position: relative;
        }

        /* Bamboo SVG watermarks in background */
        .watermark {
            position: fixed;
            pointer-events: none;
            opacity: 0.03;
            z-index: 0;
            color: var(--text-primary);
        }
        .watermark-left {
            bottom: -50px;
            left: 20px;
            width: 250px;
            height: auto;
        }
        .watermark-right {
            top: 100px;
            right: -20px;
            width: 280px;
            height: auto;
            transform: scaleX(-1);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 24px;
            position: relative;
            z-index: 10;
        }

        /* Floating Header bar */
        .header-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(15, 15, 19, 0.6);
            backdrop-filter: var(--glass-blur);
            border: 1px solid var(--border-color);
            padding: 16px 28px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.4);
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: 'Outfit', sans-serif;
        }
        .brand-logo {
            font-size: 20px;
            font-weight: 800;
            letter-spacing: 1.5px;
            color: #fff;
            text-transform: uppercase;
        }
        .brand-logo span {
            color: var(--accent-red);
        }
        .brand-japanese {
            background: var(--accent-red-dim);
            color: var(--accent-red);
            font-weight: 600;
            font-size: 13px;
            padding: 2px 10px;
            border-radius: 4px;
            border: 1px solid rgba(255, 46, 59, 0.2);
        }
        .btn-print {
            background: transparent;
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
            padding: 8px 18px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn-print:hover {
            color: #fff;
            border-color: #fff;
            background: rgba(255, 255, 255, 0.05);
        }

        /* Hero section style */
        .hero-section {
            position: relative;
            background-color: var(--bg-secondary);
            background-size: cover;
            background-position: center 30%;
            padding: 60px 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
            overflow: hidden;
            box-shadow: inset 0 0 100px rgba(0, 0, 0, 0.8), 0 10px 40px rgba(0,0,0,0.5);
        }
        .hero-overlay {
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(90deg, rgba(7, 7, 9, 0.95) 40%, rgba(7, 7, 9, 0.4) 100%);
            z-index: 1;
        }
        .hero-section::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(rgba(255, 46, 59, 0.03) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(255, 46, 59, 0.03) 1px, transparent 1px);
            background-size: 24px 24px;
            pointer-events: none;
            z-index: 2;
        }
        .hero-content {
            position: relative;
            z-index: 3;
            max-width: 600px;
        }
        .hero-tagline {
            color: var(--accent-red);
            font-size: 12px;
            font-weight: 800;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .hero-tagline::before {
            content: '';
            display: inline-block;
            width: 8px;
            height: 8px;
            background: var(--accent-red);
        }
        .hero-title {
            font-family: 'Outfit', sans-serif;
            font-size: 38px;
            font-weight: 800;
            line-height: 1.15;
            margin-bottom: 20px;
            letter-spacing: -0.5px;
        }
        .hero-meta {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
            margin-top: 30px;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
            padding-top: 24px;
        }
        .meta-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .meta-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }
        .meta-val {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-secondary);
            word-break: break-all;
        }

        /* Navigation Tabs */
        .tabs-nav {
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1px;
        }
        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            padding: 12px 24px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
            font-family: 'Outfit', sans-serif;
        }
        .tab-btn::after {
            content: '';
            position: absolute;
            bottom: -1px;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--accent-red);
            transform: scaleX(0);
            transition: transform 0.2s ease;
        }
        .tab-btn:hover {
            color: #fff;
        }
        .tab-btn.active {
            color: #fff;
        }
        .tab-btn.active::after {
            transform: scaleX(1);
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.4s ease forwards;
        }
        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Dashboard Overview layout */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }
        .dashboard-left {
            display: flex;
            flex-direction: column;
            gap: 24px;
        }
        .glass-card {
            background: var(--card-bg);
            backdrop-filter: var(--glass-blur);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }
        .glass-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 3px;
            background: transparent;
        }
        .card-red::before { background: var(--accent-red); }
        .card-orange::before { background: var(--color-warning); }
        .card-green::before { background: var(--color-pass); }
        .card-blue::before { background: var(--color-info); }

        /* Health Score circular indicator */
        .health-score-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 10px 0;
            position: relative;
        }
        .progress-ring {
            transform: rotate(-90deg);
        }
        .progress-ring__circle {
            transition: stroke-dashoffset 0.35s;
            transform-origin: 50% 50%;
        }
        .health-score-text {
            position: absolute;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -60%);
        }
        .score-num {
            font-family: 'Outfit', sans-serif;
            font-size: 36px;
            font-weight: 800;
            color: #fff;
            line-height: 1;
        }
        .score-label {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 2px;
            margin-top: 4px;
            text-transform: uppercase;
        }

        /* Stat cards mini grid */
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            width: 100%;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 16px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            transition: transform 0.2s ease;
        }
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: rgba(255,255,255,0.12);
        }
        .stat-val {
            font-family: 'Outfit', sans-serif;
            font-size: 24px;
            font-weight: 800;
        }
        .stat-lbl {
            font-size: 11px;
            color: var(--text-secondary);
        }
        .stat-critical { color: var(--color-critical); }
        .stat-warning { color: var(--color-warning); }
        .stat-pass { color: var(--color-pass); }
        .stat-info { color: var(--color-info); }

        /* Executive Summary section */
        .summary-card {
            display: flex;
            flex-direction: column;
            gap: 16px;
            height: 100%;
        }
        .card-title {
            font-family: 'Outfit', sans-serif;
            font-size: 18px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
            letter-spacing: 0.5px;
        }
        .card-title::before {
            content: '';
            display: inline-block;
            width: 4px;
            height: 16px;
            background: var(--accent-red);
        }
        .summary-text {
            color: var(--text-secondary);
            font-size: 14px;
            line-height: 1.7;
        }
        .bullet-list {
            margin-top: 10px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            list-style: none;
        }
        .bullet-list li {
            position: relative;
            padding-left: 20px;
            font-size: 14px;
            color: var(--text-secondary);
        }
        .bullet-list li::before {
            content: '▪';
            position: absolute;
            left: 0;
            color: var(--accent-red);
        }

        /* Vulnerabilities List & Filters */
        .filter-bar {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .filter-btn {
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .filter-btn:hover {
            background: rgba(255,255,255,0.08);
            color: #fff;
        }
        .filter-btn.active {
            background: var(--accent-red);
            border-color: var(--accent-red);
            color: #fff;
            box-shadow: 0 0 10px var(--accent-red-glow);
        }

        .vuln-cards-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .vuln-item-card {
            background: var(--card-bg);
            backdrop-filter: var(--glass-blur);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            overflow: hidden;
        }
        .vuln-item-card:hover {
            border-color: rgba(255, 255, 255, 0.12);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        }
        .vuln-card-header {
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            gap: 16px;
        }
        .vuln-meta-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .severity-badge {
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 1px;
            padding: 3px 10px;
            border-radius: 4px;
            text-transform: uppercase;
            text-align: center;
            min-width: 90px;
            border: 1px solid transparent;
        }
        .badge-critical {
            background: rgba(255, 46, 59, 0.12);
            color: var(--color-critical);
            border-color: rgba(255, 46, 59, 0.2);
        }
        .badge-warning {
            background: rgba(245, 158, 11, 0.12);
            color: var(--color-warning);
            border-color: rgba(245, 158, 11, 0.2);
        }
        .badge-pass {
            background: rgba(16, 185, 129, 0.12);
            color: var(--color-pass);
            border-color: rgba(16, 185, 129, 0.2);
        }

        .vuln-card-title {
            font-size: 14px;
            font-weight: 700;
            color: #fff;
        }
        .vuln-card-summary {
            font-size: 12px;
            color: var(--text-secondary);
            max-width: 450px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .arrow-icon {
            color: var(--text-muted);
            transition: transform 0.25s ease;
        }
        .vuln-item-card.expanded .arrow-icon {
            transform: rotate(180deg);
        }

        /* Collapsible body */
        .vuln-card-body {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            border-top: 1px solid transparent;
            background: rgba(0,0,0,0.15);
        }
        .vuln-item-card.expanded .vuln-card-body {
            max-height: 1000px;
            border-top: 1px solid var(--border-color);
        }
        .vuln-body-content {
            padding: 20px 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        .vuln-info-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .vuln-info-block {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .block-title {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            font-weight: 700;
        }
        .block-text {
            font-size: 13.5px;
            color: var(--text-secondary);
            line-height: 1.6;
        }
        
        /* Simulated Codeblock */
        .raw-output-block {
            background: #020204;
            border: 1px solid rgba(255,255,255,0.04);
            border-radius: 6px;
            padding: 12px 16px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #8c90a1;
            white-space: pre-wrap;
            word-break: break-all;
            position: relative;
        }
        .raw-output-block::before {
            content: 'RAW SCAN OUTPUT';
            position: absolute;
            top: -8px; right: 12px;
            background: #020204;
            font-size: 9px;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            padding: 0 4px;
            font-family: 'Inter', sans-serif;
            font-weight: 700;
        }

        /* Protocols & Ciphers Grid */
        .config-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }
        @media (max-width: 800px) {
            .config-grid, .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }
        .config-card {
            min-height: 250px;
        }
        
        /* Protocol Grid view */
        .protocol-badge-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-top: 15px;
        }
        .protocol-status-item {
            background: rgba(255,255,255,0.015);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .proto-name {
            font-weight: 700;
            font-size: 13.5px;
            font-family: 'Outfit', sans-serif;
        }
        .proto-status {
            font-size: 10px;
            font-weight: 800;
            padding: 2px 8px;
            border-radius: 4px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        .proto-secure {
            background: rgba(16, 185, 129, 0.1);
            color: var(--color-pass);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        .proto-deprecated {
            background: rgba(255, 46, 59, 0.1);
            color: var(--color-critical);
            border: 1px solid rgba(255, 46, 59, 0.2);
        }
        .proto-disabled {
            background: rgba(255,255,255,0.02);
            color: var(--text-muted);
            border: 1px solid transparent;
        }

        .cipher-list-scroll {
            max-height: 220px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 6px;
            padding-right: 6px;
            margin-top: 12px;
        }
        /* Custom scrollbar */
        .cipher-list-scroll::-webkit-scrollbar {
            width: 4px;
        }
        .cipher-list-scroll::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.1);
        }
        .cipher-list-scroll::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 2px;
        }

        .cipher-item-text {
            font-family: 'Courier New', monospace;
            font-size: 11.5px;
            color: var(--text-secondary);
            padding: 6px 10px;
            background: rgba(0,0,0,0.2);
            border-radius: 4px;
            border-left: 3px solid var(--border-color);
        }
        .cipher-item-text.weak-cipher {
            border-left-color: var(--color-critical);
            color: #ff8e95;
            background: rgba(255, 46, 59, 0.05);
        }
        .cipher-item-text.fs-cipher {
            border-left-color: var(--color-info);
            color: #8ebbff;
        }

        /* Roadmap remediation dashboard */
        .roadmap-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 16px;
        }
        .roadmap-progress-container {
            display: flex;
            align-items: center;
            gap: 16px;
            background: rgba(255,255,255,0.02);
            padding: 10px 18px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        .roadmap-bar-bg {
            width: 140px;
            height: 6px;
            background: rgba(255,255,255,0.06);
            border-radius: 3px;
            overflow: hidden;
        }
        .roadmap-bar-fill {
            height: 100%;
            background: var(--color-pass);
            width: 0%;
            transition: width 0.3s ease;
        }
        .roadmap-progress-text {
            font-size: 12px;
            font-weight: 700;
            color: var(--color-pass);
        }
        .roadmap-sections-list {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .roadmap-priority-group {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .priority-title {
            font-family: 'Outfit', sans-serif;
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 6px;
            margin-bottom: 4px;
        }
        .priority-critical { color: var(--color-critical); }
        .priority-high { color: var(--color-warning); }
        .priority-medium { color: var(--color-info); }
        .priority-low { color: var(--text-muted); }
        
        .roadmap-item {
            background: rgba(255,255,255,0.015);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px 20px;
            display: flex;
            gap: 16px;
            align-items: flex-start;
            transition: all 0.2s ease;
            position: relative;
        }
        .roadmap-item:hover {
            border-color: rgba(255,255,255,0.08);
            background: rgba(255,255,255,0.025);
        }
        
        /* Custom styled checkboxes */
        .roadmap-cb-wrapper {
            position: relative;
            display: inline-block;
            width: 20px;
            height: 20px;
            margin-top: 2px;
        }
        .roadmap-cb-input {
            position: absolute;
            opacity: 0;
            cursor: pointer;
            height: 0; width: 0;
        }
        .roadmap-checkmark {
            position: absolute;
            top: 0; left: 0;
            height: 20px; width: 20px;
            background-color: transparent;
            border: 2px solid var(--border-color);
            border-radius: 4px;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        .roadmap-item:hover .roadmap-checkmark {
            border-color: var(--text-muted);
        }
        .roadmap-cb-input:checked ~ .roadmap-checkmark {
            background-color: var(--color-pass);
            border-color: var(--color-pass);
        }
        .roadmap-checkmark::after {
            content: "";
            position: absolute;
            display: none;
            left: 6px; top: 2px;
            width: 4px; height: 9px;
            border: solid white;
            border-width: 0 2px 2px 0;
            transform: rotate(45deg);
        }
        .roadmap-cb-input:checked ~ .roadmap-checkmark::after {
            display: block;
        }

        .roadmap-item-details {
            display: flex;
            flex-direction: column;
            gap: 4px;
            flex: 1;
        }
        .roadmap-item-title {
            font-size: 13.5px;
            font-weight: 700;
            color: #fff;
            transition: all 0.2s ease;
        }
        .roadmap-item-desc {
            font-size: 12px;
            color: var(--text-secondary);
        }
        .roadmap-cb-input:checked ~ .roadmap-item-details .roadmap-item-title {
            text-decoration: line-through;
            color: var(--text-muted);
        }
        .roadmap-cb-input:checked ~ .roadmap-item-details .roadmap-item-desc {
            color: rgba(95, 99, 119, 0.5);
        }

        /* Updated health score box in roadmap */
        .roadmap-score-widget {
            background: rgba(16, 185, 129, 0.04);
            border: 1px dashed rgba(16, 185, 129, 0.2);
            border-radius: 8px;
            padding: 14px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .widget-val {
            font-family: 'Outfit', sans-serif;
            font-weight: 800;
            color: var(--color-pass);
            font-size: 20px;
        }

        /* Footer styling */
        .footer {
            text-align: center;
            border-top: 1px solid var(--border-color);
            margin-top: 50px;
            padding: 30px 0;
            color: var(--text-muted);
            font-size: 12px;
            font-family: 'Outfit', sans-serif;
            letter-spacing: 1px;
        }

        /* Print styles */
        @media print {
            body {
                background: white !important;
                color: black !important;
            }
            .watermark, .btn-print, .tabs-nav {
                display: none !important;
            }
            .glass-card, .hero-section, .header-bar, .vuln-item-card, .roadmap-item {
                background: white !important;
                border: 1px solid #ccc !important;
                box-shadow: none !important;
                color: black !important;
                page-break-inside: avoid;
            }
            .hero-overlay {
                background: linear-gradient(90deg, rgba(255,255,255,0.95) 40%, rgba(255,255,255,0.6) 100%) !important;
            }
            .hero-section::before {
                display: none !important;
            }
            .tab-content {
                display: block !important;
                opacity: 1 !important;
            }
            .raw-output-block {
                background: #f5f5f5 !important;
                color: #333 !important;
                border-color: #ccc !important;
            }
            .score-num, .card-title, .brand-logo, .vuln-card-title, .roadmap-item-title {
                color: black !important;
            }
        }
    </style>
</head>
<body>

<!-- Minimalist Bamboo Background SVG decorations (Sumi-e Style) -->
<div class="watermark watermark-left">
    <svg viewBox="0 0 100 800" fill="none" stroke="currentColor" xmlns="http://www.w3.org/2000/svg">
        <path d="M50,800 C52,700 48,600 50,550" stroke-width="4.5" stroke-linecap="round"/>
        <path d="M50,545 C51,450 49,350 50,280" stroke-width="4.0" stroke-linecap="round"/>
        <path d="M50,275 C48,200 52,100 50,20" stroke-width="3.5" stroke-linecap="round"/>
        
        <!-- Bamboo joints/rings -->
        <path d="M42,550 Q50,544 58,550" stroke-width="2.5"/>
        <path d="M43,280 Q50,274 57,280" stroke-width="2.5"/>
        
        <!-- Subtle branch 1 -->
        <path d="M50,420 Q70,380 85,395" stroke-width="1.8" stroke-linecap="round"/>
        <path d="M85,395 C95,405 105,400 115,402 Q100,385 85,395" fill="currentColor" stroke="none"/>
        <path d="M80,392 C88,380 98,375 108,378 Q95,368 80,392" fill="currentColor" stroke="none"/>

        <!-- Subtle branch 2 -->
        <path d="M50,210 Q25,180 15,190" stroke-width="1.5" stroke-linecap="round"/>
        <path d="M15,190 C5,198 -5,192 -15,194 Q-2,180 15,190" fill="currentColor" stroke="none"/>
    </svg>
</div>

<div class="watermark watermark-right">
    <svg viewBox="0 0 100 800" fill="none" stroke="currentColor" xmlns="http://www.w3.org/2000/svg">
        <path d="M50,800 C48,680 52,580 50,500" stroke-width="5" stroke-linecap="round"/>
        <path d="M50,495 C52,380 48,290 50,200" stroke-width="4" stroke-linecap="round"/>
        <path d="M50,195 C49,120 51,60 50,10" stroke-width="3.5" stroke-linecap="round"/>
        
        <path d="M41,500 Q50,494 59,500" stroke-width="3"/>
        <path d="M42,200 Q50,194 58,200" stroke-width="3"/>
        
        <path d="M50,330 Q80,290 95,300" stroke-width="2" stroke-linecap="round"/>
        <path d="M95,300 C108,310 120,305 130,306 Q115,290 95,300" fill="currentColor" stroke="none"/>
        
        <path d="M50,110 Q20,70 5,85" stroke-width="1.8" stroke-linecap="round"/>
        <path d="M5,85 C-5,95 -15,90 -25,92 Q-10,75 5,85" fill="currentColor" stroke="none"/>
    </svg>
</div>

<div class="container">
    
    <!-- Top Brand Header Bar -->
    <div class="header-bar">
        <div class="brand">
            <div class="brand-logo">Cyber Samurai<span>.</span></div>
            <div class="brand-japanese">侍</div>
        </div>
        <button class="btn-print" onclick="window.print()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
            Print Assessment
        </button>
    </div>

    <!-- Main Hero Banner (Uses base64 Cyber Samurai background if available) -->
    <div class="hero-section" id="hero-banner">
        <div class="hero-overlay"></div>
        <div class="hero-content">
            <div class="hero-tagline">Security Scan Completed</div>
            <h1 class="hero-title">TLS Security Assessment</h1>
            
            <div class="hero-meta">
                <div class="meta-item">
                    <span class="meta-label">Target Host</span>
                    <span class="meta-val"><!--TARGET--></span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">IP Address</span>
                    <span class="meta-val"><!--IP_ADDRESSES--></span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Active Service</span>
                    <span class="meta-val"><!--SERVICE--></span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Scan Timestamp</span>
                    <span class="meta-val"><!--DATE_GENERATED--></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs-nav">
        <button class="tab-btn active" onclick="switchTab(event, 'dashboard')">Overview</button>
        <button class="tab-btn" onclick="switchTab(event, 'vulnerabilities')">Vulnerabilities</button>
        <button class="tab-btn" onclick="switchTab(event, 'ciphers')">Protocols & Ciphers</button>
        <button class="tab-btn" onclick="switchTab(event, 'roadmap')">Action Roadmap</button>
    </div>

    <!-- TAB 1: OVERVIEW DASHBOARD -->
    <div id="dashboard" class="tab-content active">
        <div class="dashboard-grid">
            
            <!-- Left panel: Health score circular ring + counts -->
            <div class="dashboard-left">
                <div class="glass-card card-red health-score-card">
                    <div class="health-score-container">
                        <svg class="progress-ring" width="160" height="160">
                            <circle class="progress-ring__background" stroke="rgba(255, 255, 255, 0.04)" stroke-width="12" fill="transparent" r="68" cx="80" cy="80"/>
                            <!-- Stroke-dasharray = 2 * PI * r = 2 * 3.14159 * 68 = 427 -->
                            <circle class="progress-ring__circle" stroke="<!--SCORE_COLOR-->" stroke-width="12" stroke-dasharray="427 427" stroke-dashoffset="<!--SCORE_OFFSET-->" stroke-linecap="round" fill="transparent" r="68" cx="80" cy="80"/>
                        </svg>
                        <div class="health-score-text">
                            <span class="score-num"><!--SCORE-->%</span>
                            <span class="score-label" style="color: <!--SCORE_COLOR-->;"><!--SCORE_RATING--></span>
                        </div>
                    </div>
                </div>

                <div class="stat-grid">
                    <div class="stat-card">
                        <span class="stat-val stat-critical"><!--CRITICAL_COUNT--></span>
                        <span class="stat-lbl">Critical Issues</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-warning"><!--WARNING_COUNT--></span>
                        <span class="stat-lbl">Warnings</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-pass"><!--PASS_COUNT--></span>
                        <span class="stat-lbl">Passed Checks</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val stat-info"><!--TOTAL_PROTOCOLS--></span>
                        <span class="stat-lbl">TLS Protocols</span>
                    </div>
                </div>
            </div>

            <!-- Right panel: Executive Summary -->
            <div class="dashboard-right">
                <div class="glass-card summary-card" style="height: 100%;">
                    <h2 class="card-title">Executive Summary</h2>
                    <div class="summary-text">
                        A comprehensive TLS configuration and vulnerability analysis has been completed for <strong><!--TARGET--></strong>. 
                        The target host is currently evaluated as <strong><!--SCORE_RATING--></strong> with a security posture rating of <strong><!--SCORE-->%</strong>. 
                        <br><br>
                        This assessment analyzed supported protocols, encryption strength, cryptographic handshakes, and vulnerabilities including POODLE, Heartbleed, ROBOT, CCS Injection, and BREACH.
                        <br><br>
                        Key observations:
                        <ul class="bullet-list">
                            <li>Supported Protocols: Modern protocols (TLSv1.2, TLSv1.3) are supported. However, deprecated protocols (TLSv1.0, TLSv1.1) should be disabled to prevent downgrade attacks.</li>
                            <li>Critical Vulnerabilities: There are <strong><!--CRITICAL_COUNT--></strong> critical issues identified that require immediate remediation to prevent sensitive session exposure or data decryption.</li>
                            <li>Forward Secrecy: Perfect Forward Secrecy (PFS) is supported on modern clients, ensuring session key protection.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- TAB 2: VULNERABILITIES -->
    <div id="vulnerabilities" class="tab-content">
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterVulns('all')">All checks</button>
            <button class="filter-btn" onclick="filterVulns('critical')">Critical (<!--CRITICAL_COUNT-->)</button>
            <button class="filter-btn" onclick="filterVulns('warning')">Warnings (<!--WARNING_COUNT-->)</button>
            <button class="filter-btn" onclick="filterVulns('pass')">Passed checks</button>
        </div>

        <div class="vuln-cards-list">
            <!--VULN_CARDS_HTML-->
        </div>
    </div>

    <!-- TAB 3: PROTOCOLS & CIPHERS -->
    <div id="ciphers" class="tab-content">
        <div class="config-grid">
            
            <!-- Protocol Config -->
            <div class="glass-card config-card">
                <h2 class="card-title">Protocol Configuration</h2>
                <p class="roadmap-item-desc" style="margin-top: 4px; color: var(--text-secondary);">
                    Protocol compliance audit showing supported and deprecated/disabled TLS/SSL protocol versions.
                </p>
                
                <div class="protocol-badge-grid">
                    <!--PROTOCOL_LIST_HTML-->
                </div>
            </div>

            <!-- Cipher Suites -->
            <div class="glass-card config-card">
                <h2 class="card-title">Cipher Suite Status</h2>
                
                <div style="margin-top: 15px;">
                    <span class="block-title">Perfect Forward Secrecy (PFS)</span>
                    <!--CIPHERS_FORWARD_SECRECY_HTML-->
                </div>

                <div style="margin-top: 20px;">
                    <span class="block-title">Weak Cipher Suites Detected</span>
                    <div class="cipher-list-scroll">
                        <!--CIPHERS_WEAK_HTML-->
                    </div>
                </div>
            </div>

        </div>
    </div>

    <!-- TAB 4: ROADMAP -->
    <div id="roadmap" class="tab-content">
        <div class="glass-card">
            
            <div class="roadmap-header">
                <div>
                    <h2 class="card-title" style="margin-bottom: 4px;">Remediation Roadmap</h2>
                    <p class="roadmap-item-desc" style="color: var(--text-secondary);">
                        Interactive step-by-step remediation guide. Check items as you implement fixes to simulate your improved security score.
                    </p>
                </div>
                
                <div class="roadmap-progress-container">
                    <span class="roadmap-progress-text" id="roadmap-pct">0% Complete</span>
                    <div class="roadmap-bar-bg">
                        <div class="roadmap-bar-fill" id="roadmap-fill"></div>
                    </div>
                </div>
            </div>

            <!-- Interactive Score Simulator -->
            <div class="roadmap-score-widget" style="margin-bottom: 24px;">
                <div style="font-size: 13px; font-weight: 600; color: var(--text-secondary);">
                    Target Health Score (Simulated After Remediation):
                </div>
                <div class="widget-val" id="simulated-score"><!--SCORE-->%</div>
            </div>

            <div class="roadmap-sections-list">
                <!--ROADMAP_ITEMS_HTML-->
            </div>

        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        CYBER SAMURAI &bull; DESIGNED FOR PERFORMANCE. BUILT FOR SECURITY. &bull; GENERATED VIA TESTSSL-REPORT-ENHANCER
    </div>
</div>

<script>
    // Embed the base64 hero background if present
    const heroBg = "<!--HERO_BG_BASE64-->";
    if (heroBg && heroBg.trim().length > 0) {
        document.getElementById('hero-banner').style.backgroundImage = `linear-gradient(rgba(7, 7, 9, 0.85), rgba(7, 7, 9, 0.95)), url('data:image/jpeg;base64,${heroBg}')`;
    } else {
        document.getElementById('hero-banner').style.backgroundImage = 'linear-gradient(135deg, #0f0f13 0%, #16161e 100%)';
    }

    // Tab switcher
    function switchTab(evt, tabId) {
        // Hide all contents
        const contents = document.querySelectorAll('.tab-content');
        contents.forEach(content => content.classList.remove('active'));

        // Deactivate all tab buttons
        const tabs = document.querySelectorAll('.tab-btn');
        tabs.forEach(tab => tab.classList.remove('active'));

        // Show selected tab content and active tab button
        document.getElementById(tabId).classList.add('active');
        evt.currentTarget.classList.add('active');
    }

    // Collapsible Vulnerability Cards
    function toggleVulnCard(header) {
        const card = header.closest('.vuln-item-card');
        card.classList.toggle('expanded');
    }

    // Vulnerability filtering
    function filterVulns(severity) {
        // Toggle active button
        const filterBtns = document.querySelectorAll('.filter-btn');
        filterBtns.forEach(btn => btn.classList.remove('active'));
        event.currentTarget.classList.add('active');

        // Show/hide cards
        const cards = document.querySelectorAll('.vuln-item-card');
        cards.forEach(card => {
            const cardSeverity = card.getAttribute('data-severity');
            if (severity === 'all') {
                card.style.display = 'block';
            } else if (cardSeverity === severity) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    }

    // Interactive Roadmap Score Calculator
    const initialScore = <!--SCORE-->;
    let currentScore = initialScore;
    
    // Select all inputs
    const checkboxes = document.querySelectorAll('.roadmap-cb-input');
    
    function updateRoadmapProgress() {
        let checkedCount = 0;
        let scoreAddition = 0;
        
        checkboxes.forEach(cb => {
            if (cb.checked) {
                checkedCount++;
                scoreAddition += parseInt(cb.getAttribute('data-weight'), 10);
            }
        });
        
        // Update progress bar
        const totalItems = checkboxes.length;
        const pct = totalItems > 0 ? Math.round((checkedCount / totalItems) * 100) : 0;
        document.getElementById('roadmap-pct').innerText = `${pct}% Complete`;
        document.getElementById('roadmap-fill').style.width = `${pct}%`;
        
        // Update simulated score
        let simulated = Math.min(100, initialScore + scoreAddition);
        document.getElementById('simulated-score').innerText = `${simulated}%`;
        
        // Color transition for simulated score
        const scoreWidgetVal = document.getElementById('simulated-score');
        if (simulated >= 90) {
            scoreWidgetVal.style.color = 'var(--color-pass)';
        } else if (simulated >= 75) {
            scoreWidgetVal.style.color = 'var(--color-info)';
        } else if (simulated >= 50) {
            scoreWidgetVal.style.color = 'var(--color-warning)';
        } else {
            scoreWidgetVal.style.color = 'var(--color-critical)';
        }
    }
    
    checkboxes.forEach(cb => {
        cb.addEventListener('change', updateRoadmapProgress);
    });
</script>
</body>
</html>
"""

    # Inject metadata and summary stats
    html = html_template
    html = html.replace('<!--TARGET-->', escape(findings['target']))
    html = html.replace('<!--IP_ADDRESSES-->', escape(', '.join(findings['ip_addresses'])))
    html = html.replace('<!--SERVICE-->', escape(findings['service'] or 'HTTPS'))
    html = html.replace('<!--DATE_GENERATED-->', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    html = html.replace('<!--SCORE-->', str(score))
    html = html.replace('<!--SCORE_RATING-->', score_rating)
    html = html.replace('<!--SCORE_COLOR-->', score_color)
    html = html.replace('<!--SCORE_CLASS-->', score_class)
    
    # SVG circle offset: 427 is full circumference (100% deduction).
    # score_offset = circumference - (circumference * percentage / 100)
    score_offset = 427 - (427 * score // 100)
    html = html.replace('<!--SCORE_OFFSET-->', str(score_offset))
    html = html.replace('<!--HERO_BG_BASE64-->', image_base64)
    
    html = html.replace('<!--CRITICAL_COUNT-->', str(critical_count))
    html = html.replace('<!--WARNING_COUNT-->', str(warning_count))
    html = html.replace('<!--PASS_COUNT-->', str(pass_count))
    html = html.replace('<!--TOTAL_PROTOCOLS-->', str(total_protocols))

    # Construct Protocol badges HTML
    protocol_list_html = ""
    known_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
    for proto in known_protocols:
        # Standardize matching name in findings (findings uses 'TLSv1', 'TLSv1.1', etc.)
        supported = proto in findings['protocols']['supported'] or (f"{proto}" in findings['protocols']['supported']) or (proto == 'TLSv1' and 'TLSv1' in findings['protocols']['supported']) or (proto == 'TLSv1.1' and 'TLSv1.1' in findings['protocols']['supported'])
        
        # Check if it is deprecated or vulnerable
        vulnerable = proto in findings['protocols']['vulnerable'] or (f"{proto}" in findings['protocols']['vulnerable'])

        if not supported:
            # Protocol is disabled on the server
            status_text = "Disabled"
            status_class = "proto-disabled"
        else:
            if vulnerable or proto in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                status_text = "Deprecated"
                status_class = "proto-deprecated"
            else:
                status_text = "Secure"
                status_class = "proto-secure"
                
        protocol_list_html += f'''
                    <div class="protocol-status-item">
                        <span class="proto-name">{proto}</span>
                        <span class="proto-status {status_class}">{status_text}</span>
                    </div>'''
    html = html.replace('<!--PROTOCOL_LIST_HTML-->', protocol_list_html)

    # Construct Ciphers Forward Secrecy & Weak Ciphers HTML
    fs_ciphers = findings['ciphers']['forward_secrecy']
    if fs_ciphers:
        fs_html = f'''
                    <div style="display: flex; align-items: center; gap: 8px; margin-top: 6px;">
                        <span class="proto-status proto-secure" style="padding: 4px 12px; font-size: 11px;">Active / Supported</span>
                        <span style="font-size: 12.5px; color: var(--text-secondary);">{len(fs_ciphers)} FS cipher suites active</span>
                    </div>'''
    else:
        fs_html = '''
                    <div style="display: flex; align-items: center; gap: 8px; margin-top: 6px;">
                        <span class="proto-status proto-deprecated" style="padding: 4px 12px; font-size: 11px;">Not Supported</span>
                        <span style="font-size: 12.5px; color: var(--color-critical);">Forward secrecy is not enabled on this host!</span>
                    </div>'''
    html = html.replace('<!--CIPHERS_FORWARD_SECRECY_HTML-->', fs_html)

    weak_ciphers = findings['ciphers']['weak']
    weak_html = ""
    if weak_ciphers:
        for cipher in weak_ciphers[:20]:  # Cap at 20 ciphers
            weak_html += f'<div class="cipher-item-text weak-cipher">⚠️ {escape(cipher)}</div>'
        if len(weak_ciphers) > 20:
            weak_html += f'<div class="cipher-item-text" style="color: var(--text-muted);">... and {len(weak_ciphers) - 20} more ciphers</div>'
    else:
        weak_html = '''
                        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 30px 10px; color: var(--color-pass); gap: 8px;">
                            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            <span style="font-size: 12.5px; font-weight: 600;">No weak ciphers active on this server.</span>
                        </div>'''
    html = html.replace('<!--CIPHERS_WEAK_HTML-->', weak_html)

    # Construct Vulnerabilities Cards HTML
    vuln_cards_html = ""
    for vuln_name, data in sorted(findings['vulnerabilities'].items(), key=lambda x: ('critical', 'warning', 'pass').index(x[1]['severity'].lower())):
        status_class = data['severity'].lower()
        original_info = data.get('original_info', vuln_name)
        
        # Look up details
        details = VULN_DETAILS.get(vuln_name, {
            'name': original_info,
            'description': 'Cryptographic implementation vulnerability reported by testssl.sh.',
            'remediation': 'Please review server TLS configurations and apply security patches.'
        })
        
        status_text = "PASS"
        if status_class == 'critical':
            status_text = "CRITICAL"
        elif status_class == 'warning':
            status_text = "WARNING"
            
        vuln_cards_html += f'''
            <div class="vuln-item-card" data-severity="{status_class}">
                <div class="vuln-card-header" onclick="toggleVulnCard(this)">
                    <div class="vuln-meta-left">
                        <span class="severity-badge badge-{status_class}">{status_text}</span>
                        <div class="vuln-card-title">{escape(details['name'])}</div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span class="vuln-card-summary">{escape(data['status'])}</span>
                        <svg class="arrow-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    </div>
                </div>
                
                <div class="vuln-card-body">
                    <div class="vuln-body-content">
                        <div class="vuln-info-row">
                            <div class="vuln-info-block">
                                <span class="block-title">Threat Description</span>
                                <p class="block-text">{escape(details['description'])}</p>
                            </div>
                            <div class="vuln-info-block">
                                <span class="block-title">Remediation Guide</span>
                                <p class="block-text">{escape(details['remediation'])}</p>
                            </div>
                        </div>
                        <div class="raw-output-block">{escape(data['detail'])}</div>
                    </div>
                </div>
            </div>'''
    html = html.replace('<!--VULN_CARDS_HTML-->', vuln_cards_html)

    # Construct Roadmap items HTML
    roadmap_html = ""
    
    # Priority groups
    priorities = {
        'critical': {
            'title': 'Critical Actions (Immediate)',
            'class': 'priority-critical',
            'weight': 20,
            'items': []
        },
        'high': {
            'title': 'High Priority (Recommended)',
            'class': 'priority-high',
            'weight': 10,
            'items': []
        },
        'medium': {
            'title': 'Medium Priority (Updates)',
            'class': 'priority-medium',
            'weight': 5,
            'items': []
        }
    }

    # Add critical vulnerabilities to priority roadmap
    for name, data in critical_vulns.items():
        details = VULN_DETAILS.get(name, {'name': name, 'remediation': 'Fix vulnerability.'})
        priorities['critical']['items'].append({
            'title': f"Fix {details['name']}",
            'desc': details['remediation'],
            'weight': 20
        })

    # Add deprecated protocols to roadmap
    if deprecated_protos:
        priorities['high']['items'].append({
            'title': f"Disable Deprecated TLS Protocols ({', '.join(deprecated_protos)})",
            'desc': "Configure your web server to only support secure protocols: TLSv1.2 and TLSv1.3. Deprecated protocols are vulnerable to downgrade attacks.",
            'weight': 10
        })

    # Add warning vulnerabilities to roadmap
    for name, data in warning_vulns.items():
        details = VULN_DETAILS.get(name, {'name': name, 'remediation': 'Fix warning vulnerability.'})
        priorities['high']['items'].append({
            'title': f"Remediate {details['name']} Warning",
            'desc': details['remediation'],
            'weight': 10
        })

    # Add weak ciphers to roadmap
    if weak_ciphers:
        priorities['medium']['items'].append({
            'title': "Disable Weak Cipher Suites",
            'desc': "Disable outdated block ciphers like RC4, 3DES, Blowfish, or DES on the web server. Restrict supported ciphers to strong GCM and ChaCha20 variants.",
            'weight': 5
        })

    # Add standard action if PFS is not supported
    if not fs_ciphers:
        priorities['critical']['items'].append({
            'title': "Enable Perfect Forward Secrecy (PFS)",
            'desc': "Ensure the server prioritizes ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) and DHE cipher suites.",
            'weight': 20
        })

    # Render groups to HTML
    idx = 0
    for key, p_data in priorities.items():
        if not p_data['items']:
            continue
            
        group_html = f'''
                <div class="roadmap-priority-group">
                    <div class="priority-title {p_data['class']}">{escape(p_data['title'])}</div>'''
                    
        for item in p_data['items']:
            group_html += f'''
                    <div class="roadmap-item">
                        <div class="roadmap-cb-wrapper">
                            <input type="checkbox" id="roadmap-cb-{idx}" class="roadmap-cb-input" data-weight="{item['weight']}">
                            <span class="roadmap-checkmark"></span>
                        </div>
                        <div class="roadmap-item-details">
                            <label class="roadmap-item-title" for="roadmap-cb-{idx}">{escape(item['title'])}</label>
                            <span class="roadmap-item-desc">{escape(item['desc'])}</span>
                        </div>
                    </div>'''
            idx += 1
            
        group_html += '</div>'
        roadmap_html += group_html

    if not roadmap_html:
        roadmap_html = '''
                <div style="text-align: center; padding: 40px 10px; color: var(--color-pass);">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:12px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                    <h3 style="font-family:'Outfit',sans-serif;font-size:18px;margin-bottom:4px;">Perfect Score!</h3>
                    <p style="font-size:12.5px;color:var(--text-secondary);">No action items found. Your server configuration conforms to top security standards.</p>
                </div>'''
    html = html.replace('<!--ROADMAP_ITEMS_HTML-->', roadmap_html)

    return html


def main():
    # Configure console encoding to UTF-8 on Windows to avoid UnicodeEncodeError
    if sys.platform.startswith('win'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except AttributeError:
            # Python versions before 3.7 might not have reconfigure
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

    parser = argparse.ArgumentParser(
        description='Parse testssl.sh HTML report and generate enhanced summary.'
    )
    parser.add_argument('input', help='Input HTML file from testssl.sh')
    parser.add_argument('-o', '--output', default='enhanced_report.html',
                       help='Output HTML file (default: enhanced_report.html)')
    args = parser.parse_args()

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    parser_obj = TestSSLReportParser(content)
    findings = parser_obj.get_summary()

    html_report = generate_html_report(findings, args.input)

    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(html_report)
        print(f"✅ Enhanced report generated: {args.output}")
        print(f"📊 Findings summary:")
        print(f"   - Target: {findings['target']}")
        print(f"   - Protocols: {', '.join(findings['protocols']['supported'])}")
        print(f"   - Vulnerabilities checked: {len(findings['vulnerabilities'])}")
        critical = sum(1 for v in findings['vulnerabilities'].values() if v['severity'] == 'CRITICAL')
        warning = sum(1 for v in findings['vulnerabilities'].values() if v['severity'] == 'WARNING')
        print(f"   - Critical: {critical}, Warning: {warning}, Passed: {len(findings['vulnerabilities']) - critical - warning}")
    except Exception as e:
        print(f"Error writing output: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()