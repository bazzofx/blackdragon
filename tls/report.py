#!/usr/bin/env python3
"""
testssl_report_enhancer.py - Parse testssl.sh HTML report and generate
a modern, professional summary with key findings highlighted.
"""

import re
import sys
import argparse
from datetime import datetime
from html import escape
from typing import Dict, List, Tuple, Optional

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
        return text.strip()

    def _determine_severity(self, status: str, detail: str) -> str:
        """
        Determine severity based on status text and detail.
        Only marks as CRITICAL if explicitly vulnerable.
        """
        # Combine for easier checking
        combined = f"{status} {detail}".lower()

        # CRITICAL: Only if explicitly vulnerable (not negated)
        if 'vulnerable' in combined or 'vuln' in combined:
            # But check for negations FIRST
            if 'not vulnerable' in combined or 'not vuln' in combined:
                return 'PASS'
            if 'no rc4' in combined:
                return 'PASS'
            if 'no cipher' in combined:
                return 'PASS'
            if 'does not support' in combined:
                return 'PASS'
            # If we get here, it's actually vulnerable
            return 'CRITICAL'

        # CRITICAL: Explicit vulnerability indicators
        if 'not ok' in combined:
            return 'CRITICAL'

        # WARNING: Potentially vulnerable
        if 'potentially' in combined and 'vulnerable' in combined:
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
            # Target and IP
            clean_line = self._clean_html(line)
            
            # Domain capture using regex: (?<=\()[^)]+\.[^)]+(?=\))
            if '--&gt;&gt;' in line or '-->>' in line:
                domain_match = re.search(r'(?<=\()[^)]+\.[^)]+(?=\))', clean_line)
                if domain_match:
                    self.findings['target'] = domain_match.group(0)

            # IP capture using regex: ^Testing all IP addresses.*:\s*(\d{1,3}(?:\.\d{1,3}){3}(?:\s+\d{1,3}(?:\.\d{1,3}){3})*)$
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

            # Vulnerability findings - improved pattern matching
            vuln_patterns = {
                'Heartbleed': r'Heartbleed.*?(not vulnerable|vulnerable|OK)',
                'CCS': r'CCS.*?(not vulnerable|vulnerable|OK)',
                'Ticketbleed': r'Ticketbleed.*?(not vulnerable|vulnerable|OK)',
                'Opossum': r'Opossum.*?(not vulnerable|vulnerable|OK)',
                'ROBOT': r'ROBOT.*?(does not support|not vulnerable|vulnerable|OK)',
                'Secure Renegotiation': r'Secure Renegotiation.*?(supported|not supported)',
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
                # Skip if already processed
                if vuln_name in processed_vulns:
                    continue

                # Check if this line contains the vulnerability name
                if vuln_name in line:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        status = match.group(1)
                        # Clean the status text
                        status = self._clean_html(status)

                        # Get the full detail
                        detail = self._clean_html(line)

                        # Determine severity using the improved logic
                        severity = self._determine_severity(status, detail)

                        # Special case for BREACH
                        if 'BREACH' in vuln_name:
                            if 'not ok' in detail.lower() or 'NOT ok' in detail:
                                severity = 'CRITICAL'
                                self.findings['breach'] = True
                            elif 'potentially' in detail.lower():
                                severity = 'WARNING'
                                self.findings['breach'] = True

                        # Special case for BEAST - extract vulnerable ciphers
                        if 'BEAST' in vuln_name and 'VULNERABLE' in detail:
                            cipher_match = re.search(r'TLS1:\s*([^\s]+(?:\s+[^\s]+)*)', detail)
                            if cipher_match:
                                detail = f"BEAST vulnerable ciphers: {cipher_match.group(1)}"

                        # Extract original info (name + CVE details before status)
                        clean_match = re.search(pattern, clean_line, re.IGNORECASE)
                        if clean_match:
                            status_start = clean_match.start(1)
                            original_info = clean_line[:status_start].strip()
                            original_info = re.sub(r'\s+potentially$', '', original_info)
                            original_info = re.sub(r'\s+server$', '', original_info, flags=re.IGNORECASE)
                        else:
                            original_info = vuln_name

                        # Store the finding
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

            # Forward secrecy (look for ECDHE in cipher lines)
            if 'ECDHE' in line and ('x' in line or 'TLS_' in line):
                clean_cipher = self._clean_html(line)
                if clean_cipher and 'ECDHE' in clean_cipher:
                    if clean_cipher not in self.findings['ciphers']['forward_secrecy']:
                        self.findings['ciphers']['forward_secrecy'].append(clean_cipher)

            # Weak ciphers (look for RC4, 3DES, etc.)
            if re.search(r'RC4|3DES|IDEA|DES', line, re.IGNORECASE):
                clean_cipher = self._clean_html(line)
                if clean_cipher and clean_cipher not in self.findings['ciphers']['weak']:
                    self.findings['ciphers']['weak'].append(clean_cipher)

    def get_summary(self) -> Dict:
        """Return structured summary of findings."""
        return self.findings


def generate_html_report(findings: Dict, input_file: str) -> str:
    """Generate a modern HTML report from findings."""

    # Count issues by severity
    critical_vulns = {k: v for k, v in findings['vulnerabilities'].items()
                     if v['severity'] == 'CRITICAL'}
    warning_vulns = {k: v for k, v in findings['vulnerabilities'].items()
                    if v['severity'] == 'WARNING'}
    pass_vulns = {k: v for k, v in findings['vulnerabilities'].items()
                 if v['severity'] == 'PASS'}

    critical_count = len(critical_vulns)
    warning_count = len(warning_vulns)
    vuln_count = len(findings['vulnerabilities'])

    # Protocol issues
    deprecated_protos = [p for p in findings['protocols']['vulnerable']
                        if p in ['TLSv1', 'TLSv1.1']]

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLS Security Assessment Report - {findings['target']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f0f4f8;
            color: #1a2332;
            padding: 40px 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
            color: white;
            padding: 40px 50px;
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }}
        .header h1 {{
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        .header .subtitle {{
            font-size: 16px;
            opacity: 0.8;
        }}
        .header .meta {{
            margin-top: 16px;
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            font-size: 14px;
        }}
        .header .meta span {{
            background: rgba(255,255,255,0.1);
            padding: 4px 14px;
            border-radius: 20px;
        }}
        .score-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .score-card {{
            background: white;
            padding: 20px 24px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            border-left: 4px solid #e2e8f0;
        }}
        .score-card .number {{
            font-size: 32px;
            font-weight: 700;
            line-height: 1.2;
        }}
        .score-card .label {{
            font-size: 14px;
            color: #718096;
            margin-top: 2px;
        }}
        .score-card.critical {{ border-left-color: #e53e3e; }}
        .score-card.critical .number {{ color: #e53e3e; }}
        .score-card.warning {{ border-left-color: #ed8936; }}
        .score-card.warning .number {{ color: #ed8936; }}
        .score-card.pass {{ border-left-color: #38a169; }}
        .score-card.pass .number {{ color: #38a169; }}
        .score-card.info {{ border-left-color: #3182ce; }}
        .score-card.info .number {{ color: #3182ce; }}

        .section {{
            background: white;
            border-radius: 12px;
            padding: 28px 32px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }}
        .section h2 {{
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .section h2 .badge {{
            font-size: 12px;
            font-weight: 500;
            padding: 2px 12px;
            border-radius: 20px;
            background: #e2e8f0;
            color: #4a5568;
        }}
        .section h2 .badge.critical {{ background: #fed7d7; color: #c53030; }}
        .section h2 .badge.warning {{ background: #feebc8; color: #c05621; }}
        .section h2 .badge.pass {{ background: #c6f6d5; color: #276749; }}

        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 14px;
        }}
        .vuln-table th {{
            text-align: left;
            padding: 12px 16px;
            background: #f7fafc;
            font-weight: 600;
            border-bottom: 2px solid #e2e8f0;
            color: #4a5568;
        }}
        .vuln-table td {{
            padding: 12px 16px;
            border-bottom: 1px solid #edf2f7;
            vertical-align: middle;
        }}
        .vuln-table tr:hover td {{
            background: #f7fafc;
        }}
        .vuln-table .vuln-name {{
            font-weight: 600;
            color: #2d3748;
        }}
        .vuln-table .vuln-detail-text {{
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #4a5568;
            word-break: break-all;
        }}
        .status.critical {{ background: #fed7d7; color: #c53030; }}
        .status.warning {{ background: #feebc8; color: #c05621; }}
        .status.pass {{ background: #c6f6d5; color: #276749; }}
        .status.info {{ background: #bee3f8; color: #2b6cb0; }}

        .protocol-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 4px;
        }}
        .protocol-item {{
            padding: 4px 16px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
            background: #e2e8f0;
        }}
        .protocol-item.deprecated {{
            background: #fed7d7;
            color: #c53030;
        }}
        .protocol-item.supported {{
            background: #c6f6d5;
            color: #276749;
        }}

        .cipher-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            margin-top: 8px;
        }}
        .cipher-table th {{
            text-align: left;
            padding: 10px 14px;
            background: #f7fafc;
            font-weight: 600;
            border-bottom: 2px solid #e2e8f0;
        }}
        .cipher-table td {{
            padding: 8px 14px;
            border-bottom: 1px solid #f0f4f8;
        }}
        .cipher-table tr:hover td {{
            background: #f7fafc;
        }}
        .cipher-table .fs {{
            color: #2b6cb0;
            font-weight: 500;
        }}
        .cipher-table .weak {{
            color: #e53e3e;
            font-weight: 500;
        }}

        .vuln-list {{
            list-style: none;
            padding: 0;
            margin: 8px 0;
        }}
        .vuln-list li {{
            padding: 8px 14px;
            margin-bottom: 4px;
            border-radius: 6px;
            font-size: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
            background: #f7fafc;
        }}
        .vuln-list li.critical {{
            border-left: 4px solid #e53e3e;
            background: #fff5f5;
        }}
        .vuln-list li.warning {{
            border-left: 4px solid #ed8936;
            background: #fffbeb;
        }}
        .vuln-list .vuln-name {{
            font-weight: 600;
        }}
        .vuln-list .vuln-status {{
            font-size: 13px;
            padding: 2px 12px;
            border-radius: 20px;
            font-weight: 500;
            background: #e2e8f0;
        }}
        .vuln-list .vuln-status.critical {{ background: #fed7d7; color: #c53030; }}
        .vuln-list .vuln-status.warning {{ background: #feebc8; color: #c05621; }}
        .vuln-list .vuln-status.pass {{ background: #c6f6d5; color: #276749; }}
        .vuln-list .vuln-detail {{
            width: 100%;
            font-size: 13px;
            color: #4a5568;
            padding: 4px 0 0 0;
            font-family: 'Courier New', monospace;
            background: #edf2f7;
            padding: 4px 8px;
            border-radius: 4px;
            margin-top: 4px;
        }}

        .footer {{
            text-align: center;
            padding: 24px 0;
            color: #a0aec0;
            font-size: 14px;
        }}
        @media (max-width: 640px) {{
            body {{ padding: 16px; }}
            .header {{ padding: 24px; }}
            .section {{ padding: 20px; }}
            .score-grid {{ grid-template-columns: 1fr 1fr; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔒 TLS Security Assessment</h1>
        <div class="subtitle">Comprehensive vulnerability and configuration analysis</div>
        <div class="meta">
            <span>🎯 Target: {findings['target']}</span>
            <span>🌐 IP: {', '.join(findings['ip_addresses'])}</span>
            <span>📡 Services: {findings['service'] or 'HTTPS'}</span>
            <span>📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>
    </div>

    <div class="score-grid">
        <div class="score-card critical">
            <div class="number">{critical_count}</div>
            <div class="label">Critical Issues</div>
        </div>
        <div class="score-card warning">
            <div class="number">{warning_count}</div>
            <div class="label">Warnings</div>
        </div>
        <div class="score-card pass">
            <div class="number">{vuln_count - critical_count - warning_count}</div>
            <div class="label">Passed Checks</div>
        </div>
        <div class="score-card info">
            <div class="number">{len(findings['protocols']['supported'])}</div>
            <div class="label">TLS Protocols Supported</div>
        </div>
    </div>
'''

    # Protocol section
    html += f'''
    <div class="section">
        <h2>📋 Supported Protocols</h2>
        <div class="protocol-list">
'''
    for proto in findings['protocols']['supported']:
        if proto in ['TLSv1', 'TLSv1.1']:
            html += f'<span class="protocol-item deprecated">⚠️ {proto} (DEPRECATED)</span>'
        else:
            html += f'<span class="protocol-item supported">✅ {proto}</span>'
    html += '''
        </div>
'''
    if deprecated_protos:
        html += f'''
        <div style="margin-top:12px;padding:12px 16px;background:#fed7d7;border-radius:8px;color:#c53030;">
            ⚠️ <strong>{', '.join(deprecated_protos)}</strong> is/are still enabled.
            These protocols are deprecated and should be disabled immediately.
        </div>
'''
    html += '''
    </div>
'''

    # Vulnerability section (Table)
    html += '''
    <div class="section">
        <h2>🛡️ Vulnerability Assessment</h2>
        <table class="vuln-table">
            <thead>
                <tr>
                    <th style="width: 30%;">Name</th>
                    <th style="width: 20%;">Status</th>
                    <th style="width: 50%;">Details</th>
                </tr>
            </thead>
            <tbody>
'''
    for vuln_name, data in sorted(findings['vulnerabilities'].items()):
        status_class = data['severity'].lower()
        original_info = data.get('original_info', vuln_name)
        if status_class == 'critical':
            status_display = '❌ VULNERABLE'
        elif status_class == 'warning':
            status_display = '⚠️ WARNING'
        else:
            status_display = '✅ PASS'

        html += f'''
                <tr>
                    <td class="vuln-name">{escape(original_info)}</td>
                    <td><span class="status {status_class}">{status_display}</span></td>
                    <td class="vuln-detail-text">{escape(data['detail'])}</td>
                </tr>
'''

    html += '''
            </tbody>
        </table>
'''
    if findings['breach']:
        # Check BREACH severity
        breach_data = findings['vulnerabilities'].get('BREACH', {})
        if breach_data.get('severity') == 'CRITICAL':
            html += '''
        <div style="margin-top:12px;padding:12px 16px;background:#fed7d7;border-radius:8px;color:#c53030;">
            ❌ <strong>BREACH</strong> vulnerability detected: HTTP compression (gzip) is enabled.
            This allows attackers to decrypt sensitive data. Disable compression immediately.
        </div>
'''
        elif breach_data.get('severity') == 'WARNING':
            html += '''
        <div style="margin-top:12px;padding:12px 16px;background:#feebc8;border-radius:8px;color:#c05621;">
            ⚠️ <strong>BREACH</strong> potentially vulnerable: HTTP compression (gzip) detected.
            Consider disabling compression for sensitive content.
        </div>
'''
    html += '''
    </div>
'''

    # Forward Secrecy section
    fs_ciphers = findings['ciphers']['forward_secrecy']
    html += f'''
    <div class="section">
        <h2>🔑 Forward Secrecy</h2>
        <div style="margin-bottom:12px;">
            <span style="padding:4px 16px;border-radius:20px;background:{"#c6f6d5;color:#276749" if fs_ciphers else "#fed7d7;color:#c53030"};font-weight:500;">
                {"✅ Supported" if fs_ciphers else "❌ Not Supported"}
            </span>
        </div>
'''
    if fs_ciphers:
        html += '''
        <p style="color:#4a5568;margin-bottom:12px;">The following ciphers provide forward secrecy (Perfect Forward Secrecy):</p>
        <ul style="list-style:none;padding:0;">
'''
        for cipher in fs_ciphers[:10]:  # Limit display
            html += f'<li style="padding:4px 0;color:#2d3748;font-family:monospace;font-size:13px;">🔹 {escape(cipher)}</li>'
        if len(fs_ciphers) > 10:
            html += f'<li style="padding:4px 0;color:#718096;">... and {len(fs_ciphers) - 10} more</li>'
        html += '</ul>'
    html += '''
    </div>
'''

    # Weak ciphers section
    weak_ciphers = findings['ciphers']['weak']
    if weak_ciphers:
        html += f'''
    <div class="section">
        <h2>⚠️ Weak Ciphers Detected</h2>
        <p style="color:#e53e3e;margin-bottom:12px;">The following weak ciphers are still enabled:</p>
        <ul style="list-style:none;padding:0;">
'''
        for cipher in weak_ciphers[:10]:
            html += f'<li style="padding:4px 0;color:#c53030;font-family:monospace;font-size:13px;">🔸 {escape(cipher)}</li>'
        if len(weak_ciphers) > 10:
            html += f'<li style="padding:4px 0;color:#718096;">... and {len(weak_ciphers) - 10} more</li>'
        html += '''
        </ul>
    </div>
'''

    # Summary & Recommendations with detailed vulnerability list
    html += f'''
    <div class="section" style="background:#f7fafc;">
        <h2>📝 Summary & Recommendations</h2>
'''

    # List Critical Vulnerabilities
    # List Critical Vulnerabilities
    if critical_vulns:
        html += f'''
        <div style="margin-bottom:16px;">
            <h3 style="font-size:16px;color:#c53030;margin-bottom:10px;">❌ Critical Issues Found ({len(critical_vulns)})</h3>
            <ul class="vuln-list">
'''
        for vuln_name, data in critical_vulns.items():
            display_name = data.get('original_info', vuln_name)
            html += f'''
                <li class="critical">
                    <span class="vuln-name">{display_name}</span>
                    <span class="vuln-status critical">{data['status']}</span>
                    <div class="vuln-detail">{escape(data['detail'])}</div>
                </li>
'''
        html += '''
            </ul>
        </div>
'''

    # List Warning Vulnerabilities
    if warning_vulns:
        html += f'''
        <div style="margin-bottom:16px;">
            <h3 style="font-size:16px;color:#c05621;margin-bottom:10px;">⚠️ Warnings Found ({len(warning_vulns)})</h3>
            <ul class="vuln-list">
'''
        for vuln_name, data in warning_vulns.items():
            display_name = data.get('original_info', vuln_name)
            html += f'''
                <li class="warning">
                    <span class="vuln-name">{display_name}</span>
                    <span class="vuln-status warning">{data['status']}</span>
                    <div class="vuln-detail">{escape(data['detail'])}</div>
                </li>
'''
        html += '''
            </ul>
        </div>
'''



    # Recommendations
    html += '''
        <div style="margin-top:16px;padding:16px;background:#e2e8f0;border-radius:8px;font-size:14px;color:#4a5568;">
            <strong>📋 Action Items:</strong>
            <ul style="list-style:none;padding:8px 0 0 0;margin:0;">
'''

    if critical_count > 0:
        html += f'''
                <li style="padding:4px 0;">🔴 <strong>Immediate Action Required:</strong> {critical_count} critical vulnerability/ies found that need to be addressed urgently.</li>
'''
    if deprecated_protos:
        html += f'''
                <li style="padding:4px 0;">🔴 <strong>Disable {', '.join(deprecated_protos)}</strong> - these protocols are deprecated and insecure.</li>
'''

    # Check BREACH severity
    breach_data = findings['vulnerabilities'].get('BREACH', {})
    if breach_data.get('severity') == 'CRITICAL':
        html += '''
                <li style="padding:4px 0;">🔴 <strong>Disable HTTP Compression (gzip)</strong> to mitigate BREACH vulnerability immediately.</li>
'''
    elif breach_data.get('severity') == 'WARNING':
        html += '''
                <li style="padding:4px 0;">🟡 <strong>Review HTTP Compression</strong> - gzip compression detected, consider disabling for sensitive content.</li>
'''

    if not fs_ciphers:
        html += '''
                <li style="padding:4px 0;">🔴 <strong>Enable Forward Secrecy</strong> - prioritize ECDHE/DHE cipher suites.</li>
'''
    if weak_ciphers:
        html += f'''
                <li style="padding:4px 0;">🔴 <strong>Remove {len(weak_ciphers)} weak cipher(s)</strong> including RC4, 3DES, and other deprecated algorithms.</li>
'''

    if critical_count == 0 and warning_count == 0:
        html += '''
                <li style="padding:4px 0;">✅ <strong>No critical issues found.</strong> Continue monitoring for best practices.</li>
'''

    html += f'''
            </ul>
        </div>

    </div>

    <div class="footer">
        Generated by testssl-report-enhancer &bull; For professional security assessment purposes
    </div>
</div>
</body>
</html>
'''
    return html


def main():
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

    parser = TestSSLReportParser(content)
    findings = parser.get_summary()

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