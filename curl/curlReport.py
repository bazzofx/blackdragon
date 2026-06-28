#!/usr/bin/env python3
"""
Website Assessment Tool using curl
Usage: python3 curlv1.py <domain>
"""

import subprocess
import re
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class WebsiteAssessor:
    def __init__(self, target: str):
        self.target = target
        self.http_url = f"http://{target}"
        self.https_url = f"https://{target}"
        self.results = {}
        self.findings = []
        self.recommendations = []
        
    def run_command(self, cmd: str, timeout: int = 10) -> Tuple[str, int]:
        """Run a shell command and return output and return code"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return f"Command timed out after {timeout}s", 1
        except Exception as e:
            return str(e), 1

    def test_http_redirect(self):
        """Test if HTTP redirects to HTTPS"""
        print("[1/8] Testing HTTP to HTTPS redirect...")
        output, code = self.run_command(f"curl -I -L {self.http_url} 2>/dev/null")
        
        redirects_to_https = "Location: https" in output
        final_url = self.http_url
        
        if redirects_to_https:
            # Get the final URL
            redirect_cmd = f"curl -Ls -o /dev/null -w '%{{url_effective}}' {self.http_url}"
            final_url, _ = self.run_command(redirect_cmd)
            final_url = final_url.strip()
        
        # Get redirect chain
        chain_output, _ = self.run_command(
            f"curl -Ls -o /dev/null -w 'HTTP: %{{http_code}} -> %{{url_effective}}\n' {self.http_url}"
        )
        
        self.results['redirect'] = {
            'redirects_to_https': redirects_to_https,
            'final_url': final_url,
            'chain': chain_output.strip()
        }
        
        if redirects_to_https:
            self.results['redirect']['status'] = 'PASS'
            self.results['redirect']['message'] = 'Site redirects HTTP to HTTPS'
        else:
            self.results['redirect']['status'] = 'FAIL'
            self.results['redirect']['message'] = 'Site does NOT redirect HTTP to HTTPS'

    def test_https_details(self):
        """Get HTTPS connection details"""
        print("[2/8] Getting HTTPS details...")
        output, code = self.run_command(f"curl -Iv {self.https_url} 2>&1", 15)
        
        ssl_info = {
            'ssl_version': self.extract_field(output, 'SSL connection using'),
            'cipher': self.extract_field(output, 'cipher:'),
            'subject': self.extract_field(output, 'subject:'),
            'issuer': self.extract_field(output, 'issuer:'),
            'start_date': self.extract_field(output, 'start date:'),
            'expire_date': self.extract_field(output, 'expire date:')
        }
        
        self.results['https_details'] = ssl_info

    def test_hsts(self):
        """Check for HSTS header"""
        print("[3/8] Testing HSTS header...")
        output, code = self.run_command(f"curl -sI {self.https_url}")
        
        hsts_header = None
        for line in output.split('\n'):
            if 'strict-transport-security' in line.lower():
                hsts_header = line.strip()
                break
        
        hsts_info = {
            'enabled': hsts_header is not None,
            'header': hsts_header
        }
        
        if hsts_header:
            # Parse max-age
            max_age_match = re.search(r'max-age=(\d+)', hsts_header)
            if max_age_match:
                hsts_info['max_age'] = int(max_age_match.group(1))
                hsts_info['max_age_days'] = int(max_age_match.group(1)) / 86400
            
            hsts_info['include_subdomains'] = 'includeSubDomains' in hsts_header
            hsts_info['preload'] = 'preload' in hsts_header
        
        self.results['hsts'] = hsts_info

    def test_http2(self):
        """Test HTTP/2 support"""
        print("[4/8] Testing HTTP/2 support...")
        output, code = self.run_command(f"curl -sI --http2 {self.https_url}")
        
        http2_supported = 'HTTP/2' in output
        
        self.results['http2'] = {
            'supported': http2_supported
        }

    def test_security_headers(self):
        """Check common security headers"""
        print("[5/8] Checking security headers...")
        output, code = self.run_command(f"curl -sI {self.https_url}")
        
        headers = {
            'content_security_policy': False,
            'x_frame_options': False,
            'x_content_type_options': False,
            'x_xss_protection': False,
            'referrer_policy': False,
            'permissions_policy': False,
            'server': None,
            'x_powered_by': None
        }
        
        for line in output.split('\n'):
            line_lower = line.lower()
            if 'content-security-policy:' in line_lower:
                headers['content_security_policy'] = True
            if 'x-frame-options:' in line_lower:
                headers['x_frame_options'] = True
            if 'x-content-type-options:' in line_lower:
                headers['x_content_type_options'] = True
            if 'x-xss-protection:' in line_lower:
                headers['x_xss_protection'] = True
            if 'referrer-policy:' in line_lower:
                headers['referrer_policy'] = True
            if 'permissions-policy:' in line_lower:
                headers['permissions_policy'] = True
            if 'server:' in line_lower and 'content-security' not in line_lower:
                headers['server'] = line.split(':')[1].strip()
            if 'x-powered-by:' in line_lower:
                headers['x_powered_by'] = line.split(':')[1].strip()
        
        self.results['security_headers'] = headers

    def test_cookies(self):
        """Check cookie security"""
        print("[6/8] Checking cookie security...")
        output, code = self.run_command(f"curl -sI -i {self.https_url}")
        
        cookies = []
        for line in output.split('\n'):
            if 'Set-Cookie:' in line:
                cookie = {
                    'raw': line.strip(),
                    'secure': 'Secure' in line,
                    'httponly': 'HttpOnly' in line,
                    'samesite': None
                }
                
                same_site_match = re.search(r'SameSite=(\w+)', line)
                if same_site_match:
                    cookie['samesite'] = same_site_match.group(1)
                
                # Extract cookie name
                name_match = re.match(r'Set-Cookie:\s*([^=;]+)', line)
                if name_match:
                    cookie['name'] = name_match.group(1)
                
                cookies.append(cookie)
        
        self.results['cookies'] = cookies

    def test_exposed_info(self):
        """Check for exposed information"""
        print("[7/8] Checking for exposed information...")
        
        # Check for directory listing
        output, code = self.run_command(f"curl -s {self.https_url}/")
        directory_listing = 'Index of' in output or '<title>Index of' in output
        
        self.results['exposed_info'] = {
            'directory_listing': directory_listing,
            'server_version': self.results['security_headers'].get('server'),
            'powered_by': self.results['security_headers'].get('x_powered_by')
        }

    def test_response_time(self):
        """Test response time"""
        print("[8/8] Testing response time...")
        output, code = self.run_command(
            f"curl -s -o /dev/null -w '%{{time_total}}' {self.https_url}"
        )
        
        try:
            response_time = float(output.strip())
        except:
            response_time = None
        
        self.results['response_time'] = {
            'seconds': response_time,
            'milliseconds': response_time * 1000 if response_time else None
        }

    def extract_field(self, text: str, field: str) -> Optional[str]:
        """Extract a field from text"""
        for line in text.split('\n'):
            if field in line.lower():
                return line.strip()
        return None

    def assess_security(self):
        """Perform security assessment"""
        self.findings = []
        self.recommendations = []
        risk_score = 0
        
        # Check redirect
        if not self.results['redirect']['redirects_to_https']:
            self.findings.append(('CRITICAL', 'No HTTP to HTTPS redirect', 
                                'Site accepts HTTP connections without redirecting'))
            self.recommendations.append('Configure server to redirect HTTP to HTTPS')
            risk_score += 40
        
        # Check HSTS
        if not self.results['hsts']['enabled']:
            self.findings.append(('HIGH', 'HSTS header missing', 
                                'No HSTS policy defined'))
            self.recommendations.append('Implement HSTS header with max-age=31536000')
            risk_score += 25
        
        # Check security headers
        headers = self.results['security_headers']
        if not headers['content_security_policy']:
            self.findings.append(('HIGH', 'CSP header missing', 
                                'Content-Security-Policy not set'))
            self.recommendations.append('Implement Content-Security-Policy')
            risk_score += 15
        
        if not headers['x_frame_options']:
            self.findings.append(('MEDIUM', 'X-Frame-Options missing', 
                                'Clickjacking protection missing'))
            self.recommendations.append('Add X-Frame-Options: SAMEORIGIN')
            risk_score += 10
        
        if not headers['x_content_type_options']:
            self.findings.append(('LOW', 'X-Content-Type-Options missing', 
                                'MIME type sniffing protection missing'))
            self.recommendations.append('Add X-Content-Type-Options: nosniff')
            risk_score += 5
        
        # Check cookies
        for cookie in self.results['cookies']:
            if not cookie['secure']:
                self.findings.append(('HIGH', f'Cookie "{cookie["name"]}" missing Secure flag',
                                    'Cookie can be sent over HTTP'))
                self.recommendations.append(f'Add Secure flag to "{cookie["name"]}" cookie')
                risk_score += 15
            if not cookie['httponly']:
                self.findings.append(('MEDIUM', f'Cookie "{cookie["name"]}" missing HttpOnly',
                                    'Cookie accessible via JavaScript'))
                self.recommendations.append(f'Add HttpOnly flag to "{cookie["name"]}" cookie')
                risk_score += 10
        
        # Check exposed info
        if self.results['exposed_info']['server_version']:
            self.findings.append(('LOW', 'Server version exposed',
                                f"Server: {self.results['exposed_info']['server_version']}"))
            self.recommendations.append('Remove or obscure server version information')
            risk_score += 5
        
        if self.results['exposed_info']['directory_listing']:
            self.findings.append(('HIGH', 'Directory listing enabled',
                                'Directory indexing is enabled'))
            self.recommendations.append('Disable directory listing on the server')
            risk_score += 20
        
        # Determine risk level
        if risk_score >= 50:
            self.risk_level = 'CRITICAL'
        elif risk_score >= 25:
            self.risk_level = 'HIGH'
        elif risk_score >= 10:
            self.risk_level = 'MEDIUM'
        else:
            self.risk_level = 'LOW'
        
        self.risk_score = risk_score

    def generate_markdown(self) -> str:
        """Generate markdown report"""
        md = []
        
        # Header
        md.append(f"# Website Security Assessment Report\n")
        md.append(f"## Target: {self.target}\n")
        md.append(f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        md.append(f"**Risk Level:** **{self.risk_level}**\n")
        md.append(f"**Risk Score:** {self.risk_score}/100\n")
        md.append("---\n\n")
        
        # 1. HTTP Redirect
        md.append("## 1. HTTP to HTTPS Redirect\n")
        redirect = self.results['redirect']
        status_icon = "✅" if redirect['redirects_to_https'] else "❌"
        md.append(f"{status_icon} **{redirect['message']}**\n")
        md.append(f"- Final URL: `{redirect['final_url']}`\n\n")
        
        # 2. HTTPS Details
        md.append("## 2. HTTPS Connection Details\n")
        https = self.results['https_details']
        md.append("| Detail | Value |\n")
        md.append("|--------|-------|\n")
        md.append(f"| SSL/TLS Version | `{https.get('ssl_version', 'N/A')}` |\n")
        md.append(f"| Cipher | `{https.get('cipher', 'N/A')}` |\n")
        md.append(f"| Certificate Subject | `{https.get('subject', 'N/A')}` |\n")
        md.append(f"| Certificate Issuer | `{https.get('issuer', 'N/A')}` |\n")
        md.append(f"| Certificate Expiry | `{https.get('expire_date', 'N/A')}` |\n\n")
        
        # 3. HSTS
        md.append("## 3. HSTS (HTTP Strict Transport Security)\n")
        hsts = self.results['hsts']
        if hsts['enabled']:
            md.append("✅ **Enabled**\n")
            md.append(f"- Header: `{hsts['header']}`\n")
            if hsts.get('max_age_days'):
                md.append(f"- Max-Age: {hsts['max_age_days']:.0f} days\n")
            md.append(f"- Include Subdomains: {'✅ Yes' if hsts.get('include_subdomains') else '❌ No'}\n")
            md.append(f"- Preload Ready: {'✅ Yes' if hsts.get('preload') else '❌ No'}\n")
        else:
            md.append("❌ **Disabled** - HSTS header not found\n")
        md.append("\n")
        
        # 4. HTTP/2
        md.append("## 4. HTTP/2 Support\n")
        http2 = self.results['http2']
        md.append(f"HTTP/2: {'✅ Supported' if http2['supported'] else '❌ Not Supported'}\n\n")
        
        # 5. Security Headers
        md.append("## 5. Security Headers\n")
        headers = self.results['security_headers']
        md.append("| Header | Status |\n")
        md.append("|--------|--------|\n")
        header_map = {
            'content_security_policy': 'Content-Security-Policy',
            'x_frame_options': 'X-Frame-Options',
            'x_content_type_options': 'X-Content-Type-Options',
            'x_xss_protection': 'X-XSS-Protection',
            'referrer_policy': 'Referrer-Policy',
            'permissions_policy': 'Permissions-Policy'
        }
        for key, name in header_map.items():
            status = '✅ Present' if headers[key] else '❌ Missing'
            md.append(f"| {name} | {status} |\n")
        if headers.get('server'):
            md.append(f"| Server | `{headers['server']}` |\n")
        if headers.get('x_powered_by'):
            md.append(f"| X-Powered-By | `{headers['x_powered_by']}` |\n")
        md.append("\n")
        
        # 6. Cookies
        md.append("## 6. Cookie Security\n")
        if self.results['cookies']:
            md.append("| Cookie | Secure | HttpOnly | SameSite |\n")
            md.append("|--------|--------|----------|----------|\n")
            for cookie in self.results['cookies']:
                md.append(f"| {cookie.get('name', 'Unknown')} | "
                         f"{'✅' if cookie['secure'] else '❌'} | "
                         f"{'✅' if cookie['httponly'] else '❌'} | "
                         f"{cookie.get('samesite', 'Not Set')} |\n")
        else:
            md.append("No cookies found\n")
        md.append("\n")
        
        # 7. Exposed Information
        md.append("## 7. Exposed Information\n")
        exposed = self.results['exposed_info']
        md.append(f"- Directory Listing: {'✅ Enabled' if exposed['directory_listing'] else '❌ Disabled'}\n")
        if exposed['server_version']:
            md.append(f"- Server Version: `{exposed['server_version']}`\n")
        if exposed['powered_by']:
            md.append(f"- X-Powered-By: `{exposed['powered_by']}`\n")
        md.append("\n")
        
        # 8. Response Time
        md.append("## 8. Response Time\n")
        if self.results['response_time']['seconds']:
            rt = self.results['response_time']
            md.append(f"- {rt['seconds']:.2f} seconds ({rt['milliseconds']:.0f} ms)\n")
        md.append("\n")
        
        md.append("---\n\n")
        
        # Findings
        md.append("## 🔍 Security Findings\n")
        if self.findings:
            for severity, title, details in self.findings:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                md.append(f"### {emoji} {severity}: {title}\n")
                md.append(f"{details}\n\n")
        else:
            md.append("✅ No security issues found!\n\n")
        
        # Recommendations
        md.append("## 💡 Recommendations\n")
        if self.recommendations:
            for i, rec in enumerate(self.recommendations, 1):
                md.append(f"{i}. {rec}\n")
        else:
            md.append("✅ No recommendations needed\n")
        
        # Footer
        md.append("\n---\n")
        md.append(f"*Report generated by Website Assessment Tool*\n")
        md.append(f"*Target: {self.target}*\n")
        md.append(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")
        
        return ''.join(md)

    def generate_html(self) -> str:
        """Generate a branded, high-fidelity HTML report matching the Cyber Samurai theme."""
        import os
        import base64
        from html import escape
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Load global CSS
        css_content = ""
        css_paths = [
            os.path.join(script_dir, '..', 'reference', 'global_report.css'),
            os.path.join(script_dir, 'reference', 'global_report.css'),
            'global_report.css'
        ]
        for path in css_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        css_content = f.read()
                    break
                except:
                    pass
                    
        # Fallback CSS in case the file isn't found
        if not css_content:
            css_content = """
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
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Inter', sans-serif;
                background: var(--bg-primary);
                color: var(--text-primary);
                min-height: 100vh;
                line-height: 1.6;
            }
            .container { max-width: 1200px; margin: 0 auto; padding: 40px 24px; position: relative; z-index: 10; }
            """
            
        # Load samurai hero background
        hero_bg_base64 = ""
        banner_paths = [
            os.path.join(script_dir, '..', 'reference', 'cyber_samurai_banner.jpg'),
            os.path.join(script_dir, 'reference', 'cyber_samurai_banner.jpg')
        ]
        for path in banner_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as img_file:
                        hero_bg_base64 = base64.b64encode(img_file.read()).decode('utf-8')
                    break
                except:
                    pass

        # Calculate security health score
        health_score = max(0, 100 - self.risk_score)
        if health_score >= 90:
            score_rating = "SECURE"
            score_color = "#10b981"
        elif health_score >= 75:
            score_rating = "STRONG"
            score_color = "#3b82f6"
        elif health_score >= 50:
            score_rating = "WARNING"
            score_color = "#f59e0b"
        else:
            score_rating = "CRITICAL"
            score_color = "#ff2e3b"
            
        # SVG circle offset: 2 * PI * 68 = 427
        score_offset = 427 - (427 * health_score // 100)
        
        # Count findings by severity
        critical_count = sum(1 for f in self.findings if f[0] == 'CRITICAL')
        high_count = sum(1 for f in self.findings if f[0] == 'HIGH')
        medium_count = sum(1 for f in self.findings if f[0] == 'MEDIUM')
        low_count = sum(1 for f in self.findings if f[0] == 'LOW')
        warning_count = high_count + medium_count + low_count
        
        # Build executive summary text
        exec_summary = f"""
        A comprehensive website security assessment and header analysis has been completed for <strong>{escape(self.target)}</strong>. 
        The target host is currently evaluated as <strong>{score_rating}</strong> with a security posture rating of <strong>{health_score}%</strong>.
        <br><br>
        This assessment verified essential security controls including HTTP-to-HTTPS redirection, HSTS configuration, HTTP/2 support, HTTP security headers (CSP, X-Frame-Options, etc.), cookie security flags, and information disclosure indicators.
        <br><br>
        Key Observations:
        <ul class="bullet-list">
            <li>Redirect Status: {"HTTP is correctly redirected to HTTPS." if self.results['redirect']['redirects_to_https'] else "<strong>HTTP is NOT redirected to HTTPS!</strong> This exposes traffic to interception."}</li>
            <li>HSTS Status: {"HTTP Strict Transport Security (HSTS) is enabled, enforcing secure connections." if self.results['hsts']['enabled'] else "<strong>HSTS is missing!</strong> Browsers can be forced to downgrade to insecure HTTP."}</li>
            <li>Security Headers: There are <strong>{warning_count}</strong> warnings regarding missing HTTP security headers or server disclosures.</li>
        </ul>
        """

        # Build Findings Cards HTML
        findings_html = ""
        severity_priority = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(self.findings, key=lambda x: severity_priority.get(x[0], 4))
        
        for idx, (severity, title, detail) in enumerate(sorted_findings):
            status_class = severity.lower()
            badge_class = f"badge-{status_class}"
            
            desc = detail
            remediation = ""
            for rec in self.recommendations:
                if title.split()[0].lower() in rec.lower() or (len(title.split()) > 1 and title.split()[1].lower() in rec.lower()):
                    remediation = rec
                    break
            if not remediation:
                remediation = "Apply security patches or update server HTTP configuration headers."

            findings_html += f'''
            <div class="vuln-item-card" data-severity="{status_class}" style="margin-bottom:12px; border: 1px solid var(--border-color); border-radius:8px; background:rgba(255,255,255,0.01);">
                <div class="vuln-card-header" onclick="toggleVulnCard(this)" style="display:flex; justify-content:space-between; align-items:center; padding:16px; cursor:pointer;">
                    <div style="display:flex; align-items:center; gap:12px;">
                        <span class="badge {badge_class}" style="padding:4px 10px; font-size:11px;">{severity}</span>
                        <div style="font-size:14.5px; font-weight:600; font-family:\'Outfit\',sans-serif; color:#fff;">{escape(title)}</div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <svg class="arrow-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    </div>
                </div>
                
                <div class="vuln-card-body" style="display:none; padding: 0 16px 16px 16px; border-top: 1px solid rgba(255,255,255,0.03);">
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-top:12px;">
                        <div>
                            <span style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Details</span>
                            <p style="font-size:13px; color:var(--text-secondary); margin-top:4px;">{escape(desc)}</p>
                        </div>
                        <div>
                            <span style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Remediation</span>
                            <p style="font-size:13px; color:var(--text-secondary); margin-top:4px;">{escape(remediation)}</p>
                        </div>
                    </div>
                </div>
            </div>'''

        # Build Config Details tables
        redirect = self.results['redirect']
        hsts = self.results['hsts']
        http2 = self.results['http2']
        rt = self.results['response_time']
        
        hsts_max_age = f"{hsts.get('max_age_days', 0):.0f} days ({hsts.get('max_age', 0)} s)" if hsts.get('max_age') else "N/A"
        
        table1_rows = f'''
        <tr><td>Redirect Active</td><td>{"✅ Yes" if redirect['redirects_to_https'] else "❌ No"}</td></tr>
        <tr><td>Final URL</td><td><code>{escape(redirect['final_url'])}</code></td></tr>
        <tr><td>HSTS Status</td><td>{"✅ Enabled" if hsts['enabled'] else "❌ Disabled"}</td></tr>
        <tr><td>HSTS Max-Age</td><td>{hsts_max_age}</td></tr>
        <tr><td>HSTS Subdomains</td><td>{"✅ Yes" if hsts.get('include_subdomains') else "❌ No / N/A"}</td></tr>
        <tr><td>HSTS Preload</td><td>{"✅ Yes" if hsts.get('preload') else "❌ No / N/A"}</td></tr>
        <tr><td>HTTP/2 Supported</td><td>{"✅ Yes" if http2['supported'] else "❌ No"}</td></tr>
        <tr><td>Response Time</td><td>{rt['seconds']:.2f} s ({rt['milliseconds']:.0f} ms)</td></tr>
        '''
        
        headers = self.results['security_headers']
        cookies = self.results['cookies']
        exposed = self.results['exposed_info']
        
        cookie_list_html = ""
        if cookies:
            cookie_list_html = '<div style="display:flex; flex-direction:column; gap:8px; margin-top:8px;">'
            for c in cookies:
                cookie_list_html += f'''
                <div style="background:rgba(255,255,255,0.02); padding:8px; border-radius:6px; border:1px solid var(--border-color);">
                    <div style="font-size:12px; font-weight:700; color:#fff;">{escape(c.get('name', 'Unknown'))}</div>
                    <div style="display:flex; gap:8px; margin-top:4px; font-size:10px;">
                        <span class="badge {'badge-green' if c['secure'] else 'badge-red'}">Secure: {c['secure']}</span>
                        <span class="badge {'badge-green' if c['httponly'] else 'badge-red'}">HttpOnly: {c['httponly']}</span>
                        <span class="badge badge-blue">SameSite: {escape(c.get('samesite') or 'Not Set')}</span>
                    </div>
                </div>'''
            cookie_list_html += '</div>'
        else:
            cookie_list_html = "No cookies detected."

        table2_rows = f'''
        <tr><td>CSP Header</td><td>{"✅ Present" if headers['content_security_policy'] else "❌ Missing"}</td></tr>
        <tr><td>X-Frame-Options</td><td>{"✅ Present" if headers['x_frame_options'] else "❌ Missing"}</td></tr>
        <tr><td>X-Content-Type-Options</td><td>{"✅ Present" if headers['x_content_type_options'] else "❌ Missing"}</td></tr>
        <tr><td>Referrer-Policy</td><td>{"✅ Present" if headers['referrer_policy'] else "❌ Missing"}</td></tr>
        <tr><td>Server Header Info</td><td><code>{escape(exposed['server_version'] or 'Not Exposed')}</code></td></tr>
        <tr><td>Powered-By Header</td><td><code>{escape(exposed['powered_by'] or 'Not Exposed')}</code></td></tr>
        <tr><td>Directory Listing</td><td>{"⚠️ Enabled" if exposed['directory_listing'] else "✅ Disabled"}</td></tr>
        '''

        # Build Remediation Roadmap HTML
        remed_html = ""
        if self.recommendations:
            remed_html = '<div class="roadmap-priority-group">'
            remed_html += '<div class="priority-title priority-critical" style="font-size:13px; font-weight:700; color:var(--accent-red); margin-bottom:12px; text-transform:uppercase; letter-spacing:0.5px;">Recommended Adjustments</div>'
            for idx, rec in enumerate(self.recommendations, 1):
                remed_html += f'''
                <div class="roadmap-item" style="background:rgba(255,255,255,0.01); border:1px solid var(--border-color); padding:16px; border-radius:8px; margin-bottom:12px; display:flex; align-items:center; gap:12px;">
                    <div style="font-size:16px; font-weight:800; color:var(--accent-red); font-family:\'Outfit\',sans-serif;">{idx:02d}</div>
                    <div class="roadmap-item-details">
                        <div class="roadmap-item-title" style="font-size:13.5px; font-weight:600; color:#fff;">{escape(rec)}</div>
                    </div>
                </div>'''
            remed_html += '</div>'
        else:
            remed_html = '''
            <div style="text-align: center; padding: 40px 10px; color: var(--color-pass);">
                <h3 style="font-family:\'Outfit\',sans-serif;font-size:18px;margin-bottom:4px;">No adjustments needed</h3>
                <p style="font-size:12.5px;color:var(--text-secondary);">Your website configuration conforms to top security standards.</p>
            </div>'''

        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CYBER SAMURAI | Website Security Assessment</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        <!--CSS_CONTENT-->
        
        .vuln-item-card.expanded .vuln-card-body {
            display: block !important;
        }
        .vuln-item-card.expanded .arrow-icon {
            transform: rotate(180deg);
        }
        .arrow-icon {
            transition: transform 0.2s ease;
            color: var(--text-muted);
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
    </style>
</head>
<body>
    <div class="container">
        <!-- Floating Header bar -->
        <div class="header-bar">
            <div class="brand">
                <div class="brand-logo">Cyber Samurai<span>.</span></div>
                <div class="brand-japanese">侍</div>
            </div>
            <a class="btn-print" href="https://cybersamurai.co.uk/contact" target="_blank">
                Contact Cyber Samurai
            </a>
        </div>

        <!-- Hero Section -->
        <div class="hero-section" id="hero-banner">
            <div class="hero-overlay"></div>
            <div class="hero-content">
                <div class="hero-tagline">Header & HTTP Assessment</div>
                <h1 class="hero-title">Website Security Scan</h1>
                
                <div class="hero-meta">
                    <div class="meta-item">
                        <span class="meta-label">Target Host</span>
                        <span class="meta-val"><!--TARGET--></span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Scan Timestamp</span>
                        <span class="meta-val"><!--TIMESTAMP--></span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <div class="tabs-nav">
            <button class="tab-btn active" onclick="switchTab(event, 'dashboard')">Overview</button>
            <button class="tab-btn" onclick="switchTab(event, 'findings')">Security Findings</button>
            <button class="tab-btn" onclick="switchTab(event, 'config')">Config Details</button>
            <button class="tab-btn" onclick="switchTab(event, 'roadmap')">Action Roadmap</button>
        </div>

        <!-- TAB 1: OVERVIEW DASHBOARD -->
        <div id="dashboard" class="tab-content active">
            <div class="dashboard-grid" style="display: grid; grid-template-columns: 320px 1fr; gap: 24px; margin-bottom: 24px;">
                <!-- Left panel: Health score circular ring + counts -->
                <div class="dashboard-left" style="display: flex; flex-direction: column; gap: 24px;">
                    <div class="glass-card card-red health-score-card" style="text-align:center;">
                        <div style="font-size: 13px; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; font-family: 'Outfit', sans-serif;">Security Health</div>
                        <div class="health-score-container" style="display: flex; flex-direction: column; align-items: center; justify-content: center; position: relative;">
                            <svg class="progress-ring" width="160" height="160" style="transform: rotate(-90deg);">
                                <circle class="progress-ring__background" stroke="rgba(255, 255, 255, 0.04)" stroke-width="12" fill="transparent" r="68" cx="80" cy="80"/>
                                <circle class="progress-ring__circle" stroke="<!--SCORE_COLOR-->" stroke-width="12" stroke-dasharray="427 427" stroke-dashoffset="<!--SCORE_OFFSET-->" stroke-linecap="round" fill="transparent" r="68" cx="80" cy="80"/>
                            </svg>
                            <div class="health-score-text" style="position: absolute; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                                <span class="score-num" style="font-family: 'Outfit', sans-serif; font-size: 36px; font-weight: 800; color: #fff;"><!--HEALTH_SCORE-->%</span>
                                <span class="score-label" style="color: <!--SCORE_COLOR-->; font-size: 11px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; margin-top: 4px;"><!--SCORE_RATING--></span>
                            </div>
                        </div>
                    </div>

                    <div class="stat-grid" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; width: 100%;">
                        <div class="stat-card" style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 8px; padding: 14px 16px; display: flex; flex-direction: column; gap: 4px;">
                            <span class="stat-val stat-critical" style="font-family: 'Outfit', sans-serif; font-size: 24px; font-weight: 800; color: var(--color-critical);"><!--CRITICAL_COUNT--></span>
                            <span class="stat-lbl" style="font-size: 11px; color: var(--text-secondary);">Critical Issues</span>
                        </div>
                        <div class="stat-card" style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 8px; padding: 14px 16px; display: flex; flex-direction: column; gap: 4px;">
                            <span class="stat-val stat-warning" style="font-family: 'Outfit', sans-serif; font-size: 24px; font-weight: 800; color: var(--color-warning);"><!--WARNING_COUNT--></span>
                            <span class="stat-lbl" style="font-size: 11px; color: var(--text-secondary);">Warnings</span>
                        </div>
                    </div>
                </div>

                <!-- Right panel: Executive Summary -->
                <div class="dashboard-right">
                    <div class="glass-card summary-card" style="height: 100%;">
                        <h2 class="card-title">Executive Summary</h2>
                        <div class="summary-text">
                            <!--EXEC_SUMMARY-->
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 2: SECURITY FINDINGS -->
        <div id="findings" class="tab-content">
            <div class="glass-card">
                <h2 class="card-title">Security Issues Detected</h2>
                <div style="margin-top:15px;">
                    <!--FINDINGS_HTML-->
                </div>
            </div>
        </div>

        <!-- TAB 3: CONFIG DETAILS -->
        <div id="config" class="tab-content">
            <div class="config-grid">
                <!-- Redirection & HSTS -->
                <div class="glass-card">
                    <h2 class="card-title">Redirection & Protocols</h2>
                    <table class="cert-table">
                        <!--TABLE1_ROWS-->
                    </table>
                </div>
                
                <!-- Security Headers & Cookies -->
                <div class="glass-card">
                    <h2 class="card-title">Security Headers & Disclosures</h2>
                    <table class="cert-table">
                        <!--TABLE2_ROWS-->
                    </table>
                    <div style="margin-top: 20px;">
                        <span style="font-size: 11px; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Active Cookie Analysis</span>
                        <!--COOKIE_LIST_HTML-->
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 4: ROADMAP -->
        <div id="roadmap" class="tab-content">
            <div class="glass-card">
                <h2 class="card-title">Remediation Roadmap</h2>
                <p class="roadmap-item-desc" style="color: var(--text-secondary); margin-bottom: 20px;">
                    Follow these step-by-step recommendations to patch the detected vulnerabilities.
                </p>
                <!--REMED_HTML-->
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            CYBER SAMURAI &bull; DESIGNED FOR PERFORMANCE. BUILT FOR SECURITY. &bull; GENERATED VIA WEBSITE-ASSESSMENT-TOOL
        </div>
    </div>

    <script>
        const heroBg = "<!--HERO_BG_BASE64-->";
        if (heroBg && heroBg.trim().length > 0) {
            document.getElementById('hero-banner').style.backgroundImage = `linear-gradient(rgba(7, 7, 9, 0.85), rgba(7, 7, 9, 0.95)), url('data:image/jpeg;base64,$[heroBg}')`.replace('$[heroBg}', heroBg);
        } else {
            document.getElementById('hero-banner').style.backgroundImage = 'linear-gradient(135deg, #0f0f13 0%, #16161e 100%)';
        }

        function switchTab(evt, tabId) {
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));

            const tabs = document.querySelectorAll('.tab-btn');
            tabs.forEach(tab => tab.classList.remove('active'));

            document.getElementById(tabId).classList.add('active');
            evt.currentTarget.classList.add('active');
        }

        function toggleVulnCard(header) {
            const card = header.closest('.vuln-item-card');
            card.classList.toggle('expanded');
        }
    </script>
</body>
</html>
"""

        # Perform manual replacements on standard string
        html_out = html_template
        html_out = html_out.replace('<!--CSS_CONTENT-->', css_content)
        html_out = html_out.replace('<!--TARGET-->', escape(self.target))
        html_out = html_out.replace('<!--TIMESTAMP-->', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        html_out = html_out.replace('<!--HEALTH_SCORE-->', str(health_score))
        html_out = html_out.replace('<!--SCORE_COLOR-->', score_color)
        html_out = html_out.replace('<!--SCORE_RATING-->', score_rating)
        html_out = html_out.replace('<!--SCORE_OFFSET-->', str(score_offset))
        html_out = html_out.replace('<!--CRITICAL_COUNT-->', str(critical_count))
        html_out = html_out.replace('<!--WARNING_COUNT-->', str(warning_count))
        html_out = html_out.replace('<!--EXEC_SUMMARY-->', exec_summary)
        html_out = html_out.replace('<!--FINDINGS_HTML-->', findings_html if findings_html else '<p style="color:var(--color-pass);">No security issues detected.</p>')
        html_out = html_out.replace('<!--TABLE1_ROWS-->', table1_rows)
        html_out = html_out.replace('<!--TABLE2_ROWS-->', table2_rows)
        html_out = html_out.replace('<!--COOKIE_LIST_HTML-->', cookie_list_html)
        html_out = html_out.replace('<!--REMED_HTML-->', remed_html)
        html_out = html_out.replace('<!--HERO_BG_BASE64-->', hero_bg_base64)
        
        return html_out

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 curlv1.py <domain>")
        print("Example: python3 curlv1.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"\n🔍 Starting assessment for: {target}")
    print("=" * 60)
    
    # Create assessor
    assessor = WebsiteAssessor(target)
    
    # Run tests
    assessor.test_http_redirect()
    assessor.test_https_details()
    assessor.test_hsts()
    assessor.test_http2()
    assessor.test_security_headers()
    assessor.test_cookies()
    assessor.test_exposed_info()
    assessor.test_response_time()
    
    # Perform assessment
    print("\n📊 Performing security assessment...")
    assessor.assess_security()
    
    # Generate reports
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file_md = f"assessment_{target}_{timestamp}.md"
    report_file_html = f"assessment_{target}_{timestamp}.html"
    
    md_report = assessor.generate_markdown()
    html_report = assessor.generate_html()
    
    with open(report_file_md, 'w', encoding='utf-8') as f:
        f.write(md_report)
        
    with open(report_file_html, 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    print(f"\n✅ Assessment complete!")
    print(f"📊 Markdown report saved to: {report_file_md}")
    print(f"🌐 Branded HTML report saved to: {report_file_html}")
    print(f"📈 Risk Level: {assessor.risk_level}")
    print(f"📊 Risk Score: {assessor.risk_score}/100")
    print(f"⚠️  Findings: {len(assessor.findings)}")
    print(f"💡 Recommendations: {len(assessor.recommendations)}")
    
    # Show summary
    print("\n" + "=" * 60)
    print("FINDINGS SUMMARY:")
    for severity, title, _ in assessor.findings[:5]:
        print(f"  [{severity}] {title}")
    if len(assessor.findings) > 5:
        print(f"  ... and {len(assessor.findings) - 5} more")
    
    print(f"\n💡 Key Recommendations:")
    for rec in assessor.recommendations[:3]:
        print(f"  • {rec}")
    if len(assessor.recommendations) > 3:
        print(f"  ... and {len(assessor.recommendations) - 3} more")

if __name__ == '__main__':
    main()