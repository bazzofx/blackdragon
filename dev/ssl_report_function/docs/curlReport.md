# curlReport.sh - HTTP Headers & Cookie Security Assessment

Quick wrapper script that audits a target domain's HTTP security posture — redirects, headers, cookies, and response time — and exports the results in three formats.

## Usage

```bash
./curlReport.sh <target_domain> <output_directory>
```

### Example

```bash
./curlReport.sh cybersamurai.co.uk ./cybersamurai.co.uk_d
```

This runs the full 8-step assessment against `cybersamurai.co.uk` and writes the following files into `./cybersamurai.co.uk_d/`:

| File               | Format | Description                      |
|--------------------|--------|----------------------------------|
| `curlReport.json`  | JSON   | Machine-readable raw results     |
| `curlReport.html`  | HTML   | Branded client-facing dashboard  |
| `curlReport.md`    | Markdown | Plain-text summary report     |

## What It Checks

1. **HTTP → HTTPS Redirect** — does port 80 redirect to 443?
2. **HTTPS Connection Details** — TLS version, cipher suite, certificate info
3. **HSTS Header** — max-age, includeSubDomains, preload status
4. **HTTP/2 Support** — protocol negotiation
5. **Security Headers** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and more
6. **Cookie Security** — Secure, HttpOnly, SameSite flags on every Set-Cookie
7. **Exposed Information** — directory listing, server banner, X-Powered-By
8. **Response Time** — latency in seconds and milliseconds

## Requirements

- **Python 3** — the script calls `python3` to run `curlReport.py`
- **curl** — standard on Linux/macOS; available via Git Bash on Windows

## Troubleshooting

| Problem                              | Fix                                            |
|--------------------------------------|------------------------------------------------|
| `curlReport.py not found`            | Make sure the script is run from `ssl_report_function/` |
| `python3: command not found`         | Use `python` instead, or install Python 3       |
| `curl: command not found`            | Install curl (`apt install curl` / `brew install curl`) |