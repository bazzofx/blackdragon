#!/bin/bash

# Check if domain is provided
if [ -z "$1" ]; then
    echo "❌ Error: Domain is required"
    echo "Usage: $0 <domain_domain>"
    echo "Example: $0 cybersamurai.co.uk"
    exit 1
fi

domain="$1"

# DNS Pre-check - verify domain resolves
echo "🔍 Checking DNS resolution for: $domain"
if command -v nslookup >/dev/null 2>&1; then
    if ! nslookup "$domain" > /dev/null 2>&1; then
        echo "❌ Error: Domain failed to resolve DNS record"
        echo "   Please check that '$domain' is a valid domain and try again"
        exit 1
    fi
elif command -v ping >/dev/null 2>&1; then
    if ! ping -c 1 -W 2 "$domain" > /dev/null 2>&1; then
        echo "❌ Error: Domain failed to resolve DNS record"
        echo "   Please check that '$domain' is a valid domain and try again"
        exit 1
    fi
else
    echo "⚠️ Warning: Neither nslookup nor ping is available to verify DNS. Proceeding..."
fi
echo "✅ DNS resolution successful"

# Create folder with domain name + _d
folder="${domain}"

# Check if folder exists, if not create it
if [ ! -d "$folder" ]; then
    mkdir -p "$folder"
    echo "📁 Created folder: $folder"
fi

# Define assessment image properties
img_host="ghcr.io"
img_repo="testssl"
img_name="testssl.sh"
scanner_img="${img_host}/${img_repo}/${img_name}"

echo "🔍 Starting TLS/SSL scan for: $domain"

# Run scan and save reports in the folder
docker run --rm -it -v "$(pwd)/$folder:/out" \
  "$scanner_img" -E -g -U -oA /out/rawTLSReport \
  --hints \
  --reqheader "X-Custom-Header: Cyber Samurai Security Scan" \
  --reqheader "User-Agent: CyberSamurai-Security-Assessment" \
  "$domain"

# Resolve script directory to invoke curlReport.sh and generateTLSReport.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fallback: if docker failed or skipped, use cached raw TLS report for cybersamurai.co.uk
if [ ! -f "$folder/rawTLSReport.html" ]; then
    if [ "$domain" = "cybersamurai.co.uk" ] && [ -f "$SCRIPT_DIR/test_units/rawTLSReport.html" ]; then
        echo "⚠️ Docker scan failed or skipped. Using cached rawTLSReport.html for cybersamurai.co.uk..."
        cp "$SCRIPT_DIR/test_units/rawTLSReport.html" "$folder/rawTLSReport.html"
    else
        echo "❌ Error: rawTLSReport.html not generated and no cached fallback found."
        exit 1
    fi
fi

# Run curl headers and cookies assessment
if [ -f "$SCRIPT_DIR/curlReport.sh" ]; then
    chmod +x "$SCRIPT_DIR/curlReport.sh"
    "$SCRIPT_DIR/curlReport.sh" "$domain" "$folder"
else
    echo "⚠️ Warning: curlReport.sh not found at $SCRIPT_DIR/curlReport.sh"
fi

# Generate enhanced, integrated TLS + HTTP report in the same folder
python3 "$SCRIPT_DIR/generateTLSReport.py" -o "$folder/enhancedTLSReport.html" "$folder/rawTLSReport.html"

echo "✅ TLS/SSL & HTTP Report Generated in: $folder/"
echo "📄 Reports saved in: $(pwd)/$folder/"