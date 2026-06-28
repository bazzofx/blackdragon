#!/bin/bash

# Check if domain is provided
if [ -z "$1" ]; then
    echo "❌ Error: Domain is required"
    echo "Usage: $0 <target_domain>"
    echo "Example: $0 cybersamurai.co.uk"
    exit 1
fi

target="$1"

# DNS Pre-check - verify domain resolves
echo "🔍 Checking DNS resolution for: $target"
if ! nslookup "$target" > /dev/null 2>&1; then
    echo "❌ Error: Domain failed to resolve DNS record"
    echo "   Please check that '$target' is a valid domain and try again"
    exit 1
fi
echo "✅ DNS resolution successful"

# Create folder with target name + _d
folder="${target}_d"

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

echo "🔍 Starting TLS/SSL scan for: $target"

# Run scan and save reports in the folder
docker run --rm -it -v "$(pwd)/$folder:/out" \
  "$scanner_img" -E -g -U -oA /out/samuraiTLSReport \
  --hints \
  --reqheader "X-Custom-Header: Cyber Samurai Security Scan" \
  --reqheader "User-Agent: CyberSamurai-Security-Assessment" \
  "$target"

# Generate enhanced report in the same folder
python3 generateTLSReport.py -o "$folder/enhancedTLSReport.html" "$folder/rawTLSReport.html"

echo "✅ TLS/SSL Report Generated in: $folder/"
echo "📄 Reports saved in: $(pwd)/$folder/"