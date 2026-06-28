#!/bin/bash
# Wrapper script to execute curlReport.py and export outputs to the target directory

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "❌ Error: Target domain and output directory are required."
    echo "Usage: $0 <target_domain> <output_folder>"
    exit 1
fi

TARGET="$1"
OUT_DIR="$2"

# Resolve directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURL_PY_PATH="$SCRIPT_DIR/../curl/curlReport.py"

if [ ! -f "$CURL_PY_PATH" ]; then
    echo "❌ Error: curlReport.py not found at $CURL_PY_PATH"
    exit 1
fi

echo "🔍 Starting HTTP headers and cookies assessment for $TARGET..."
python3 "$CURL_PY_PATH" "$TARGET" \
    --json-out "$OUT_DIR/curlReport.json" \
    --html-out "$OUT_DIR/curlReport.html" \
    --md-out "$OUT_DIR/curlReport.md"

echo "✅ HTTP assessment finished."
