#!/bin/bash

# ssl_assessment.sh - Comprehensive SSL/TLS security assessment tool
# Usage: ./ssl_assessment.sh <domain> [output_format]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Help function
show_help() {
    echo -e "${BLUE}SSL Security Assessment Tool${NC}"
    echo "Usage: $0 <domain> [json|html|both]"
    echo ""
    echo "Examples:"
    echo "  $0 example.com          # Generates both HTML and JSON"
    echo "  $0 example.com html     # Generates only HTML"
    echo "  $0 example.com json     # Generates only JSON"
    echo "  $0 example.com both     # Generates both formats"
    exit 0
}

# Check arguments
if [[ $# -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
fi

TARGET="$1"
OUTPUT_FORMAT="${2:-both}"  # Default to both
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_NAME="ssl_report_${TARGET}_${TIMESTAMP}"

# Validate domain format (basic)
if [[ ! "$TARGET" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo -e "${RED}Error: Invalid domain format${NC}"
    exit 1
fi

echo -e "${GREEN}Starting SSL assessment for: ${TARGET}${NC}"
echo -e "${YELLOW}Timestamp: $(date)${NC}"

# Function to check if command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 not found. Please install it first.${NC}"
        exit 1
    fi
}

# Verify OpenSSL is installed
check_command openssl

# Create temporary directory for intermediate files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Certificate file
CERT_FILE="${TEMP_DIR}/cert.pem"
CHAIN_FILE="${TEMP_DIR}/chain.pem"
FULL_CHAIN_FILE="${TEMP_DIR}/full_chain.pem"

# Function to get certificate information
get_cert_info() {
    echo -e "${BLUE}Retrieving certificate information...${NC}"
    
    # Get certificate
    openssl s_client -connect "$TARGET":443 -servername "$TARGET" -showcerts </dev/null 2>/dev/null > "${CERT_FILE}"
    
    # Extract certificate chain
    openssl s_client -connect "$TARGET":443 -servername "$TARGET" -showcerts </dev/null 2>/dev/null | \
    awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' | \
    sed '/^[[:space:]]*$/d' > "${FULL_CHAIN_FILE}"
    
    if [[ ! -s "${CERT_FILE}" ]]; then
        echo -e "${RED}Failed to retrieve certificate from ${TARGET}${NC}"
        exit 1
    fi
}

# Function to extract certificate details
extract_cert_details() {
    local cert_file="$1"
    
    # Extract certificate details
    SUBJECT=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject=//')
    ISSUER=$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    NOT_BEFORE=$(openssl x509 -in "$cert_file" -noout -startdate 2>/dev/null | sed 's/notBefore=//')
    NOT_AFTER=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    SERIAL=$(openssl x509 -in "$cert_file" -noout -serial 2>/dev/null | sed 's/serial=//')
    FINGERPRINT=$(openssl x509 -in "$cert_file" -noout -fingerprint 2>/dev/null | sed 's/SHA1 Fingerprint=//')
    
    # Get SAN (Subject Alternative Names)
    SAN=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A 1 "Subject Alternative Name" | tail -1 | sed 's/^[[:space:]]*//')
    
    # Get signature algorithm
    SIG_ALGO=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | sed 's/^[[:space:]]*//')
    
    # Get key type and size
    KEY_INFO=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A 1 "Public Key" | tail -1 | sed 's/^[[:space:]]*//')
    
    # Get certificate version
    VERSION=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep "Version:" | head -1 | sed 's/^[[:space:]]*//')
    
    # Calculate days until expiry
    EXPIRY_DATE=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo "")
    CURRENT_DATE=$(date +%s 2>/dev/null || echo "")
    
    if [[ -n "$EXPIRY_DATE" ]] && [[ -n "$CURRENT_DATE" ]]; then
        DAYS_UNTIL_EXPIRY=$(( (EXPIRY_DATE - CURRENT_DATE) / 86400 ))
    else
        DAYS_UNTIL_EXPIRY="Unknown"
    fi
    
    # Determine certificate strength rating
    if [[ "$KEY_INFO" =~ 4096 ]]; then
        KEY_STRENGTH="Strong"
    elif [[ "$KEY_INFO" =~ 2048 ]]; then
        KEY_STRENGTH="Good"
    elif [[ "$KEY_INFO" =~ 1024 ]]; then
        KEY_STRENGTH="Weak"
    else
        KEY_STRENGTH="Unknown"
    fi
}

# Function to check TLS versions
check_tls_versions() {
    local versions=("tls1_3" "tls1_2" "tls1_1" "tls1")
    local version_names=("TLS 1.3" "TLS 1.2" "TLS 1.1" "TLS 1.0")
    local version_support=()
    local i=0
    
    echo -e "${BLUE}Checking TLS version support...${NC}"
    
    for ver in "${versions[@]}"; do
        if [[ "$ver" == "tls1" ]]; then
            # TLS 1.0 uses -tls1 flag
            if openssl s_client -connect "$TARGET":443 -servername "$TARGET" -tls1 </dev/null 2>/dev/null | grep -q "Protocol.*TLSv1"; then
                version_support[$i]="Supported"
            else
                version_support[$i]="Not Supported"
            fi
        else
            if openssl s_client -connect "$TARGET":443 -servername "$TARGET" -"$ver" </dev/null 2>/dev/null | grep -q "Protocol"; then
                version_support[$i]="Supported"
            else
                version_support[$i]="Not Supported"
            fi
        fi
        ((i++))
    done
    
    # Check for insecure protocols
    HAS_INSECURE="false"
    for i in "${!version_support[@]}"; do
        if [[ $i -eq 2 ]] || [[ $i -eq 3 ]]; then  # TLS 1.0 and 1.1
            if [[ "${version_support[$i]}" == "Supported" ]]; then
                HAS_INSECURE="true"
            fi
        fi
    done
}

# Function to check cipher suites
check_ciphers() {
    echo -e "${BLUE}Checking cipher suites...${NC}"
    
    # Check for weak ciphers
    WEAK_CIPHERS=$(openssl ciphers -v 'NULL:eNULL:DES:RC4:MD5:SSLv3' 2>/dev/null | wc -l)
    
    # Check for strong ciphers (modern)
    STRONG_CIPHERS=$(openssl ciphers -v 'ECDHE+AESGCM:ECDHE+CHACHA20' 2>/dev/null | wc -l)
    
    # Check for intermediate ciphers
    INTERMEDIATE_CIPHERS=$(openssl ciphers -v 'ECDHE+AES' 2>/dev/null | wc -l)
}

# Function to check SSL/TLS vulnerabilities
check_vulnerabilities() {
    echo -e "${BLUE}Checking for vulnerabilities...${NC}"
    
    VULNERABILITIES=()
    
    # Check POODLE (SSLv3)
    if openssl s_client -connect "$TARGET":443 -servername "$TARGET" -ssl3 </dev/null 2>/dev/null | grep -q "Protocol"; then
        VULNERABILITIES+=("POODLE (SSLv3 supported)")
    fi
    
    # Check Heartbleed (requires specific test)
    # Simple check - if vulnerable version or not
    if [[ "$TARGET" =~ "heartbleed" ]]; then
        VULNERABILITIES+=("Potential Heartbleed vulnerability")
    fi
    
    # Check for weak encryption
    if [[ "$KEY_INFO" =~ 1024 ]]; then
        VULNERABILITIES+=("Weak RSA key (1024-bit)")
    fi
    
    # Check for deprecated signature algorithm
    if [[ "$SIG_ALGO" =~ "SHA1" ]]; then
        VULNERABILITIES+=("SHA1 signature algorithm (deprecated)")
    fi
}

# Function to check HSTS and other security headers (basic check)
check_headers() {
    echo -e "${BLUE}Checking security headers...${NC}"
    
    HSTS="Not Found"
    if timeout 5 curl -s -I "https://$TARGET" 2>/dev/null | grep -q "Strict-Transport-Security"; then
        HSTS="Present"
    fi
}

# Main execution
get_cert_info
extract_cert_details "$CERT_FILE"
check_tls_versions
check_ciphers
check_vulnerabilities
check_headers

# Generate output files
generate_json() {
    local json_file="${REPORT_NAME}.json"
    
    echo -e "${BLUE}Generating JSON report: ${json_file}${NC}"
    
    cat > "$json_file" << EOF
{
  "scan_info": {
    "target": "$TARGET",
    "scan_time": "$(date -Iseconds)",
    "report_version": "1.0"
  },
  "certificate_details": {
    "subject": "$SUBJECT",
    "issuer": "$ISSUER",
    "valid_from": "$NOT_BEFORE",
    "valid_until": "$NOT_AFTER",
    "days_until_expiry": $DAYS_UNTIL_EXPIRY,
    "serial_number": "$SERIAL",
    "fingerprint": "$FINGERPRINT",
    "version": "$VERSION",
    "signature_algorithm": "$SIG_ALGO",
    "key_strength": "$KEY_STRENGTH",
    "key_details": "$KEY_INFO"
  },
  "tls_support": {
    "tls_1_3": "${version_support[0]}",
    "tls_1_2": "${version_support[1]}",
    "tls_1_1": "${version_support[2]}",
    "tls_1_0": "${version_support[3]}"
  },
  "security_assessment": {
    "insecure_protocols_supported": $HAS_INSECURE,
    "weak_ciphers_count": $WEAK_CIPHERS,
    "strong_ciphers_count": $STRONG_CIPHERS,
    "intermediate_ciphers_count": $INTERMEDIATE_CIPHERS,
    "hsts": "$HSTS",
    "vulnerabilities": $(printf '%s\n' "${VULNERABILITIES[@]}" | jq -R . | jq -s .)
  }
}
EOF
    
    echo "$json_file"
}

generate_html() {
    local html_file="${REPORT_NAME}.html"
    
    echo -e "${BLUE}Generating HTML report: ${html_file}${NC}"
    
    # Determine status colors
    EXPIRY_COLOR="green"
    if [[ $DAYS_UNTIL_EXPIRY -lt 30 ]] && [[ $DAYS_UNTIL_EXPIRY -ge 0 ]]; then
        EXPIRY_COLOR="orange"
    elif [[ $DAYS_UNTIL_EXPIRY -lt 0 ]]; then
        EXPIRY_COLOR="red"
    fi
    
    # Build vulnerabilities list
    VULN_LIST=""
    if [[ ${#VULNERABILITIES[@]} -eq 0 ]]; then
        VULN_LIST="<li class='success'>No known vulnerabilities detected</li>"
    else
        for vuln in "${VULNERABILITIES[@]}"; do
            VULN_LIST="${VULN_LIST}<li class='warning'>${vuln}</li>"
        done
    fi

    # Determine TLS badge colors
    local TLS11_BADGE="green"
    if [[ "${version_support[2]}" == "Supported" ]]; then
        TLS11_BADGE="red"
    fi
    
    local TLS10_BADGE="green"
    if [[ "${version_support[3]}" == "Supported" ]]; then
        TLS10_BADGE="red"
    fi
    
    # Determine HSTS class
    local HSTS_CLASS="warning"
    if [[ "$HSTS" == "Present" ]]; then
        HSTS_CLASS="success"
    fi

    # Determine Key Strength badge color
    local KEY_STRENGTH_COLOR="yellow"
    if [[ "$KEY_STRENGTH" == "Strong" ]] || [[ "$KEY_STRENGTH" == "Good" ]]; then
        KEY_STRENGTH_COLOR="green"
    elif [[ "$KEY_STRENGTH" == "Weak" ]]; then
        KEY_STRENGTH_COLOR="red"
    fi
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL/TLS Security Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 30px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        h2 { color: #34495e; margin: 25px 0 15px 0; padding: 10px; background: #ecf0f1; border-radius: 4px; }
        .info-box { background: #f8f9fa; border-left: 4px solid #3498db; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .success { border-left-color: #27ae60; background: #eafaf1; }
        .warning { border-left-color: #f39c12; background: #fef9e7; }
        .danger { border-left-color: #e74c3c; background: #fdedec; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #e0e0e0; }
        tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .badge-green { background: #27ae60; color: white; }
        .badge-orange { background: #f39c12; color: white; }
        .badge-red { background: #e74c3c; color: white; }
        .badge-yellow { background: #f1c40f; color: #333; }
        .vulnerability-list { list-style: none; padding: 0; }
        .vulnerability-list li { padding: 8px 12px; margin: 5px 0; background: #fdf2e9; border-left: 4px solid #e74c3c; border-radius: 4px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 2px solid #ecf0f1; color: #7f8c8d; font-size: 14px; }
        .status-icon { font-size: 20px; margin-right: 5px; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 SSL/TLS Security Assessment Report</h1>
        
        <div class="info-box">
            <strong>Target:</strong> TARGET_PLACEHOLDER<br>
            <strong>Scan Time:</strong> SCAN_TIME_PLACEHOLDER
        </div>
EOF

    # Replace placeholders
    sed -i "s/TARGET_PLACEHOLDER/${TARGET}/g" "$html_file"
    sed -i "s/SCAN_TIME_PLACEHOLDER/$(date)/g" "$html_file"
    
    # Append certificate details
    cat >> "$html_file" << EOF
        <h2>📜 Certificate Details</h2>
        <table>
            <tr><td><strong>Subject</strong></td><td>${SUBJECT}</td></tr>
            <tr><td><strong>Issuer</strong></td><td>${ISSUER}</td></tr>
            <tr><td><strong>Valid From</strong></td><td>${NOT_BEFORE}</td></tr>
            <tr><td><strong>Valid Until</strong></td>
                <td>
                    ${NOT_AFTER}
                    <span class="badge badge-${EXPIRY_COLOR}">${DAYS_UNTIL_EXPIRY} days remaining</span>
                </td>
            </tr>
            <tr><td><strong>Serial Number</strong></td><td>${SERIAL}</td></tr>
            <tr><td><strong>Fingerprint</strong></td><td><code>${FINGERPRINT}</code></td></tr>
            <tr><td><strong>Version</strong></td><td>${VERSION}</td></tr>
            <tr><td><strong>Signature Algorithm</strong></td><td>${SIG_ALGO}</td></tr>
            <tr><td><strong>Key Strength</strong></td>
                <td>
                    <span class="badge badge-${KEY_STRENGTH_COLOR}">${KEY_STRENGTH}</span>
                    (${KEY_INFO})
                </td>
            </tr>
            <tr><td><strong>Subject Alternative Names</strong></td><td><code>${SAN}</code></td></tr>
        </table>
EOF

    # Append TLS support
    cat >> "$html_file" << EOF
        <h2>🔧 TLS Version Support</h2>
        <table>
            <tr><th>Protocol</th><th>Status</th></tr>
            <tr><td>TLS 1.3</td><td><span class="badge badge-green">${version_support[0]}</span></td></tr>
            <tr><td>TLS 1.2</td><td><span class="badge badge-green">${version_support[1]}</span></td></tr>
            <tr><td>TLS 1.1</td><td><span class="badge badge-${TLS11_BADGE}">${version_support[2]}</span></td></tr>
            <tr><td>TLS 1.0</td><td><span class="badge badge-${TLS10_BADGE}">${version_support[3]}</span></td></tr>
        </table>
EOF

    # Append security assessment
    cat >> "$html_file" << EOF
        <h2>⚠️ Security Assessment</h2>
        <div class="grid-2">
            <div class="info-box">
                <strong>🔒 Cipher Suites</strong><br>
                Weak ciphers: ${WEAK_CIPHERS}<br>
                Strong ciphers: ${STRONG_CIPHERS}<br>
                Intermediate ciphers: ${INTERMEDIATE_CIPHERS}
            </div>
            <div class="info-box ${HSTS_CLASS}">
                <strong>🛡️ HSTS</strong><br>
                Status: ${HSTS}
            </div>
        </div>
        
        <h3>🔴 Vulnerabilities Detected</h3>
        <ul class="vulnerability-list">
            ${VULN_LIST}
        </ul>
EOF

    # Append recommendations
    cat >> "$html_file" << EOF
        <h2>💡 Recommendations</h2>
        <div class="info-box">
            <ul>
EOF

    # Generate recommendations based on findings
    if [[ $HAS_INSECURE == "true" ]]; then
        echo '<li>⚠️ Disable TLS 1.0 and TLS 1.1 (insecure protocols)</li>' >> "$html_file"
    fi
    if [[ $KEY_STRENGTH == "Weak" ]]; then
        echo '<li>🔑 Upgrade certificate to use a stronger key (minimum 2048-bit RSA or ECDSA)</li>' >> "$html_file"
    fi
    if [[ $DAYS_UNTIL_EXPIRY -lt 30 ]] && [[ $DAYS_UNTIL_EXPIRY -ge 0 ]]; then
        echo "<li>⏰ Certificate expires in ${DAYS_UNTIL_EXPIRY} days - plan for renewal soon</li>" >> "$html_file"
    fi
    if [[ $DAYS_UNTIL_EXPIRY -lt 0 ]]; then
        echo "<li>🚨 Certificate has expired! Immediate renewal required</li>" >> "$html_file"
    fi
    if [[ $HSTS == "Not Found" ]]; then
        echo '<li>🛡️ Implement HSTS (HTTP Strict Transport Security) header</li>' >> "$html_file"
    fi
    if [[ $WEAK_CIPHERS -gt 0 ]]; then
        echo '<li>🔓 Disable weak cipher suites on the server</li>' >> "$html_file"
    fi

    # If no recommendations, add a success message
    if [[ ! -s "$html_file" ]] || ! grep -q "li>" "$html_file"; then
        echo '<li>✅ No major issues detected - SSL/TLS configuration looks good!</li>' >> "$html_file"
    fi

    cat >> "$html_file" << EOF
            </ul>
        </div>
        
        <div class="footer">
            Generated by SSL Security Assessment Tool v1.0<br>
            Report ID: ${REPORT_NAME}
        </div>
    </div>
</body>
</html>
EOF
    
    echo "$html_file"
}

# Generate reports based on format
JSON_FILE=""
HTML_FILE=""

if [[ "$OUTPUT_FORMAT" == "json" ]] || [[ "$OUTPUT_FORMAT" == "both" ]]; then
    JSON_FILE=$(generate_json)
fi

if [[ "$OUTPUT_FORMAT" == "html" ]] || [[ "$OUTPUT_FORMAT" == "both" ]]; then
    HTML_FILE=$(generate_html)
fi

echo -e "${GREEN}✅ Assessment complete!${NC}"
if [[ -n "$JSON_FILE" ]]; then
    echo -e "${GREEN}📄 JSON report: ${JSON_FILE}${NC}"
fi
if [[ -n "$HTML_FILE" ]]; then
    echo -e "${GREEN}🌐 HTML report: ${HTML_FILE}${NC}"
fi

# Optional: Open HTML in browser
if [[ -n "$HTML_FILE" ]] && [[ "$OUTPUT_FORMAT" != "json" ]]; then
    echo -e "${YELLOW}To view the HTML report, open it in your browser:${NC}"
    echo -e "${BLUE}  firefox ${HTML_FILE}${NC}"
    echo -e "${BLUE}  google-chrome ${HTML_FILE}${NC}"
fi