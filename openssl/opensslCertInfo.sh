#!/bin/bash

# opensslCertInfo.sh - Focused SSL/TLS certificate, chain, OCSP, compression and signature analysis tool
# Usage: ./opensslCertInfo.sh <domain> [output_format]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Help function
show_help() {
    echo -e "${BLUE}SSL Certificate & Chain Analysis Tool${NC}"
    echo "Usage: $0 <domain> [text|json|html|both]"
    echo ""
    echo "Examples:"
    echo "  $0 example.com          # Prints text output only"
    echo "  $0 example.com html     # Generates HTML report"
    echo "  $0 example.com json     # Generates JSON report"
    echo "  $0 example.com both     # Generates both HTML and JSON, prints text"
    exit 0
}

# Check arguments
if [[ $# -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
fi

TARGET="$1"
OUTPUT_FORMAT="${2:-text}"  # Default to text
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_NAME="cert_info_${TARGET}_${TIMESTAMP}"

# Validate domain format (basic)
if [[ ! "$TARGET" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo -e "${RED}Error: Invalid domain format${NC}"
    exit 1
fi

# Function to check if command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 not found. Please install it first.${NC}"
        exit 1
    fi
}

# Verify OpenSSL and curl are installed
check_command openssl
check_command curl

# Create temporary directory for intermediate files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

S_CLIENT_OUTPUT="${TEMP_DIR}/s_client_raw.txt"
LEAF_CERT="${TEMP_DIR}/leaf_cert.pem"
CHAIN_CERTS="${TEMP_DIR}/chain_certs.pem"

# Function to connect and retrieve TLS data
retrieve_tls_data() {
    echo -e "${BLUE}Connecting to ${TARGET}:443 to retrieve certificates and handshake details...${NC}"
    
    # Capture s_client status connection (status check for OCSP stapling)
    openssl s_client -connect "$TARGET":443 -servername "$TARGET" -status -showcerts </dev/null 2>/dev/null > "${S_CLIENT_OUTPUT}" || true
    
    if [[ ! -s "${S_CLIENT_OUTPUT}" ]]; then
        echo -e "${RED}Failed to connect to ${TARGET} or retrieve certificates.${NC}"
        exit 1
    fi
    
    # Extract leaf certificate
    awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/ {print; if ($0 == "-----END CERTIFICATE-----") exit}' "${S_CLIENT_OUTPUT}" > "${LEAF_CERT}"
    
    # Extract all certificates sent by the server for the chain check
    awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "${S_CLIENT_OUTPUT}" > "${CHAIN_CERTS}"
    
    if [[ ! -s "${LEAF_CERT}" ]]; then
        echo -e "${RED}No certificate found in the server response.${NC}"
        exit 1
    fi
}

extract_details() {
    # Extract leaf details
    SUBJECT=$(openssl x509 -in "${LEAF_CERT}" -noout -subject 2>/dev/null | sed 's/subject=//')
    ISSUER=$(openssl x509 -in "${LEAF_CERT}" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    NOT_BEFORE=$(openssl x509 -in "${LEAF_CERT}" -noout -startdate 2>/dev/null | sed 's/notBefore=//')
    NOT_AFTER=$(openssl x509 -in "${LEAF_CERT}" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    SERIAL=$(openssl x509 -in "${LEAF_CERT}" -noout -serial 2>/dev/null | sed 's/serial=//')
    FINGERPRINT=$(openssl x509 -in "${LEAF_CERT}" -noout -fingerprint 2>/dev/null | sed 's/SHA1 Fingerprint=//')
    
    # Get SAN
    SAN=$(openssl x509 -in "${LEAF_CERT}" -noout -text 2>/dev/null | grep -A 1 "Subject Alternative Name" | tail -1 | sed 's/^[[:space:]]*//' || echo "N/A")
    
    # Get certificate signature algorithm
    SIG_ALGO=$(openssl x509 -in "${LEAF_CERT}" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | sed 's/^[[:space:]]*//')
    
    # Get key type and size
    KEY_INFO=$(openssl x509 -in "${LEAF_CERT}" -noout -text 2>/dev/null | grep -A 1 "Public Key" | tail -1 | sed 's/^[[:space:]]*//')
    
    # Days until expiry
    EXPIRY_DATE=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo "")
    CURRENT_DATE=$(date +%s 2>/dev/null || echo "")
    if [[ -n "$EXPIRY_DATE" ]] && [[ -n "$CURRENT_DATE" ]]; then
        DAYS_UNTIL_EXPIRY=$(( (EXPIRY_DATE - CURRENT_DATE) / 86400 ))
    else
        DAYS_UNTIL_EXPIRY="Unknown"
    fi
}

check_chain_completeness() {
    # Split the chain certs into individual files
    local cert_count=0
    local current_cert_file=""
    
    # Read the chain file line by line and split
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            current_cert_file="${TEMP_DIR}/chain_cert_${cert_count}.pem"
            echo "$line" > "$current_cert_file"
        elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
            echo "$line" >> "$current_cert_file"
            cert_count=$((cert_count + 1))
        elif [[ -n "$current_cert_file" ]]; then
            echo "$line" >> "$current_cert_file"
        fi
    done < "${CHAIN_CERTS}"
    
    CHAIN_COUNT=$cert_count
    
    if [[ $cert_count -eq 0 ]]; then
        CHAIN_STATUS="Empty / No Certificates Sent"
        CHAIN_DETAILS="The server did not send any certificates."
        return 1
    fi
    
    # If only 1 cert is sent, check if it is self-signed
    if [[ $cert_count -eq 1 ]]; then
        local leaf_subj=$(openssl x509 -in "${TEMP_DIR}/chain_cert_0.pem" -noout -subject_hash 2>/dev/null)
        local leaf_iss=$(openssl x509 -in "${TEMP_DIR}/chain_cert_0.pem" -noout -issuer_hash 2>/dev/null)
        if [[ "$leaf_subj" == "$leaf_iss" ]]; then
            CHAIN_STATUS="Self-Signed Root Certificate Only"
            CHAIN_DETAILS="Only a self-signed root certificate was sent."
        else
            CHAIN_STATUS="Incomplete (Only Leaf Certificate Sent)"
            CHAIN_DETAILS="Only the leaf certificate was sent, missing intermediate certificates."
        fi
        return 0
    fi
    
    # Check intermediate links
    local broken_link="false"
    for ((i=0; i<cert_count-1; i++)); do
        local issuer_hash=$(openssl x509 -in "${TEMP_DIR}/chain_cert_${i}.pem" -noout -issuer_hash 2>/dev/null)
        local next_subject_hash=$(openssl x509 -in "${TEMP_DIR}/chain_cert_$((i+1)).pem" -noout -subject_hash 2>/dev/null)
        if [[ "$issuer_hash" != "$next_subject_hash" ]]; then
            broken_link="true"
            break
        fi
    done
    
    # Verify using openssl verify command against system store if available
    local verify_err=""
    local verify_ok="false"
    
    # Try different standard system CA paths
    local ca_paths=("/etc/ssl/certs" "/etc/pki/tls/certs" "/etc/pki/CA" "/system/etc/security/cacerts")
    local ca_path_arg=""
    for path in "${ca_paths[@]}"; do
        if [[ -d "$path" ]]; then
            ca_path_arg="-CApath $path"
            break
        fi
    done
    
    # Try verifying leaf against chain
    # Combine cert_1.pem to cert_N.pem into intermediate chain file
    local int_chain="${TEMP_DIR}/intermediates.pem"
    > "$int_chain"
    for ((i=1; i<cert_count; i++)); do
        cat "${TEMP_DIR}/chain_cert_${i}.pem" >> "$int_chain"
    done
    
    # Run verification
    if verify_output=$(openssl verify $ca_path_arg -untrusted "$int_chain" "${TEMP_DIR}/chain_cert_0.pem" 2>&1); then
        verify_ok="true"
    else
        verify_err=$(echo "$verify_output" | sed "s|${TEMP_DIR}/||g")
    fi
    
    if [[ "$broken_link" == "true" ]]; then
        CHAIN_STATUS="Broken / Out of Order"
        CHAIN_DETAILS="The issuer of a certificate in the chain does not match the subject of the next certificate."
    elif [[ "$verify_ok" == "true" ]]; then
        CHAIN_STATUS="Complete and Trusted"
        CHAIN_DETAILS="All intermediate certificates are present and verify successfully against the local trust store."
    else
        # If verify failed, check if it's unable to get issuer cert (untrusted root or missing intermediate)
        if [[ "$verify_err" =~ "unable to get local issuer certificate" ]]; then
            # Check if the last certificate in intermediates is self-signed
            local last_idx=$((cert_count - 1))
            local last_subj=$(openssl x509 -in "${TEMP_DIR}/chain_cert_${last_idx}.pem" -noout -subject_hash 2>/dev/null)
            local last_iss=$(openssl x509 -in "${TEMP_DIR}/chain_cert_${last_idx}.pem" -noout -issuer_hash 2>/dev/null)
            if [[ "$last_subj" == "$last_iss" ]]; then
                CHAIN_STATUS="Complete but Untrusted Root"
                CHAIN_DETAILS="The certificate chain is complete up to a root certificate, but the root is not trusted by the local store."
            else
                CHAIN_STATUS="Incomplete (Missing Intermediate or Root Certificate)"
                CHAIN_DETAILS="The local store could not verify the issuer. This usually means intermediate certificates are missing from the chain."
            fi
        else
            CHAIN_STATUS="Verification Failed"
            CHAIN_DETAILS="Certificate validation failed: ${verify_err}"
        fi
    fi
}

check_ocsp() {
    # Check OCSP Stapling (TLS Handshake response)
    if grep -q -i "OCSP Response Status:" "${S_CLIENT_OUTPUT}"; then
        OCSP_STAPLING_SUPPORTED="Yes (Stapled)"
        OCSP_STAPLING_STATUS=$(grep -i "OCSP Response Status:" "${S_CLIENT_OUTPUT}" | head -1 | sed 's/^[[:space:]]*//' | awk -F': ' '{print $2}')
        OCSP_STAPLED_CERT_STATUS=$(grep -i "Cert Status:" "${S_CLIENT_OUTPUT}" | head -1 | sed 's/^[[:space:]]*//' | awk -F': ' '{print $2}')
    else
        OCSP_STAPLING_SUPPORTED="No"
        OCSP_STAPLING_STATUS="N/A (No response sent by server)"
        OCSP_STAPLED_CERT_STATUS="N/A"
    fi
    
    # Manual OCSP query check
    OCSP_URI=$(openssl x509 -in "${LEAF_CERT}" -noout -ocsp_uri 2>/dev/null || echo "")
    
    if [[ -n "$OCSP_URI" ]] && [[ -f "${TEMP_DIR}/chain_cert_1.pem" ]]; then
        OCSP_MANUAL_OUTPUT="${TEMP_DIR}/ocsp_manual.txt"
        # Run manual check
        if openssl ocsp -issuer "${TEMP_DIR}/chain_cert_1.pem" -cert "${LEAF_CERT}" -url "${OCSP_URI}" -resp_text -no_nonce > "${OCSP_MANUAL_OUTPUT}" 2>&1; then
            OCSP_MANUAL_SUPPORTED="Yes"
            # Extract response status and certificate status
            OCSP_MANUAL_STATUS=$(grep -i "Response Status" "${OCSP_MANUAL_OUTPUT}" | head -1 | sed 's/^[[:space:]]*//' | awk -F': ' '{print $2}' || echo "Unknown")
            OCSP_MANUAL_CERT_STATUS=$(grep -i -A 5 "Response Data:" "${OCSP_MANUAL_OUTPUT}" | grep -i "${LEAF_CERT}" | awk -F': ' '{print $2}' | sed 's/^[[:space:]]*//' || echo "Unknown")
            if [[ -z "$OCSP_MANUAL_CERT_STATUS" ]]; then
                # Fallback parse
                OCSP_MANUAL_CERT_STATUS=$(grep -i "cert.pem:" "${OCSP_MANUAL_OUTPUT}" | awk -F': ' '{print $2}' || echo "Unknown")
            fi
        else
            OCSP_MANUAL_SUPPORTED="Failed to query responder"
            OCSP_MANUAL_STATUS="Query failed"
            OCSP_MANUAL_CERT_STATUS="Unknown"
        fi
    else
        OCSP_MANUAL_SUPPORTED="No"
        OCSP_MANUAL_STATUS="N/A (Missing OCSP responder URI or intermediate cert)"
        OCSP_MANUAL_CERT_STATUS="N/A"
    fi
}

check_compression_and_signature_algs() {
    # Extract TLS Compression
    COMPRESSION=$(grep -i "^Compression:" "${S_CLIENT_OUTPUT}" | head -1 | sed 's/^[[:space:]]*//' | awk -F': ' '{print $2}' || echo "Unknown")
    if [[ -z "$COMPRESSION" ]]; then
        COMPRESSION="None / Disabled (Secure)"
    fi
    
    # Extract Handshake Signature Algorithms (Peer info)
    PEER_SIGN_DIGEST=$(grep -i "Peer signing digest:" "${S_CLIENT_OUTPUT}" | awk -F': ' '{print $2}' || echo "N/A (TLS 1.2+ only)")
    PEER_SIGN_TYPE=$(grep -i "Peer signature type:" "${S_CLIENT_OUTPUT}" | awk -F': ' '{print $2}' || echo "N/A (TLS 1.2+ only)")
    SERVER_TEMP_KEY=$(grep -i "Server Temp Key:" "${S_CLIENT_OUTPUT}" | awk -F': ' '{print $2}' || echo "N/A")
}

generate_text_report() {
    echo -e "\n${CYAN}======================================================================${NC}"
    echo -e "${MAGENTA}   SSL/TLS Certificate, Chain, OCSP & Protocol Details for ${NC}${GREEN}${TARGET}${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    
    echo -e "\n${BLUE}[📜 Certificate Leaf Details]${NC}"
    echo -e "  Subject:             ${YELLOW}${SUBJECT}${NC}"
    echo -e "  Issuer:              ${YELLOW}${ISSUER}${NC}"
    echo -e "  Serial Number:       ${YELLOW}${SERIAL}${NC}"
    echo -e "  Validity:            Not Before: ${YELLOW}${NOT_BEFORE}${NC}"
    echo -e "                       Not After:  ${YELLOW}${NOT_AFTER}${NC} (${GREEN}${DAYS_UNTIL_EXPIRY} days remaining${NC})"
    echo -e "  Key Details:         ${YELLOW}${KEY_INFO}${NC}"
    echo -e "  Cert Sig Algo:       ${YELLOW}${SIG_ALGO}${NC}"
    echo -e "  SAN:                 ${YELLOW}${SAN}${NC}"
    
    echo -e "\n${BLUE}[🔗 Certificate Chain Verification]${NC}"
    echo -e "  Certs Sent by Server: ${YELLOW}${CHAIN_COUNT}${NC}"
    local status_color="${GREEN}"
    if [[ "$CHAIN_STATUS" =~ "Incomplete" ]] || [[ "$CHAIN_STATUS" =~ "Broken" ]]; then
        status_color="${RED}"
    elif [[ "$CHAIN_STATUS" =~ "Untrusted" ]]; then
        status_color="${YELLOW}"
    fi
    echo -e "  Chain Status:        ${status_color}${CHAIN_STATUS}${NC}"
    echo -e "  Chain Details:       ${status_color}${CHAIN_DETAILS}${NC}"
    
    echo -e "\n${BLUE}[🛡️ OCSP (Online Certificate Status Protocol) Details]${NC}"
    echo -e "  OCSP URI:            ${YELLOW}${OCSP_URI:-None}${NC}"
    echo -e "  OCSP Stapling:       ${YELLOW}${OCSP_STAPLING_SUPPORTED}${NC}"
    if [[ "$OCSP_STAPLING_SUPPORTED" =~ "Yes" ]]; then
        echo -e "    Stapling Status:   ${GREEN}${OCSP_STAPLING_STATUS}${NC}"
        echo -e "    Cert Status:       ${GREEN}${OCSP_STAPLED_CERT_STATUS}${NC}"
    fi
    echo -e "  Manual OCSP Query:   ${YELLOW}${OCSP_MANUAL_SUPPORTED}${NC}"
    if [[ "$OCSP_MANUAL_SUPPORTED" == "Yes" ]]; then
        echo -e "    Responder Status:  ${GREEN}${OCSP_MANUAL_STATUS}${NC}"
        echo -e "    Cert Status:       ${GREEN}${OCSP_MANUAL_CERT_STATUS}${NC}"
    fi
    
    echo -e "\n${BLUE}[🔒 Protocol Compression & Handshake Signatures]${NC}"
    local comp_color="${GREEN}"
    if [[ "$COMPRESSION" =~ "zlib" ]]; then
        comp_color="${RED} (VULNERABLE to CRIME attack)"
    fi
    echo -e "  TLS Compression:     ${comp_color}${COMPRESSION}${NC}"
    echo -e "  Peer Sign Digest:    ${YELLOW}${PEER_SIGN_DIGEST}${NC}"
    echo -e "  Peer Sign Type:      ${YELLOW}${PEER_SIGN_TYPE}${NC}"
    echo -e "  Server Temp Key:     ${YELLOW}${SERVER_TEMP_KEY}${NC}"
    echo -e "${CYAN}======================================================================${NC}\n"
}

generate_json() {
    local json_file="${REPORT_NAME}.json"
    echo -e "${BLUE}Generating JSON report: ${json_file}${NC}" >&2
    
    # Handle backslashes/quotes in values
    local clean_subj=$(echo "$SUBJECT" | sed 's/"/\\"/g')
    local clean_issuer=$(echo "$ISSUER" | sed 's/"/\\"/g')
    local clean_san=$(echo "$SAN" | sed 's/"/\\"/g')
    local clean_chain_details=$(echo "$CHAIN_DETAILS" | sed 's/"/\\"/g')
    
    cat > "$json_file" << EOF
{
  "scan_info": {
    "target": "$TARGET",
    "scan_time": "$(date -Iseconds)",
    "report_version": "1.0"
  },
  "certificate_leaf": {
    "subject": "$clean_subj",
    "issuer": "$clean_issuer",
    "serial_number": "$SERIAL",
    "validity_not_before": "$NOT_BEFORE",
    "validity_not_after": "$NOT_AFTER",
    "days_until_expiry": "$DAYS_UNTIL_EXPIRY",
    "fingerprint": "$FINGERPRINT",
    "key_info": "$KEY_INFO",
    "signature_algorithm": "$SIG_ALGO",
    "subject_alternative_names": "$clean_san"
  },
  "certificate_chain": {
    "certificates_sent": $CHAIN_COUNT,
    "status": "$CHAIN_STATUS",
    "details": "$clean_chain_details"
  },
  "ocsp": {
    "ocsp_uri": "${OCSP_URI:-null}",
    "ocsp_stapling_supported": "$OCSP_STAPLING_SUPPORTED",
    "ocsp_stapling_status": "$OCSP_STAPLING_STATUS",
    "ocsp_stapled_cert_status": "$OCSP_STAPLED_CERT_STATUS",
    "manual_ocsp_supported": "$OCSP_MANUAL_SUPPORTED",
    "manual_ocsp_status": "$OCSP_MANUAL_STATUS",
    "manual_ocsp_cert_status": "$OCSP_MANUAL_CERT_STATUS"
  },
  "protocol_negotiation": {
    "tls_compression": "$COMPRESSION",
    "peer_signing_digest": "$PEER_SIGN_DIGEST",
    "peer_signature_type": "$PEER_SIGN_TYPE",
    "server_temp_key": "$SERVER_TEMP_KEY"
  }
}
EOF
    echo "$json_file"
}

generate_html() {
    local html_file="${REPORT_NAME}.html"
    echo -e "${BLUE}Generating HTML report: ${html_file}${NC}" >&2
    
    # Determine badge classes and colors
    local expiry_badge_class="badge-green"
    if [[ $DAYS_UNTIL_EXPIRY -lt 30 ]] && [[ $DAYS_UNTIL_EXPIRY -ge 0 ]]; then
        expiry_badge_class="badge-yellow"
    elif [[ $DAYS_UNTIL_EXPIRY -lt 0 ]]; then
        expiry_badge_class="badge-red"
    fi
    
    local chain_badge_class="badge-green"
    if [[ "$CHAIN_STATUS" =~ "Incomplete" ]] || [[ "$CHAIN_STATUS" =~ "Broken" ]]; then
        chain_badge_class="badge-red"
    elif [[ "$CHAIN_STATUS" =~ "Untrusted" ]]; then
        chain_badge_class="badge-yellow"
    fi
    
    local stapling_badge_class="badge-yellow"
    if [[ "$OCSP_STAPLING_SUPPORTED" =~ "Yes" ]]; then
        stapling_badge_class="badge-green"
    fi
    
    local manual_badge_class="badge-yellow"
    if [[ "$OCSP_MANUAL_SUPPORTED" == "Yes" ]]; then
        manual_badge_class="badge-green"
    fi
    
    local comp_badge_class="badge-green"
    if [[ "$COMPRESSION" =~ "zlib" ]]; then
        comp_badge_class="badge-red"
    fi
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL/TLS Certificate & Chain Details</title>
    <style>
        :root {
            --primary: #8a2be2;
            --primary-glow: rgba(138, 43, 226, 0.4);
            --bg: #0f0c1b;
            --card-bg: rgba(22, 17, 43, 0.7);
            --border: rgba(138, 43, 226, 0.2);
            --text: #e0dcf0;
            --text-muted: #a59fb8;
            --green: #00ff87;
            --green-glow: rgba(0, 255, 135, 0.2);
            --red: #ff3860;
            --red-glow: rgba(255, 56, 96, 0.2);
            --yellow: #ffdd57;
            --yellow-glow: rgba(255, 221, 87, 0.2);
            --blue: #209cee;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Outfit', sans-serif;
            background: radial-gradient(circle at 50% 0%, #1e1335, #0f0c1b);
            color: var(--text);
            padding: 40px 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        header {
            text-align: center;
            margin-bottom: 40px;
            position: relative;
        }
        h1 {
            font-size: 2.5rem;
            color: #fff;
            text-shadow: 0 0 15px var(--primary-glow);
            margin-bottom: 10px;
            font-weight: 700;
        }
        .target-box {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 15px;
            display: inline-block;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
            margin-top: 15px;
        }
        .target-box strong { color: var(--green); }
        .section-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
            backdrop-filter: blur(8px);
            transition: all 0.3s ease;
        }
        .section-card:hover {
            border-color: rgba(138, 43, 226, 0.4);
            box-shadow: 0 12px 40px var(--primary-glow);
        }
        h2 {
            font-size: 1.5rem;
            color: #fff;
            margin-bottom: 20px;
            border-left: 4px solid var(--primary);
            padding-left: 12px;
            line-height: 1.2;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        tr {
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        tr:last-child {
            border-bottom: none;
        }
        td {
            padding: 12px;
            vertical-align: top;
        }
        td:first-child {
            font-weight: 600;
            color: var(--text-muted);
            width: 250px;
        }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-green { background: var(--green-glow); color: var(--green); border: 1px solid var(--green); }
        .badge-red { background: var(--red-glow); color: var(--red); border: 1px solid var(--red); }
        .badge-yellow { background: var(--yellow-glow); color: var(--yellow); border: 1px solid var(--yellow); }
        .badge-blue { background: rgba(32, 156, 238, 0.2); color: var(--blue); border: 1px solid var(--blue); }
        code {
            font-family: 'Fira Code', monospace;
            background: rgba(0,0,0,0.3);
            padding: 3px 6px;
            border-radius: 4px;
            font-size: 13px;
        }
        .footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
            margin-top: 50px;
            border-top: 1px solid rgba(255,255,255,0.05);
            padding-top: 20px;
        }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&family=Fira+Code&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 SSL/TLS Certificate Analysis</h1>
            <div class="target-box">
                Target Host: <strong>TARGET_PLACEHOLDER</strong> | Scan Time: <span>SCAN_TIME_PLACEHOLDER</span>
            </div>
        </header>
EOF

    # Replace placeholders portably without using sed -i (which behaves differently on macOS/BSD vs GNU/Linux)
    local tmp_html="${html_file}.tmp"
    sed -e "s/TARGET_PLACEHOLDER/${TARGET}/g" -e "s/SCAN_TIME_PLACEHOLDER/$(date)/g" "$html_file" > "$tmp_html"
    mv "$tmp_html" "$html_file"

    # Append certificate leaf info
    cat >> "$html_file" << EOF
        <!-- Certificate Leaf Card -->
        <div class="section-card">
            <h2>📜 Certificate Leaf Details</h2>
            <table>
                <tr><td>Subject</td><td>${SUBJECT}</td></tr>
                <tr><td>Issuer</td><td>${ISSUER}</td></tr>
                <tr><td>Serial Number</td><td><code>${SERIAL}</code></td></tr>
                <tr><td>Fingerprint (SHA1)</td><td><code>${FINGERPRINT}</code></td></tr>
                <tr><td>Validity (Not Before)</td><td>${NOT_BEFORE}</td></tr>
                <tr><td>Validity (Not After)</td>
                    <td>
                        ${NOT_AFTER}
                        <span class="badge ${expiry_badge_class}">${DAYS_UNTIL_EXPIRY} days remaining</span>
                    </td>
                </tr>
                <tr><td>Key Details</td><td>${KEY_INFO}</td></tr>
                <tr><td>Cert Signature Algorithm</td><td><code>${SIG_ALGO}</code></td></tr>
                <tr><td>Subject Alternative Names</td><td><code>${SAN}</code></td></tr>
            </table>
        </div>

        <!-- Certificate Chain Card -->
        <div class="section-card">
            <h2>🔗 Certificate Chain Status</h2>
            <table>
                <tr><td>Certs Sent by Server</td><td><strong>${CHAIN_COUNT}</strong></td></tr>
                <tr><td>Chain Status</td><td><span class="badge ${chain_badge_class}">${CHAIN_STATUS}</span></td></tr>
                <tr><td>Verification Details</td><td>${CHAIN_DETAILS}</td></tr>
            </table>
        </div>

        <!-- OCSP Card -->
        <div class="section-card">
            <h2>🛡️ OCSP (Online Certificate Status Protocol)</h2>
            <table>
                <tr><td>OCSP Responder URI</td><td><code>${OCSP_URI:-None}</code></td></tr>
                <tr><td>OCSP Stapling Supported</td><td><span class="badge ${stapling_badge_class}">${OCSP_STAPLING_SUPPORTED}</span></td></tr>
                <tr><td>Stapling Response Status</td><td>${OCSP_STAPLING_STATUS}</td></tr>
                <tr><td>Stapled Certificate Status</td><td>${OCSP_STAPLED_CERT_STATUS}</td></tr>
                <tr><td>Manual OCSP Query</td><td><span class="badge ${manual_badge_class}">${OCSP_MANUAL_SUPPORTED}</span></td></tr>
                <tr><td>Manual Response Status</td><td>${OCSP_MANUAL_STATUS}</td></tr>
                <tr><td>Manual Certificate Status</td><td>${OCSP_MANUAL_CERT_STATUS}</td></tr>
            </table>
        </div>

        <!-- Connection Parameters Card -->
        <div class="section-card">
            <h2>🔒 Connection Security & Handshake</h2>
            <table>
                <tr><td>TLS Compression</td><td><span class="badge ${comp_badge_class}">${COMPRESSION}</span></td></tr>
                <tr><td>Peer Signing Digest</td><td><code>${PEER_SIGN_DIGEST}</code></td></tr>
                <tr><td>Peer Signature Type</td><td><code>${PEER_SIGN_TYPE}</code></td></tr>
                <tr><td>Server Temp Key</td><td><code>${SERVER_TEMP_KEY}</code></td></tr>
            </table>
        </div>

        <div class="footer">
            Generated by SSL/TLS Certificate Analysis Tool v1.0<br>
            Report ID: ${REPORT_NAME}
        </div>
    </div>
</body>
</html>
EOF
    echo "$html_file"
}

# Main execution
retrieve_tls_data
extract_details
check_chain_completeness
check_ocsp
check_compression_and_signature_algs

# Handle output formats
JSON_FILE=""
HTML_FILE=""

if [[ "$OUTPUT_FORMAT" == "text" ]] || [[ "$OUTPUT_FORMAT" == "both" ]]; then
    generate_text_report
fi

if [[ "$OUTPUT_FORMAT" == "json" ]] || [[ "$OUTPUT_FORMAT" == "both" ]]; then
    JSON_FILE=$(generate_json)
fi

if [[ "$OUTPUT_FORMAT" == "html" ]] || [[ "$OUTPUT_FORMAT" == "both" ]]; then
    HTML_FILE=$(generate_html)
fi

# Print summary of generated files
if [[ "$OUTPUT_FORMAT" != "text" ]]; then
    echo -e "${GREEN}✅ Assessment complete!${NC}"
    if [[ -n "$JSON_FILE" ]]; then
        echo -e "${GREEN}📄 JSON report: ${JSON_FILE}${NC}"
    fi
    if [[ -n "$HTML_FILE" ]]; then
        echo -e "${GREEN}🌐 HTML report: ${HTML_FILE}${NC}"
    fi
fi
