#!/bin/bash

# ssl_missing_info.sh - Captures SSL/TLS info not in testssl.sh report
# Usage: ./ssl_missing_info.sh <domain> [output_file]

TARGET="${1:-cybersamurai.co.uk}"
OUTPUT_FILE="${2:-ssl_missing_info.txt}"

echo "=== SSL/TLS Information Missing from testssl.sh Report ==="
echo "Target: $TARGET"
echo "Generated: $(date)"
echo "============================================================"
echo ""

{
echo "============================================================"
echo "1. CERTIFICATE DETAILS (Missing from testssl.sh)"
echo "============================================================"

# Get certificate from the server
CERT_DATA=$(openssl s_client -connect "$TARGET":443 -servername "$TARGET" -showcerts </dev/null 2>/dev/null)

# Extract the first certificate
echo "$CERT_DATA" | openssl x509 -noout -text 2>/dev/null | grep -E "Subject:|Issuer:|Not Before:|Not After:|Serial Number:|SHA1 Fingerprint=|Subject Alternative Name|Public Key Algorithm|RSA Public Key|NIST CURVE|X509v3 Extended Key Usage|X509v3 Key Usage"

echo ""
echo "============================================================"
echo "2. CERTIFICATE CHAIN (Complete chain details)"
echo "============================================================"

# Count certificates in chain
CERT_COUNT=$(echo "$CERT_DATA" | grep -c "BEGIN CERTIFICATE")
echo "Number of certificates in chain: $CERT_COUNT"

# Show issuer for each certificate
for i in $(seq 1 $CERT_COUNT); do
    echo "Certificate $i:"
    echo "$CERT_DATA" | awk -v n=$i '/BEGIN CERTIFICATE/{c++} c==n' | openssl x509 -noout -issuer -subject -dates 2>/dev/null
    echo "---"
done

echo ""
echo "============================================================"
echo "3. OCSP RESPONSE (Online Certificate Status Protocol)"
echo "============================================================"

# Check OCSP stapling
openssl s_client -connect "$TARGET":443 -servername "$TARGET" -status </dev/null 2>&1 | grep -A 20 "OCSP response:" | head -30

echo ""
echo "============================================================"
echo "4. CERTIFICATE REVOCATION LISTS (CRL Distribution Points)"
echo "============================================================"

echo "$CERT_DATA" | openssl x509 -noout -text 2>/dev/null | grep -A 5 "X509v3 CRL Distribution Points"

echo ""
echo "============================================================"
echo "5. AUTHORITY INFORMATION ACCESS (AIA) - OCSP & CA Issuers"
echo "============================================================"

echo "$CERT_DATA" | openssl x509 -noout -text 2>/dev/null | grep -A 5 "Authority Information Access"

echo ""
echo "============================================================"
echo "6. KEY STRENGTH & ALGORITHM DETAILS"
echo "============================================================"

echo "$CERT_DATA" | openssl x509 -noout -text 2>/dev/null | grep -A 10 "Public Key Algorithm"

echo ""
echo "============================================================"
echo "7. EXTENDED VALIDATION (EV) INDICATORS"
echo "============================================================"

echo "$CERT_DATA" | openssl x509 -noout -text 2>/dev/null | grep -i "Certificate Policy" -A 3 | head -20

echo ""
echo "============================================================"
echo "8. TLS HANDSHAKE DETAILS (Full protocol negotiation)"
echo "============================================================"

echo "Connecting and showing full handshake details:"
openssl s_client -connect "$TARGET":443 -servername "$TARGET" -state -debug 2>&1 | head -50

echo ""
echo "============================================================"
echo "9. SUPPORTED SIGNATURE ALGORITHMS (Server preference)"
echo "============================================================"

echo | openssl s_client -connect "$TARGET":443 -servername "$TARGET" -sigalgs 2>/dev/null | grep -i "Server Temp Key" -A 2

echo ""
echo "============================================================"
echo "10. SESSION RESUMPTION SUPPORT"
echo "============================================================"

# Test session resumption
echo "Testing session resumption..."
SESSION_ID=$(openssl s_client -connect "$TARGET":443 -servername "$TARGET" </dev/null 2>/dev/null | grep "Session-ID:" | head -1)
if [ -n "$SESSION_ID" ]; then
    echo "Session ID: $SESSION_ID"
    echo "Session resumption appears supported"
else
    echo "No session ID found - session resumption may not be supported"
fi

echo ""
echo "============================================================"
echo "11. PERFECT FORWARD SECRECY (PFS) SUPPORT DETAILS"
echo "============================================================"

echo "Checking for PFS support in cipher suites:"
openssl s_client -connect "$TARGET":443 -servername "$TARGET" -cipher 'ECDHE:EDH' </dev/null 2>/dev/null | grep -E "Protocol|Cipher" | head -5

echo ""
echo "============================================================"
echo "12. TLS EXTENSIONS SUPPORTED"
echo "============================================================"

openssl s_client -connect "$TARGET":443 -servername "$TARGET" -tlsextdebug </dev/null 2>&1 | grep -i "Extension" | head -20

echo ""
echo "============================================================"
echo "13. COMPRESSION METHODS (Security concern if enabled)"
echo "============================================================"

openssl s_client -connect "$TARGET":443 -servername "$TARGET" -comp </dev/null 2>&1 | grep -i "compression"

echo ""
echo "============================================================"
echo "14. SERVER SIGNATURE ALGORITHMS (What the server supports)"
echo "============================================================"

echo | openssl s_client -connect "$TARGET":443 -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text | grep "Signature Algorithm"

} | tee -a "$OUTPUT_FILE"

echo ""
echo "Report saved to: $OUTPUT_FILE"