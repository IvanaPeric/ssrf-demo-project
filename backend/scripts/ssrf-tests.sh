#!/usr/bin/env bash
# SSRF vulnerability demo script - compares vulnerable vs secure implementations
# Usage: ./scripts/ssrf-tests.sh
#
# Prerequisites:
# - Vulnerable server running on port 3000: node server-vulnerable.js
# - Secure server running on port 4000: node server-secure.js

set -euo pipefail

VULN_BASE="http://localhost:3000"
SECURE_BASE="http://localhost:4000"

VULN_FETCH="$VULN_BASE/fetch"
SECURE_FETCH_GET="$SECURE_BASE/fetch"
SECURE_FETCH_POST="$SECURE_BASE/fetch-secure"

META="http://localhost:3000/aws-metadata/latest/meta-data/iam/security-credentials"
META_SECURE="http://localhost:4000/aws-metadata/latest/meta-data/iam/security-credentials"
ALLOWED="http://httpbin.org/get"
PRIVATE_IP="http://192.168.1.1"
LOCALHOST="http://127.0.0.1:3000/aws-metadata/latest/meta-data/iam/security-credentials"

echo "=========================================="
echo "SSRF VULNERABILITY DEMONSTRATION"
echo "=========================================="
echo ""

echo "--- TEST 1: Vulnerable Server - SSRF Attack on Metadata (SUCCEEDS - VULNERABLE) ---"
echo "Attempting to fetch AWS metadata through vulnerable endpoint..."
curl -s "$VULN_FETCH?url=$META" | head -n 10
echo ""
echo ""

echo "--- TEST 2: Secure Server - Same Attack Blocked (BLOCKED - SECURE) ---"
echo "Attempting same attack on secure endpoint (GET)..."
curl -s "$SECURE_FETCH_GET?url=$META_SECURE" | head -n 5
echo ""
echo ""

echo "--- TEST 3: Secure Server - Same Attack Blocked via POST (BLOCKED - SECURE) ---"
echo "Attempting same attack on secure endpoint (POST)..."
curl -s -X POST "$SECURE_FETCH_POST" -H 'Content-Type: application/json' -d "{\"url\":\"$META_SECURE\"}" | head -n 5
echo ""
echo ""

echo "--- TEST 4: Secure Server - Allowed Host (SUCCEEDS - SECURE) ---"
echo "Fetching from allowlisted host (httpbin.org)..."
curl -s "$SECURE_FETCH_GET?url=$ALLOWED" | head -n 10
echo ""
echo ""

echo "--- TEST 5: Secure Server - Private IP Blocked (BLOCKED - SECURE) ---"
echo "Attempting to fetch from private IP..."
curl -s "$SECURE_FETCH_GET?url=$PRIVATE_IP" | head -n 5
echo ""
echo ""

echo "--- TEST 6: Secure Server - Localhost Blocked (BLOCKED - SECURE) ---"
echo "Attempting to fetch localhost..."
curl -s "$SECURE_FETCH_GET?url=$LOCALHOST" | head -n 5
echo ""
echo ""

echo "=========================================="
echo "Summary:"
echo "- Vulnerable server: Accepts any URL (SSRF vulnerability)"
echo "- Secure server: Validates URL, blocks private IPs, uses allowlist"
echo "=========================================="
