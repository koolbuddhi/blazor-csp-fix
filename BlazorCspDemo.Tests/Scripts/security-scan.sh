#!/usr/bin/env bash
set -euo pipefail

# Security Scan Script — Tier 3
# Runs curl-based CSP and security header checks against the Blazor app.
# Usage:
#   ./security-scan.sh              # curl checks only
#   ./security-scan.sh --zap        # + OWASP ZAP baseline scan (requires Docker)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../BlazorCspDemo" && pwd)"
REPORT_FILE="$SCRIPT_DIR/security-scan-report.txt"
PORT=5199
BASE_URL="http://127.0.0.1:$PORT"
RUN_ZAP=false
PASS=0
FAIL=0
SERVER_PID=""

if [[ "${1:-}" == "--zap" ]]; then
    RUN_ZAP=true
fi

# --- Helpers ---

log() { echo "$@" | tee -a "$REPORT_FILE"; }

pass() {
    PASS=$((PASS + 1))
    log "  [PASS] $1"
}

fail() {
    FAIL=$((FAIL + 1))
    log "  [FAIL] $1"
}

check_header() {
    local url="$1" header="$2" expected="$3" label="$4"
    local value
    value=$(curl -sI "$url" | grep -i "^${header}:" | head -1 | sed "s/^${header}: *//i" | tr -d '\r')
    if echo "$value" | grep -qi "$expected"; then
        pass "$label"
    else
        fail "$label (got: '$value', expected to contain: '$expected')"
    fi
}

check_header_absent() {
    local url="$1" header="$2" label="$3"
    local value
    value=$(curl -sI "$url" | grep -i "^${header}:" | head -1 || true)
    if [[ -z "$value" ]]; then
        pass "$label"
    else
        fail "$label (header present but should be absent: '$value')"
    fi
}

get_csp() {
    curl -sI "$1" | grep -i "^content-security-policy:" | head -1 | sed 's/^content-security-policy: *//i' | tr -d '\r'
}

start_server() {
    local mode="$1"
    log ""
    log "--- Starting server in $mode mode on $BASE_URL ---"
    ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS="$BASE_URL" CspMode="$mode" \
        dotnet run --no-launch-profile --project "$PROJECT_DIR" > /dev/null 2>&1 &
    SERVER_PID=$!

    # Wait for server to start
    for i in $(seq 1 30); do
        if curl -s "$BASE_URL" > /dev/null 2>&1; then
            log "Server started (PID $SERVER_PID)"
            return 0
        fi
        sleep 1
    done
    log "ERROR: Server did not start within 30 seconds"
    exit 1
}

stop_server() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        log "Server stopped"
    fi
}

cleanup() {
    stop_server
}
trap cleanup EXIT

# --- Start Report ---

echo "" > "$REPORT_FILE"
log "=========================================="
log "  CSP Security Scan Report"
log "  $(date)"
log "=========================================="

# ==========================================
# SECURE MODE TESTS
# ==========================================

start_server "Secure"

log ""
log "=== Secure Mode: CSP Header Checks ==="

# 1. CSP header present
CSP=$(get_csp "$BASE_URL")
if [[ -n "$CSP" ]]; then
    pass "CSP header present on /"
else
    fail "CSP header missing on /"
fi

# 2. Nonce present in script-src
if echo "$CSP" | grep -q "'nonce-"; then
    pass "Nonce present in CSP"
else
    fail "Nonce missing in CSP"
fi

# 3. No unsafe-inline in Secure production mode
if echo "$CSP" | grep -q "'unsafe-inline'"; then
    fail "unsafe-inline found in Secure production CSP"
else
    pass "No unsafe-inline in Secure production CSP"
fi

# 4. No unsafe-eval
if echo "$CSP" | grep -q "'unsafe-eval'"; then
    fail "unsafe-eval found in Secure CSP"
else
    pass "No unsafe-eval in Secure CSP"
fi

# 5. Nonce rotation — two requests should produce different nonces
NONCE1=$(echo "$CSP" | grep -o "'nonce-[^']*'" | head -1)
CSP2=$(get_csp "$BASE_URL")
NONCE2=$(echo "$CSP2" | grep -o "'nonce-[^']*'" | head -1)
if [[ "$NONCE1" != "$NONCE2" ]]; then
    pass "Nonce rotates between requests"
else
    fail "Same nonce returned for two requests"
fi

# 6. default-src is 'self'
if echo "$CSP" | grep -q "default-src 'self'"; then
    pass "default-src is 'self'"
else
    fail "default-src is not 'self'"
fi

log ""
log "=== Secure Mode: Security Header Checks ==="

check_header "$BASE_URL" "X-Content-Type-Options" "nosniff" "X-Content-Type-Options: nosniff"
check_header "$BASE_URL" "X-Frame-Options" "DENY" "X-Frame-Options: DENY"
check_header "$BASE_URL" "Referrer-Policy" "strict-origin-when-cross-origin" "Referrer-Policy set"
check_header "$BASE_URL" "Permissions-Policy" "camera=()" "Permissions-Policy restricts camera"

log ""
log "=== Secure Mode: Static File Checks ==="

# Static files should NOT have CSP headers (UseStaticFiles short-circuits)
check_header_absent "$BASE_URL/app.css" "Content-Security-Policy" "app.css has no CSP header"
check_header_absent "$BASE_URL/favicon.png" "Content-Security-Policy" "favicon.png has no CSP header"
check_header_absent "$BASE_URL/js/csp-test.js" "X-Frame-Options" "csp-test.js has no X-Frame-Options"

stop_server

# ==========================================
# INSECURE MODE TESTS
# ==========================================

start_server "Insecure"

log ""
log "=== Insecure Mode: CSP Header Checks ==="

CSP_INSECURE=$(get_csp "$BASE_URL")

# 1. unsafe-inline present
if echo "$CSP_INSECURE" | grep -q "'unsafe-inline'"; then
    pass "unsafe-inline present in Insecure mode"
else
    fail "unsafe-inline missing in Insecure mode"
fi

# 2. unsafe-eval present
if echo "$CSP_INSECURE" | grep -q "'unsafe-eval'"; then
    pass "unsafe-eval present in Insecure mode"
else
    fail "unsafe-eval missing in Insecure mode"
fi

stop_server

# ==========================================
# OPTIONAL: OWASP ZAP Baseline Scan
# ==========================================

if $RUN_ZAP; then
    log ""
    log "=== OWASP ZAP Baseline Scan ==="

    start_server "Secure"

    if command -v docker &> /dev/null; then
        ZAP_REPORT="$SCRIPT_DIR/zap-report.html"
        log "Running ZAP baseline scan against $BASE_URL..."
        docker run --rm --network=host \
            -v "$SCRIPT_DIR:/zap/wrk/:rw" \
            ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
            -t "$BASE_URL" \
            -r zap-report.html \
            -I 2>&1 | tee -a "$REPORT_FILE" || true
        if [[ -f "$ZAP_REPORT" ]]; then
            pass "ZAP report generated at $ZAP_REPORT"
        else
            fail "ZAP report not generated"
        fi
    else
        log "  [SKIP] Docker not available — skipping ZAP scan"
    fi

    stop_server
fi

# ==========================================
# SUMMARY
# ==========================================

log ""
log "=========================================="
log "  RESULTS: $PASS passed, $FAIL failed"
log "=========================================="

if [[ $FAIL -gt 0 ]]; then
    exit 1
else
    exit 0
fi
