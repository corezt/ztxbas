#!/bin/bash
# ztxbas_api_test.sh — end-to-end tester for the ztxbas v1 API.
#
# Adapted from the C-era api_client_challenge.sh. Key differences:
#   • Paths are /v1/* (was /api/*).
#   • HMAC identity header is X-Application-ID (was X-Client-ID).
#   • Status is GET /v1/auth/status/{id} (was POST with body).
#   • There is no /api/auth/respond — approval happens on the mobile
#     device via ztxlib. For automated testing, run the server with
#     the ztxlib_fake tag (make build-fake), which auto-approves after
#     ~2 seconds. This script polls with a timeout instead of calling
#     a respond endpoint.
#   • Register-user hits POST /v1/users; deregister uses DELETE.
#
# Prereqs:  jq, curl, openssl.

set -e

API_BASE="${API_BASE:-http://localhost:8443}"      # http unless TLS configured
CREDENTIALS_FILE=".ztxbas_credentials.json"
POLL_TIMEOUT="${POLL_TIMEOUT:-15}"                 # seconds for auto test-flow

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✔${NC} $1"; }
log_error()   { echo -e "${RED}✗${NC} $1" >&2; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
log_header()  { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

# ---------------------------------------------------------------------------
# HMAC signing — sign_data = "METHOD|PATH|TIMESTAMP|NONCE|BODY"
# Server verifies with hex(HMAC-SHA256(secret, sign_data)).
# ---------------------------------------------------------------------------
generate_nonce()     { openssl rand -hex 32; }
generate_timestamp() { date +%s; }

generate_signature() {
    local secret="$1" method="$2" url="$3" timestamp="$4" nonce="$5" body="$6"
    local data="${method}|${url}|${timestamp}|${nonce}|${body}"
    printf '%s' "$data" | openssl dgst -sha256 -hmac "$secret" | awk '{print $2}'
}

# ---------------------------------------------------------------------------
# Credentials — created via `ztxbas app create <name>` on the server side.
# The server prints the HMAC secret once; paste it in with `setup`.
# ---------------------------------------------------------------------------
load_credentials() {
    if [ -f "$CREDENTIALS_FILE" ]; then
        APP_ID=$(jq -r '.application_id // empty' "$CREDENTIALS_FILE" 2>/dev/null)
        HMAC_SECRET=$(jq -r '.hmac_secret // empty' "$CREDENTIALS_FILE" 2>/dev/null)
        [ -n "$APP_ID" ] && [ -n "$HMAC_SECRET" ] && return 0
    fi
    return 1
}

save_credentials() {
    cat > "$CREDENTIALS_FILE" <<EOF
{
  "application_id": "$1",
  "hmac_secret": "$2",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    chmod 600 "$CREDENTIALS_FILE"
    log_success "Credentials saved to $CREDENTIALS_FILE"
}

# ---------------------------------------------------------------------------
# api_call METHOD ENDPOINT [BODY]
# For GET, pass "" as body.
# ---------------------------------------------------------------------------
api_call() {
    local method="$1" endpoint="$2" body="${3:-}"

    if ! load_credentials; then
        log_error "No credentials. Run: $0 setup"
        return 1
    fi

    local timestamp; timestamp=$(generate_timestamp)
    local nonce;     nonce=$(generate_nonce)
    local signature; signature=$(generate_signature "$HMAC_SECRET" "$method" "$endpoint" "$timestamp" "$nonce" "$body")

    local -a args=(
        --insecure -s -w "\n%{http_code}"
        -X "$method"
        -H "Content-Type: application/json"
        -H "X-Application-ID: $APP_ID"
        -H "X-Timestamp: $timestamp"
        -H "X-Nonce: $nonce"
        -H "X-Signature: $signature"
    )
    [ -n "$body" ] && args+=(-d "$body")
    args+=("${API_BASE}${endpoint}")

    local response; response=$(curl "${args[@]}")
    RESPONSE_BODY=$(echo "$response" | head -n -1)
    RESPONSE_STATUS=$(echo "$response" | tail -n 1)
}

print_response() {
    echo -e "${BLUE}$1${NC} (HTTP $RESPONSE_STATUS):"
    echo "$RESPONSE_BODY" | jq '.' 2>/dev/null || echo "$RESPONSE_BODY"
    echo ""
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_setup() {
    log_header "ztxbas API Client Setup"

    if load_credentials; then
        echo "Current credentials:"
        echo "  Application ID: $APP_ID"
        echo "  Secret: ${HMAC_SECRET:0:20}..."
        read -p "Update? (y/N): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && { log_info "Keeping existing"; return 0; }
    fi
    echo "Get these from: ztxbas app create <name>  (on the server host)"
    read -r -p "Application ID: " app_id
    read -r -p "HMAC Secret: "    hmac_secret
    [ -z "$app_id" ] || [ -z "$hmac_secret" ] && { log_error "Both required"; return 1; }
    save_credentials "$app_id" "$hmac_secret"
    log_success "Setup complete"
}

cmd_status() {
    log_header "Client Status"
    echo "API Endpoint: $API_BASE"
    if load_credentials; then
        echo -e "Credentials: ${GREEN}✔ configured${NC}  (app=$APP_ID)"
    else
        echo -e "Credentials: ${RED}✗ missing${NC} — run: $0 setup"
        return 1
    fi

    log_info "Testing /health..."
    local resp; resp=$(curl --insecure -s -w "\n%{http_code}" "${API_BASE}/health")
    local body; body=$(echo "$resp" | head -n -1)
    local st;   st=$(echo "$resp" | tail -n 1)
    if [ "$st" = "200" ]; then
        echo -e "Server: ${GREEN}✔ healthy${NC}"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
    else
        echo -e "Server: ${RED}✗ unreachable${NC} (HTTP $st)"
        return 1
    fi
}

cmd_register_origin() {
    local origin="$1" display_name="$2"
    if [ -z "$origin" ] || [ -z "$display_name" ]; then
        log_error "Usage: $0 origin-register <origin_url> <display_name>"
        return 1
    fi
    log_header "Register Origin"
    api_call POST "/v1/origins" "{\"origin\":\"$origin\",\"display_name\":\"$display_name\"}"
    print_response "Response"
    if [ "$RESPONSE_STATUS" = "201" ] || [ "$RESPONSE_STATUS" = "200" ]; then
        log_success "Origin registered"
        echo "  Origin Hash: $(echo "$RESPONSE_BODY" | jq -r '.origin_hash')"
    else
        log_error "Failed"
        return 1
    fi
}

cmd_user_register() {
    local email="$1"
    [ -z "$email" ] && { log_error "Usage: $0 user-register <email>"; return 1; }
    log_header "Register User"
    api_call POST "/v1/users" "{\"email\":\"$email\"}"
    print_response "Response"
}

cmd_user_deregister() {
    local email="$1"
    [ -z "$email" ] && { log_error "Usage: $0 user-deregister <email>"; return 1; }
    log_header "Deregister User"
    api_call DELETE "/v1/users" "{\"email\":\"$email\"}"
    print_response "Response"
}

cmd_create_challenge() {
    local user_email="$1" origin="$2"
    if [ -z "$user_email" ] || [ -z "$origin" ]; then
        log_error "Usage: $0 challenge <user_email> <origin>"
        return 1
    fi
    log_header "Create Auth Challenge"
    log_info "User:   $user_email"
    log_info "Origin: $origin"

    api_call POST "/v1/auth/challenge" "{\"user_email\":\"$user_email\",\"origin\":\"$origin\"}"
    print_response "Response"

    if [ "$RESPONSE_STATUS" = "201" ] || [ "$RESPONSE_STATUS" = "200" ]; then
        local ch_id;   ch_id=$(echo "$RESPONSE_BODY"   | jq -r '.challenge_id')
        local ttl;     ttl=$(echo "$RESPONSE_BODY"     | jq -r '.expires_in')
        local display; display=$(echo "$RESPONSE_BODY" | jq -r '.origin_display')
        log_success "Challenge created: $ch_id (expires in ${ttl}s)"
        echo ""
        echo "Mobile app would show:"
        echo "  ┌─────────────────────────────┐"
        echo "  │ Login to: $display"
        echo "  │   $origin"
        echo "  │ Account:  $user_email"
        echo "  │ [Deny]           [Approve]  │"
        echo "  └─────────────────────────────┘"
        echo "$ch_id" > .last_challenge_id
        log_info "Saved. Poll with: $0 poll"
    elif [ "$RESPONSE_STATUS" = "403" ]; then
        log_error "Origin not registered — request rejected (phishing resistance)."
        echo "  Register with: $0 origin-register $origin \"<name>\""
    else
        log_error "Challenge creation failed"
        return 1
    fi
}

cmd_poll_status() {
    local ch_id="$1"
    if [ -z "$ch_id" ] && [ -f .last_challenge_id ]; then
        ch_id=$(cat .last_challenge_id)
        log_info "Using saved challenge ID: $ch_id"
    fi
    [ -z "$ch_id" ] && { log_error "Usage: $0 poll [challenge_id]"; return 1; }

    log_header "Poll Challenge Status"
    api_call GET "/v1/auth/status/$ch_id" ""
    print_response "Response"

    local status; status=$(echo "$RESPONSE_BODY" | jq -r '.status // empty')
    case "$status" in
        pending)  log_warning "Waiting for approval on the device..." ;;
        approved)
            log_success "Approved!"
            local jwt; jwt=$(echo "$RESPONSE_BODY" | jq -r '.jwt // empty')
            [ -n "$jwt" ] && echo "  JWT: ${jwt:0:60}..."
            rm -f .last_challenge_id
            ;;
        denied)   log_error "User denied"; rm -f .last_challenge_id ;;
        expired)  log_error "Challenge expired"; rm -f .last_challenge_id ;;
        *)        log_error "Unknown status: $status" ;;
    esac
}

# Poll every second up to POLL_TIMEOUT — for the automated flow test.
poll_until_terminal() {
    local ch_id="$1"
    local deadline=$(( $(date +%s) + POLL_TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        api_call GET "/v1/auth/status/$ch_id" ""
        local status; status=$(echo "$RESPONSE_BODY" | jq -r '.status // empty')
        case "$status" in
            approved|denied|expired) POLL_FINAL="$status"; return 0 ;;
        esac
        sleep 1
    done
    POLL_FINAL="timeout"
}

cmd_test_flow() {
    log_header "Full Authentication Flow"
    local email="testuser@example.com" origin="https://test-app.example.com"

    log_info "Requires the server to be built with -tags ztxlib_fake"
    log_info "(otherwise the poll will not auto-approve)"
    echo ""

    log_info "Step 1: Register user (triggers enrollment)"
    api_call POST "/v1/users" "{\"email\":\"$email\"}"
    [ "$RESPONSE_STATUS" != "200" ] && [ "$RESPONSE_STATUS" != "201" ] && [ "$RESPONSE_STATUS" != "409" ] \
        && { log_error "user register: HTTP $RESPONSE_STATUS"; echo "$RESPONSE_BODY"; return 1; }
    log_success "User: $email"

    log_info "Step 2: Register origin"
    api_call POST "/v1/origins" "{\"origin\":\"$origin\",\"display_name\":\"Test Application\"}"
    [ "$RESPONSE_STATUS" != "201" ] && [ "$RESPONSE_STATUS" != "200" ] && [ "$RESPONSE_STATUS" != "409" ] \
        && { log_error "origin register: HTTP $RESPONSE_STATUS"; echo "$RESPONSE_BODY"; return 1; }
    log_success "Origin: $origin"

    log_info "Step 3: Create challenge"
    api_call POST "/v1/auth/challenge" "{\"user_email\":\"$email\",\"origin\":\"$origin\"}"
    [ "$RESPONSE_STATUS" != "201" ] && [ "$RESPONSE_STATUS" != "200" ] \
        && { log_error "challenge: HTTP $RESPONSE_STATUS"; echo "$RESPONSE_BODY"; return 1; }
    local ch_id; ch_id=$(echo "$RESPONSE_BODY" | jq -r '.challenge_id')
    log_success "Challenge: ${ch_id:0:12}…"

    log_info "Step 4: First poll (expect pending)"
    api_call GET "/v1/auth/status/$ch_id" ""
    local first_status; first_status=$(echo "$RESPONSE_BODY" | jq -r '.status')
    if [ "$first_status" = "pending" ]; then
        log_success "pending"
    else
        log_warning "unexpected first status: $first_status"
    fi

    log_info "Step 5: Poll until terminal (max ${POLL_TIMEOUT}s)"
    poll_until_terminal "$ch_id"
    case "$POLL_FINAL" in
        approved)
            local jwt; jwt=$(echo "$RESPONSE_BODY" | jq -r '.jwt // empty')
            log_success "Approved — full flow OK"
            [ -n "$jwt" ] && echo "  JWT: ${jwt:0:60}…"
            ;;
        timeout)
            log_error "Poll timed out. Is the server running with -tags ztxlib_fake?"
            return 1
            ;;
        *)
            log_error "Terminal status was: $POLL_FINAL"
            return 1
            ;;
    esac
}

cmd_test_phishing() {
    log_header "Phishing Resistance Test"
    local email="victim@example.com"
    local legit="https://legitimate-app.com"
    local phish="https://legitimate-app.com.evil.com"

    log_info "Step 1: Ensure victim user exists"
    api_call POST "/v1/users" "{\"email\":\"$email\"}"

    log_info "Step 2: Register legitimate origin"
    api_call POST "/v1/origins" "{\"origin\":\"$legit\",\"display_name\":\"Legitimate App\"}"

    log_info "Step 3: Challenge from legitimate origin (should succeed)"
    api_call POST "/v1/auth/challenge" "{\"user_email\":\"$email\",\"origin\":\"$legit\"}"
    if [ "$RESPONSE_STATUS" = "201" ] || [ "$RESPONSE_STATUS" = "200" ]; then
        log_success "Accepted (as expected)"
    else
        log_error "Legitimate challenge failed unexpectedly (HTTP $RESPONSE_STATUS)"
        echo "$RESPONSE_BODY"
        return 1
    fi

    log_info "Step 4: Challenge from PHISHING origin (should be blocked)"
    api_call POST "/v1/auth/challenge" "{\"user_email\":\"$email\",\"origin\":\"$phish\"}"
    if [ "$RESPONSE_STATUS" = "403" ]; then
        log_success "BLOCKED. Phishing resistance works."
        echo "$RESPONSE_BODY" | jq '.'
    else
        log_error "Phishing origin was NOT blocked (HTTP $RESPONSE_STATUS)"
        return 1
    fi
}

cmd_help() {
    cat <<EOF

${CYAN}ztxbas API Test Client (v1 API)${NC}

${YELLOW}Usage:${NC}
  $0 <command> [args]

${YELLOW}Setup:${NC}
  setup                                Configure application_id + hmac_secret
                                       (get from: ztxbas app create <name>)
  status                               Show config + hit /health

${YELLOW}Origin management:${NC}
  origin-register <url> <name>         POST /v1/origins

${YELLOW}Users:${NC}
  user-register   <email>              POST /v1/users
  user-deregister <email>              DELETE /v1/users

${YELLOW}Authentication:${NC}
  challenge <email> <origin>           POST /v1/auth/challenge
  poll      [challenge_id]             GET  /v1/auth/status/{id}

${YELLOW}Automated tests:${NC}
  test-flow                            End-to-end (needs -tags ztxlib_fake)
  test-phishing                        Verify origin binding blocks lookalikes

${YELLOW}Env vars:${NC}
  API_BASE       default http://localhost:8443
                 use https://… only if you configured ZTXBAS_TLS_CERT/KEY
  POLL_TIMEOUT   seconds test-flow will wait for approval (default 15)

${YELLOW}Notes:${NC}
  • Approvals happen on the mobile device via ztxlib in production.
    Build with 'make build-fake' for local end-to-end tests without a phone.
  • Signing string is METHOD|PATH|TIMESTAMP|NONCE|BODY; HMAC-SHA256 hex.
  • X-Application-ID header carries the app ID; ${YELLOW}not${NC} X-Client-ID.

EOF
}

# ---------------------------------------------------------------------------
main() {
    for c in jq curl openssl; do
        command -v "$c" &>/dev/null || { log_error "$c required"; exit 1; }
    done

    local cmd="${1:-help}"; shift || true
    case "$cmd" in
        setup)                       cmd_setup                 ;;
        status)                      cmd_status                ;;
        origin-register|register-origin) cmd_register_origin "$@" ;;
        user-register)               cmd_user_register    "$@" ;;
        user-deregister)             cmd_user_deregister  "$@" ;;
        challenge|auth)              cmd_create_challenge "$@" ;;
        poll|status-poll)            cmd_poll_status      "$@" ;;
        test-flow|test)              cmd_test_flow             ;;
        test-phishing)               cmd_test_phishing         ;;
        help|--help|-h)              cmd_help                  ;;
        *) log_error "Unknown command: $cmd"; echo "Try: $0 help"; exit 1 ;;
    esac
}
main "$@"
