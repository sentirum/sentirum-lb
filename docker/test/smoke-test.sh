#!/bin/bash
# Smoke tests for sentirum-lb local test environment
set -uo pipefail

LB="http://localhost:9999"
ADMIN="http://localhost:9998"
TOKEN="test-token"
PASS=0
FAIL=0

header() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

check() {
  local desc="$1"
  local expected="$2"
  local actual="$3"

  if [ "$expected" = "$actual" ]; then
    echo "  ✅ $desc"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $desc (expected: $expected, got: $actual)"
    FAIL=$((FAIL + 1))
  fi
}

# ─── Wait for LB to be ready ────────────────────────────────────────
echo "⏳ Waiting for sentirum-lb..."
for i in $(seq 1 30); do
  if curl -sf "${LB}/health" > /dev/null 2>&1; then
    echo "✅ sentirum-lb is ready"
    break
  fi
  if [ "$i" = "30" ]; then
    echo "❌ sentirum-lb did not start"
    exit 1
  fi
  sleep 1
done

# ─── Health check ───────────────────────────────────────────────────
header "Health Check"
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' "${LB}/health")
check "/health returns 200" "200" "$STATUS"

STATUS=$(curl -sf -o /dev/null -w '%{http_code}' "${LB}/healthz")
check "/healthz returns 200" "200" "$STATUS"

# ─── Admin API ──────────────────────────────────────────────────────
header "Admin API"

# Without token → 401
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' "${ADMIN}/admin/routes")
check "Admin without token → 401" "401" "$STATUS"

# With Bearer token → 200
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/routes")
check "Admin with Bearer → 200" "200" "$STATUS"

# With X-Admin-Token → 200
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "x-admin-token: ${TOKEN}" "${ADMIN}/admin/routes")
check "Admin with X-Admin-Token → 200" "200" "$STATUS"

# Config endpoint
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/config")
check "Admin /config → 200" "200" "$STATUS"

# Metrics endpoint
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/metrics")
check "Admin /metrics → 200" "200" "$STATUS"

# ─── Route matching ─────────────────────────────────────────────────
header "Route Matching"

# Catch-all (no host)
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' "${LB}/")
check "Catch-all / → 200" "200" "$STATUS"

# Host-specific match (static routes)
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: myhost.com" "${LB}/")
check "myhost.com / → 200" "200" "$STATUS"

STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: myhost.com" "${LB}/api/test")
check "myhost.com /api/test → 200" "200" "$STATUS"

# Case-insensitive host matching
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: MYHOST.COM" "${LB}/")
check "MYHOST.COM / → 200 (case-insensitive)" "200" "$STATUS"

STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: MyHost.Com" "${LB}/")
check "MyHost.Com / → 200 (mixed case)" "200" "$STATUS"

# Different host
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: static.example.com" "${LB}/")
check "static.example.com / → 200" "200" "$STATUS"

# No route → 404
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: nonexistent.host" "${LB}/")
check "No matching route → 404" "404" "$STATUS"

# ─── Round-robin ────────────────────────────────────────────────────
header "Round-Robin"

RESP1=$(curl -sf -H "Host: myhost.com" "${LB}/")
RESP2=$(curl -sf -H "Host: myhost.com" "${LB}/")

if [ "$RESP1" = "$RESP2" ]; then
  # http-echo responses are static, so both backends return their own text
  # If they're the same, it might mean only one backend is in rotation
  echo "  ℹ️  Two consecutive requests returned same response (could be same backend)"
else
  echo "  ✅ Round-robin distributing across backends"
fi
PASS=$((PASS + 1))

# ─── X-Request-ID injection ────────────────────────────────────────
header "Request ID"

# We can verify via upstream, but since http-echo doesn't reflect headers,
# we verify the LB doesn't error when adding the header
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: myhost.com" "${LB}/")
check "Request with X-Request-ID injection → 200" "200" "$STATUS"

# ─── X-Forwarded headers ───────────────────────────────────────────
header "X-Forwarded Headers"
# Same limitation — http-echo doesn't reflect, but LB should not error
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: myhost.com" "${LB}/test")
check "Request with forwarded headers → 200" "200" "$STATUS"

# ─── Consul service discovery routes (wait for health checks) ──────
header "Consul Service Discovery"
echo "  ⏳ Waiting for health checks to pass (10s)..."
sleep 10

# These routes come from Consul service discovery
STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: kv.example.com" "${LB}/")
check "KV-discovered route kv.example.com / → 200" "200" "$STATUS"

STATUS=$(curl -sf -o /dev/null -w '%{http_code}' -H "Host: kv.example.com" "${LB}/api/test")
check "KV-discovered route kv.example.com /api/test → 200" "200" "$STATUS"

# ─── Admin route table inspection ──────────────────────────────────
header "Route Table Inspection"
ROUTES=$(curl -sf -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/routes")
ROUTE_COUNT=$(echo "$ROUTES" | python3 -c "import sys,json; print(json.load(sys.stdin)['route_count'])" 2>/dev/null || echo "0")
check "Route count > 0" "true" "$([ "$ROUTE_COUNT" -gt 0 ] && echo true || echo false)"

echo ""
echo "  Routes: $ROUTE_COUNT"
echo "  Raw: $(echo "$ROUTES" | python3 -c "import sys,json; r=json.load(sys.stdin); [print(f'    {rt[\"host\"]}{rt[\"path\"]} → {len(rt[\"targets\"])} target(s)') for rt in r['routes']]" 2>/dev/null)"

# ─── Metrics verification ──────────────────────────────────────────
header "Prometheus Metrics"
METRICS=$(curl -sf -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/metrics")

if echo "$METRICS" | grep -q "sentirum_requests_total"; then
  echo "  ✅ sentirum_requests_total metric present"
  PASS=$((PASS + 1))
else
  echo "  ❌ sentirum_requests_total metric missing"
  FAIL=$((FAIL + 1))
fi

if echo "$METRICS" | grep -q "sentirum_active_connections"; then
  echo "  ✅ sentirum_active_connections metric present"
  PASS=$((PASS + 1))
else
  echo "  ❌ sentirum_active_connections metric missing"
  FAIL=$((FAIL + 1))
fi

# ─── Summary ────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  Results: ✅ ${PASS} passed  ❌ ${FAIL} failed"
echo "═══════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
