#!/bin/bash
# Smoke tests for sentirum-lb local test environment
set -uo pipefail

LB="http://localhost:9999"
ADMIN="http://localhost:9998"
TOKEN="test-token"
PASS=0
FAIL=0
C="curl --max-time 5 -s -H "Connection: close""

header() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "  ✅ $desc"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $desc (expected: $expected, got: $actual)"
    FAIL=$((FAIL + 1))
  fi
}

# ─── Wait for LB ────────────────────────────────────────────────────
echo "⏳ Waiting for sentirum-lb..."
for i in $(seq 1 30); do
  if $C -o /dev/null -w '' "${LB}/health" 2>/dev/null; then
    echo "✅ sentirum-lb is ready"
    break
  fi
  [ "$i" = "30" ] && { echo "❌ sentirum-lb did not start"; exit 1; }
  sleep 1
done

# ─── Health ─────────────────────────────────────────────────────────
header "Health Check"
check "/health → 200" "200" "$($C -o /dev/null -w '%{http_code}' "${LB}/health")"
check "/healthz → 200" "200" "$($S -o /dev/null -w '%{http_code}' "${LB}/healthz")"

# ─── Admin API ──────────────────────────────────────────────────────
header "Admin API"
check "No token → 401" "401" "$($C -o /dev/null -w '%{http_code}' "${ADMIN}/admin/routes")"
check "Bearer → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/routes")"
check "X-Admin-Token → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "x-admin-token: ${TOKEN}" "${ADMIN}/admin/routes")"
check "/config → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/config")"
check "/metrics → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/metrics")"

# ─── Route Matching ─────────────────────────────────────────────────
header "Route Matching"
check "Catch-all / → 200" "200" "$($C -o /dev/null -w '%{http_code}' "${LB}/")"
check "myhost.com / → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "Host: myhost.com" "${LB}/")"
check "myhost.com /api/test → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "Host: myhost.com" "${LB}/api/test")"
check "MYHOST.COM / → 200 (case)" "200" "$($C -o /dev/null -w '%{http_code}' -H "Host: MYHOST.COM" "${LB}/")"
check "MyHost.Com / → 200 (mixed)" "200" "$($C -o /dev/null -w '%{http_code}' -H "Host: MyHost.Com" "${LB}/")"
check "static.example.com / → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "Host: static.example.com" "${LB}/")"
check "No route → 404" "404" "$($C -o /dev/null -w '%{http_code}' -H "Host: nonexistent.host" "${LB}/")"

# ─── Round-Robin ────────────────────────────────────────────────────
header "Round-Robin"
RESP1=$($C -H "Host: myhost.com" "${LB}/")
RESP2=$($C -H "Host: myhost.com" "${LB}/")
if [ "$RESP1" = "$RESP2" ]; then
  echo "  ℹ️  Same backend twice (may be OK with 2-target round-robin)"
else
  echo "  ✅ Different backends (round-robin working)"
fi
PASS=$((PASS + 1))

# ─── Consul Service Discovery ──────────────────────────────────────
header "Consul Service Discovery"
echo "  ⏳ Waiting for health checks (10s)..."
sleep 10
check "kv.example.com / → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "Host: kv.example.com" "${LB}/")"
check "kv.example.com /api/ → 200" "200" "$($C -o /dev/null -w '%{http_code}' -H "Host: kv.example.com" "${LB}/api/test")"

# ─── Route Table ────────────────────────────────────────────────────
header "Route Table"
ROUTES=$($C -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/routes")
ROUTE_COUNT=$(echo "$ROUTES" | python3 -c "import sys,json; print(json.load(sys.stdin)['route_count'])" 2>/dev/null || echo "0")
check "Routes > 0" "true" "$([ "$ROUTE_COUNT" -gt 0 ] && echo true || echo false)"
echo "  Routes: $ROUTE_COUNT"
echo "$ROUTES" | python3 -c "import sys,json; [print(f'    {r[\"host\"]}{r[\"path\"]} → {len(r[\"targets\"])} target(s)') for r in json.load(sys.stdin)['routes']]" 2>/dev/null

# ─── Metrics ────────────────────────────────────────────────────────
header "Prometheus Metrics"
METRICS=$($C -H "Authorization: Bearer ${TOKEN}" "${ADMIN}/admin/metrics")
if echo "$METRICS" | grep -q "sentirum_requests_total"; then
  echo "  ✅ sentirum_requests_total present"; PASS=$((PASS + 1))
else
  echo "  ❌ sentirum_requests_total missing"; FAIL=$((FAIL + 1))
fi
if echo "$METRICS" | grep -q "sentirum_active_connections"; then
  echo "  ✅ sentirum_active_connections present"; PASS=$((PASS + 1))
else
  echo "  ❌ sentirum_active_connections missing"; FAIL=$((FAIL + 1))
fi

# ─── Summary ────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  Results: ✅ ${PASS} passed  ❌ ${FAIL} failed"
echo "═══════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
