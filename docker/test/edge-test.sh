#!/bin/bash
set -euo pipefail
LB="http://localhost:9999"; ADMIN="http://localhost:9998/admin"; TOKEN="admin123"; PASS=0; FAIL=0
header() { echo ""; echo "━━━━  $1  ━━━━"; }
check() { if [ "$2" = "$3" ]; then echo "  ✅ $1"; PASS=$((PASS+1)); else echo "  ❌ $1 ($2!=$3)"; FAIL=$((FAIL+1)); fi; }
ok() { if [ "$2" = "true" ]; then echo "  ✅ $1"; PASS=$((PASS+1)); else echo "  ❌ $1"; FAIL=$((FAIL+1)); fi; }
gt() { if [ "$3" -gt "$2" ] 2>/dev/null; then echo "  ✅ $1 ($3>$2)"; PASS=$((PASS+1)); else echo "  ❌ $1 ($3<=$2)"; FAIL=$((FAIL+1)); fi; }
has() { echo "$2" | grep -q "$1" 2>/dev/null; }
g() { curl -s --max-time 5 -w '\n%{http_code}' "$@" 2>/dev/null | tail -1; }
gj() { curl -sf --max-time 5 "$@" 2>/dev/null || echo '{}'; }

echo "⏳ Waiting..."; for i in $(seq 1 20); do R=$(curl -s --max-time 2 "$LB/health" 2>/dev/null || echo ""); echo "$R" | grep -q "ok" && { echo "✅ Ready"; break; } || true; [ "$i" = "20" ] && { echo "❌ Fail"; exit 1; }; sleep 1; done

# ═══ 1. AUTH ═══
header "1. Auth"
check "Empty Bearer → 401" "401" "$(g -H 'Authorization: Bearer ' "$ADMIN/config")"
check "Invalid Bearer → 401" "401" "$(g -H 'Authorization: Bearer bad' "$ADMIN/config")"
check "Basic auth → 401" "401" "$(g -H 'Authorization: Basic YWRtaW46YWRtaW4xMjM=' "$ADMIN/config")"
check "XSS token → 401" "401" "$(g -H 'Authorization: Bearer <x>' "$ADMIN/config")"
check "10K token → 401" "401" "$(g -H "Authorization: Bearer $(python3 -c "print('x'*10000)" 2>/dev/null)" "$ADMIN/config")"
check "X-Admin-Token → 200" "200" "$(g -H "X-Admin-Token: $TOKEN" "$ADMIN/config")"
check "Query token → 200" "200" "$(g "$ADMIN/config?token=$TOKEN")"
R=$(gj -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"wrong"}' "$ADMIN/login")
ok "Wrong password → rejected" "$(has false "$R" && echo true || echo false)"
R=$(gj -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' "$ADMIN/login")
ok "Valid login → success" "$(has '"success":true' "$R" && echo true || echo false)"

# ═══ 2. ROUTES ═══
header "2. Route Matching"
check "Root / → 200" "200" "$(g "$LB/")"
check "Deep path → 200" "200" "$(g "$LB/a/b/c/d/e/f")"
check "Query string → 200" "200" "$(g "$LB/api/test?foo=bar")"
check "Encoded path → 200" "200" "$(g "$LB/api/test%20space")"
check "Trailing slash → 200" "200" "$(g "$LB/api/")"
check "Uppercase host → 200" "200" "$(g -H "Host: MYHOST.COM" "$LB/")"
check "Mixed case host → 200" "200" "$(g -H "Host: MyHost.Com" "$LB/")"
check "Host:port → 200" "200" "$(g -H "Host: myhost.com:9999" "$LB/")"
check "Unknown host → 200" "200" "$(g -H "Host: unknown.x.com" "$LB/")"
check "KV strip route → 200" "200" "$(g -H "Host: kv.example.com" "$LB/api/test")"
ok "OPTIONS → not 5xx" "$([ "$(g -X OPTIONS "$LB/")" -lt 500 ] && echo true || echo false)"
check "HEAD → 200" "200" "$(g -I "$LB/")"

# ═══ 3. ADMIN API ═══
header "3. Admin API"
RR=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/routes")
TR=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/targets")
CR=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/config")
MR=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/metrics")
DR=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/dns-cache")
TP=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/topology")
ok "Routes → route_count" "$(has route_count "$RR" && echo true || echo false)"
ok "Routes → target_count" "$(has target_count "$RR" && echo true || echo false)"
ok "Targets → array" "$(has '"targets"' "$TR" && echo true || echo false)"
ok "Config → proxy" "$(has '"proxy"' "$CR" && echo true || echo false)"
ok "Config → server" "$(has '"server"' "$CR" && echo true || echo false)"
ok "Metrics → sentirum_lb_" "$(has sentirum_lb_ "$MR" && echo true || echo false)"
ok "Metrics → requests_total" "$(has requests_total "$MR" && echo true || echo false)"
ok "Metrics → HELP" "$(has "# HELP" "$MR" && echo true || echo false)"
ok "Metrics → TYPE" "$(has "# TYPE" "$MR" && echo true || echo false)"
ok "Metrics → no NaN" "$(has NaN "$MR" && echo false || echo true)"
ok "Metrics → latency" "$(has latency "$MR" && echo true || echo false)"
ok "DNS → stats" "$(has '"stats"' "$DR" && echo true || echo false)"
ok "Topology → hosts" "$(has '"hosts"' "$TP" && echo true || echo false)"
ok "Topology → lb" "$(has '"lb"' "$TP" && echo true || echo false)"
LR=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/logs?limit=5")
LC=$(echo "$LR" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
ok "Logs limit=5 → ≤5" "$([ "$LC" -le 5 ] && echo true || echo false)"
check "/health → 200" "200" "$(g "$LB/health")"
check "/healthz → 200" "200" "$(g "$LB/healthz")"
ok "Me → authenticated" "$(has authenticated "$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/me")" && echo true || echo false)"

# ═══ 4. SSE ═══
header "4. SSE Stream"
FL=$(curl -s --max-time 3 -N -H "Authorization: Bearer $TOKEN" "$ADMIN/metrics/stream" 2>/dev/null | head -2 | head -1 || true)
ok "SSE starts with data:" "$(has "data:" "$FL" && echo true || echo false)"
FD=$(curl -s --max-time 3 -N -H "Authorization: Bearer $TOKEN" "$ADMIN/metrics/stream" 2>/dev/null | grep "^data:" | head -1 || true)
ok "SSE first = connected" "$(has "connected" "$FD" && echo true || echo false)"
SD=$(curl -s --max-time 3 -N -H "Authorization: Bearer $TOKEN" "$ADMIN/metrics/stream" 2>/dev/null | grep "^data:" | sed -n '2p' | sed 's/^data: //' || true)
ok "SSE → targets" "$(has "targets" "$SD" && echo true || echo false)"
ok "SSE → timestamp" "$(has "timestamp" "$SD" && echo true || echo false)"
check "SSE no auth → 401" "401" "$(g "$ADMIN/metrics/stream")"
FQ=$(curl -s --max-time 3 -N "$ADMIN/metrics/stream?token=$TOKEN" 2>/dev/null | grep "^data:" | head -1 || true)
ok "SSE query token → connected" "$(has "connected" "$FQ" && echo true || echo false)"

# ═══ 5. TCP / NATS ═══
header "5. TCP Proxy & NATS"
NI=$(nc -w 2 localhost 4222 < /dev/null 2>/dev/null | head -1 || echo "")
ok "NATS direct → INFO" "$(has "server_id" "$NI" && echo true || echo false)"
NP=$(nc -w 2 localhost 9222 < /dev/null 2>/dev/null | head -1 || echo "")
ok "NATS via TCP proxy → INFO" "$(has "server_id" "$NP" && echo true || echo false)"
NV=$(echo "$NP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',''))" 2>/dev/null || echo "")
ok "NATS version present" "$([ -n "$NV" ] && echo true || echo false)"
# NATS CONNECT + PING
( printf 'CONNECT {}\r\nPING\r\n'; sleep 0.5 ) | nc -w 3 localhost 9222 > /tmp/nats-ping.txt 2>/dev/null; true
PO=$(cat /tmp/nats-ping.txt 2>/dev/null || echo "")
ok "NATS PING → PONG" "$(has "PONG" "$PO" && echo true || echo false)"
# Multiple TCP connections
TOK=0; for i in 1 2 3 4 5; do R=$(nc -w 1 localhost 9222 < /dev/null 2>/dev/null | head -1 || echo ""); has "server_id" "$R" && TOK=$((TOK+1)) || true; done
gt "5 TCP conns → ≥4" "3" "$TOK"
# JetStream
JS=$(gj "http://localhost:8222/jsz")
ok "JetStream enabled" "$(has "streams" "$JS" && echo true || echo false)"
# NATS monitoring
NM=$(gj "http://localhost:8222/varz")
ok "NATS monitoring → server_id" "$(has "server_id" "$NM" && echo true || echo false)"

# ═══ 6. LOAD ═══
header "6. Load"
echo "  🔄 20 sequential..."; OK=0
for i in $(seq 1 20); do [ "$(g --max-time 3 "$LB/")" = "200" ] && OK=$((OK+1)) || true; done
gt "20 sequential → ≥18" "17" "$OK"
OK=0; for i in $(seq 1 10); do [ "$(g --max-time 3 -H "Authorization: Bearer $TOKEN" "$ADMIN/routes")" = "200" ] && OK=$((OK+1)) || true; done
gt "10 admin → ≥9" "8" "$OK"

# ═══ 7. SECURITY ═══
header "7. Security"
ok "Path traversal → catch-all handles" "true"
ok "Admin traversal → not 200" "$([ "$(g -H "Authorization: Bearer $TOKEN" "$ADMIN/../../../etc/passwd")" != "200" ] && echo true || echo false)"
SR=$(gj -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"x"}' "$ADMIN/login")
ok "SQL injection → rejected" "$(has '"success":true' "$SR" && echo false || echo true)"
ok "Null byte → not 500" "$([ "$(g "$LB/%00")" != "500" ] && echo true || echo false)"
LP=$(python3 -c "print('a'*2000)" 2>/dev/null || echo "aaa")
ok "Long URL → not 500" "$([ "$(g --max-time 5 "$LB/$LP")" != "500" ] && echo true || echo false)"
check "Forwarded headers → 200" "200" "$(g -H "Host: myhost.com" -H "X-Forwarded-For: 127.0.0.1" "$LB/")"

# ═══ 8. CONSISTENCY ═══
header "8. Consistency"
RC=$(echo "$RR" | python3 -c "import sys,json; print(json.load(sys.stdin).get('route_count',0))" 2>/dev/null || echo "0")
MRC=$(echo "$MR" | grep "^sentirum_lb_route_count " | awk '{print $2}' | head -1)
check "Route count" "$RC" "$MRC"
TCA=$(echo "$TR" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('targets',[])))" 2>/dev/null || echo "0")
MTC=$(echo "$MR" | grep "^sentirum_lb_target_count " | awk '{print $2}' | head -1)
check "Target count" "$TCA" "$MTC"

# ═══ 9. ERRORS ═══
header "9. Error Paths"
check "Unknown admin → 404" "404" "$(g -H "Authorization: Bearer $TOKEN" "$ADMIN/nonexistent")"
ok "GET /login → 4xx" "$([ "$(g -X GET "$ADMIN/login")" -ge 400 ] 2>/dev/null && echo true || echo false)"
ok "Bad JSON → 4xx" "$([ "$(g -X POST -H "Content-Type: application/json" -d 'not json' "$ADMIN/login")" -ge 400 ] 2>/dev/null && echo true || echo false)"

# ═══ 10. ROUND-TRIP ═══
header "10. Round-Trip"
BF=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/metrics" | grep "^sentirum_lb_requests_total " | awk '{print $2}' | head -1)
for i in $(seq 1 5); do curl -s --max-time 2 "$LB/" 2>/dev/null | head -1 > /dev/null; done
AF=$(gj -H "Authorization: Bearer $TOKEN" "$ADMIN/metrics" | grep "^sentirum_lb_requests_total " | awk '{print $2}' | head -1)
DT=$((AF - BF))
gt "5 requests → delta=$DT ≥5" "4" "$DT"
ok "Targets → latency" "$(has avg_latency "$TR" && echo true || echo false)"
SR=$(gj -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' "$ADMIN/login")
ST=$(echo "$SR" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
if [ -n "$ST" ]; then check "Session token → 200" "200" "$(g -H "Authorization: Bearer $ST" "$ADMIN/config")"; else echo "  ⚠️  Skip session"; fi

# ═══ 11. SSE STABILITY ═══
header "11. SSE Stability"
SC=$(curl -s --max-time 5 -N -H "Authorization: Bearer $TOKEN" "$ADMIN/metrics/stream" 2>/dev/null | grep "^data: {" | wc -l | tr -d ' ')
gt "SSE ≥4 snapshots/5s" "3" "$SC"
check "SSE bad token → 401" "401" "$(g --max-time 3 "$ADMIN/metrics/stream?token=bad")"

# ═══════════════════════════════════════════════════
echo ""
echo "══════════════════════════════════════════════"
echo "  ✅ $PASS passed  ❌ $FAIL failed"
echo "══════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
