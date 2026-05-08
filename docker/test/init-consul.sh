#!/bin/bash
# Initialize Consul with test data for sentirum-lb
set -euo pipefail

CONSUL="http://localhost:8500"
echo "⏳ Waiting for Consul to be ready..."
until curl -sf "${CONSUL}/v1/status/leader" > /dev/null 2>&1; do
  sleep 1
done
echo "✅ Consul is ready"

# ─── Register mock services with urlprefix- tags ────────────────────
echo ""
echo "📦 Registering services..."

# web-blue service
curl -sf -X PUT "${CONSUL}/v1/agent/service/register" -d '{
  "ID": "web-blue-1",
  "Name": "web-blue",
  "Address": "upstream-web-blue",
  "Port": 8080,
  "Tags": ["urlprefix-myhost.com/ proto=http"],
  "Check": {
    "HTTP": "http://upstream-web-blue:8080/",
    "Interval": "5s",
    "Timeout": "2s"
  }
}' > /dev/null && echo "  ✅ web-blue registered"

# web-green service
curl -sf -X PUT "${CONSUL}/v1/agent/service/register" -d '{
  "ID": "web-green-1",
  "Name": "web-green",
  "Address": "upstream-web-green",
  "Port": 8081,
  "Tags": ["urlprefix-myhost.com/ proto=http"],
  "Check": {
    "HTTP": "http://upstream-web-green:8081/",
    "Interval": "5s",
    "Timeout": "2s"
  }
}' > /dev/null && echo "  ✅ web-green registered"

# api service
curl -sf -X PUT "${CONSUL}/v1/agent/service/register" -d '{
  "ID": "api-1",
  "Name": "api",
  "Address": "upstream-api",
  "Port": 9090,
  "Tags": ["urlprefix-myhost.com/api/ proto=http"],
  "Check": {
    "HTTP": "http://upstream-api:9090/",
    "Interval": "5s",
    "Timeout": "2s"
  }
}' > /dev/null && echo "  ✅ api registered"

# ─── Seed KV routes ─────────────────────────────────────────────────
echo ""
echo "📝 Seeding KV routes..."

curl -sf -X PUT "${CONSUL}/v1/kv/sentirum-lb/routes/routes" -d '
route add kv-service kv.example.com/ http://upstream-api:9090/
route add kv-api kv.example.com/api/ http://upstream-api:9090/ opts "strip=/api"
' > /dev/null && echo "  ✅ KV routes seeded"

# ─── Summary ────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  Consul test data initialized!"
echo ""
echo "  Services (service discovery):"
echo "    web-blue   → upstream-web-blue:8080  (urlprefix-myhost.com/)"
echo "    web-green  → upstream-web-green:8081 (urlprefix-myhost.com/)"
echo "    api        → upstream-api:9090       (urlprefix-myhost.com/api/)"
echo ""
echo "  KV routes:"
echo "    kv.example.com/     → upstream-api:9090"
echo "    kv.example.com/api/ → upstream-api:9090 (strip=/api)"
echo "═══════════════════════════════════════════════════"
