job "sentirum-lb" {
  datacenters = ["dc1"]
  type        = "system"

  constraint {
    attribute = "${meta.public}"
    value     = "true"
  }

  constraint {
    attribute = "${meta.ingress}"
    value     = "true"
  }

  group "lb" {
    network {
      port "http" {
        static = 80
      }

      port "https" {
        static = 443
      }

      port "admin" {
        static = 9998
      }
    }

    task "sentirum-lb" {
      driver = "docker"

      config {
        image        = "ghcr.io/your-org/sentirum-lb:latest"
        network_mode = "host"
        ports        = ["http", "https", "admin"]
        args         = ["--config", "/app/config.toml"]

        dns_servers        = ["10.101.1.11", "10.101.1.12", "10.101.1.13"]
        dns_search_domains = ["service.consul"]

        volumes = [
          "local/config.toml:/app/config.toml:ro"
        ]
      }

      # Example only. Replace with your own Vault/Nomad variable wiring if needed.
      template {
        destination = "local/config.toml"
        perms       = "0644"
        data = <<EOF
[server]
listen = ":80"
admin_listen = "127.0.0.1:9998"
admin_token = "{{ with nomadVar \"nomad/jobs/sentirum-lb\" }}{{ .admin_token }}{{ end }}"
workers = 0
drain_timeout = "30s"

# Admin users for dashboard login
[[server.admin_users]]
username = "admin"
password = "{{ with nomadVar \"nomad/jobs/sentirum-lb\" }}{{ .admin_password }}{{ end }}"

[consul]
address = "consul.service.consul:8500"
scheme = "http"
token = "{{ with nomadVar \"nomad/jobs/sentirum-lb\" }}{{ .consul_token }}{{ end }}"
kv_prefix = "/fabio/config"
tag_prefix = "urlprefix-"
poll_interval = "5m"
service_discovery = true
kv_watching = true

[proxy]
strategy = "round-robin"
matcher = "prefix"
request_id_header = "X-Request-ID"
no_route_status = 404
connect_timeout = "30s"
# Issue #22: read_timeout is now the *non-streaming* default. Keep it well
# below the CDN/edge origin timeout (Cloudflare ~100s) so the LB fails fast on
# a dead upstream instead of black-holing a POST until the edge gives up (524).
# Long-lived streams use stream_read_timeout below.
read_timeout = "60s"
write_timeout = "3600s"
idle_timeout = "90s"
enable_h2c = true
upstream_h2_max_streams = 128
upstream_h2_ping_interval = ""
pool_size = 128
max_connections = 10000

# TCP keepalive on pooled connections (Issue #22). Detects/evicts silently-dead
# pooled connections before a non-idempotent request is written into them.
# Format: "idle,interval,count". Empty disables.
upstream_tcp_keepalive = "15s,5s,3"
downstream_tcp_keepalive = "15s,5s,3"
# TCP_USER_TIMEOUT (Linux): bounds unacked writes so a black-holed POST fails
# in ~30s instead of waiting on read_timeout. Empty/0 = system default.
upstream_user_timeout = "30s"
# Streaming responses (WebSocket / SSE `text/event-stream` / long-poll) keep a
# long read timeout; non-streaming requests use read_timeout above. Per-route
# override available via the `readtimeout=` target option.
stream_read_timeout = "3600s"

# Circuit breaker
circuit_breaker_enabled = true
circuit_breaker_error_threshold = 50
circuit_breaker_window_size = 100
circuit_breaker_recovery_timeout = 30
circuit_breaker_half_open_max = 3

# Health checking
health_check_interval = "10s"
health_check_timeout = "5s"
health_check_fall = 3
health_check_rise = 2
health_check_path = "/health"

# Rate limiting (per-target)
rate_limit_per_target = 0   # 0 = disabled; set e.g. 100 for 100 req/s
rate_limit_burst = 0

# DNS cache
dns_cache_ttl = 30
dns_negative_cache_ttl = 10

trusted_proxies = [
  # Fill with Cloudflare CIDRs or your trusted ingress hop ranges.
  # "173.245.48.0/20",
  # "103.21.244.0/22",
]

[logging]
level = "info"
format = "json"

[tls]
source = "consul_kv"
listen = ":443"
consul_cert_prefix = "/fabio/cert"
strict_sni = false
require_initial_snapshot = true
client_auth = ""                   # set to "optional" or "required" when enabling mTLS
client_ca_source = ""              # "file" or "consul_kv"
client_ca_path = ""                # file/dir path when client_ca_source=file
client_ca_consul_prefix = ""       # e.g. "/fabio/client-ca" when client_ca_source=consul_kv
client_ca_upgrade_cn = ""          # e.g. "ApiGateway" for Fabio-style CA-upgrade compatibility

# Additional TLS listeners (e.g., mTLS on a separate port)
# [[tls_listeners]]
# listen = ":8443"
# cert_path = "/etc/sentirum-lb/mtls-cert.pem"
# key_path = "/etc/sentirum-lb/mtls-key.pem"
# client_auth = "required"
# client_ca_path = "/etc/sentirum-lb/client-ca.pem"
EOF
      }

      resources {
        cpu    = 1000
        memory = 512
      }

      kill_timeout = "35s"

      service {
        name = "sentirum-lb-http"
        port = "http"
        tags = ["ingress", "loadbalancer", "sentirum-lb", "http"]

        check {
          type     = "http"
          path     = "/health"
          port     = "http"
          interval = "10s"
          timeout  = "2s"
        }
      }

      service {
        name = "sentirum-lb-https"
        port = "https"
        tags = ["ingress", "loadbalancer", "sentirum-lb", "https"]

        check {
          type     = "tcp"
          port     = "https"
          interval = "10s"
          timeout  = "2s"
        }
      }

      service {
        name = "sentirum-lb-admin"
        port = "admin"
        tags = ["admin", "metrics", "sentirum-lb"]

        check {
          type     = "http"
          path     = "/admin/health"
          port     = "admin"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }
}

# Notes
# - This job keeps the Fabio route model: service tags still use `urlprefix-...`.
# - Downstream HTTPS certs are loaded dynamically from Consul KV under `/fabio/cert/*`.
# - File-based cert hot-reload also supported via `FileCertWatcherService` (30s poll).
# - Manual cert reload: `POST /admin/certs/reload`
# - Existing connections are not dropped on cert updates; new TLS handshakes use the new snapshot.
# - Optional downstream mTLS can be enabled with `tls.client_auth` + client CA settings.
# - Additional TLS listeners can be configured via `[[tls_listeners]]` array.
# - `/fabio/config` route KV remains optional; if empty, only KV routes are empty, service-tag routes continue.
# - Runtime config hot-reload via `PUT /admin/config` (no restart needed for strategy, timeouts, CB, HC, rate limits).
# - Live route addition via `POST /admin/routes` (Fabio-style commands).
