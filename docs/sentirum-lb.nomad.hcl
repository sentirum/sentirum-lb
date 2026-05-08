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
read_timeout = "3600s"
write_timeout = "3600s"
idle_timeout = "90s"
enable_h2c = true
upstream_h2_max_streams = 128
upstream_h2_ping_interval = ""
pool_size = 128
max_connections = 10000
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
# - Existing connections are not dropped on cert updates; new TLS handshakes use the new snapshot.
# - `/fabio/config` route KV remains optional; if empty, only KV routes are empty, service-tag routes continue.
