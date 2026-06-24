use super::Config;

impl Config {
    pub fn validate(&self) -> Option<String> {
        let mut errors = Vec::new();

        validate_duration_field(
            &mut errors,
            "server.drain_timeout",
            &self.server.drain_timeout,
            false,
        );
        validate_duration_field(
            &mut errors,
            "consul.poll_interval",
            &self.consul.poll_interval,
            true,
        );
        validate_duration_field(
            &mut errors,
            "proxy.connect_timeout",
            &self.proxy.connect_timeout,
            true,
        );
        validate_duration_field(
            &mut errors,
            "proxy.read_timeout",
            &self.proxy.read_timeout,
            true,
        );
        validate_duration_field(
            &mut errors,
            "proxy.write_timeout",
            &self.proxy.write_timeout,
            true,
        );
        validate_duration_field(
            &mut errors,
            "proxy.idle_timeout",
            &self.proxy.idle_timeout,
            true,
        );
        if !self.proxy.upstream_h2_ping_interval.trim().is_empty() {
            validate_duration_field(
                &mut errors,
                "proxy.upstream_h2_ping_interval",
                &self.proxy.upstream_h2_ping_interval,
                true,
            );
        }
        validate_duration_field(
            &mut errors,
            "proxy.health_check_interval",
            &self.proxy.health_check_interval,
            true,
        );
        validate_duration_field(
            &mut errors,
            "proxy.health_check_timeout",
            &self.proxy.health_check_timeout,
            true,
        );
        validate_duration_field(&mut errors, "tcp.refresh", &self.tcp.refresh, true);

        // Streaming read timeout is optional; validate only when set.
        if !self.proxy.stream_read_timeout.trim().is_empty() {
            validate_duration_field(
                &mut errors,
                "proxy.stream_read_timeout",
                &self.proxy.stream_read_timeout,
                true,
            );
        }
        // upstream_user_timeout is optional (empty/0 = system default).
        if !self.proxy.upstream_user_timeout.trim().is_empty() {
            validate_duration_field(
                &mut errors,
                "proxy.upstream_user_timeout",
                &self.proxy.upstream_user_timeout,
                true,
            );
        }
        // TCP keepalive specs: empty disables; otherwise must be 'idle,interval,count'.
        validate_keepalive_field(
            &mut errors,
            "proxy.upstream_tcp_keepalive",
            &self.proxy.upstream_tcp_keepalive,
        );
        validate_keepalive_field(
            &mut errors,
            "proxy.downstream_tcp_keepalive",
            &self.proxy.downstream_tcp_keepalive,
        );

        // Validate circuit breaker threshold (0-100)
        if self.proxy.circuit_breaker_error_threshold > 100 {
            errors.push(format!(
                "circuit_breaker_error_threshold must be 0-100, got {}",
                self.proxy.circuit_breaker_error_threshold
            ));
        }

        // Validate circuit breaker window size
        if self.proxy.circuit_breaker_window_size == 0 {
            errors.push("circuit_breaker_window_size must be > 0".to_string());
        }

        // Validate circuit breaker recovery timeout
        if self.proxy.circuit_breaker_recovery_timeout == 0 {
            errors.push("circuit_breaker_recovery_timeout must be > 0".to_string());
        }

        // Validate circuit breaker half-open max
        if self.proxy.circuit_breaker_half_open_max == 0 {
            errors.push("circuit_breaker_half_open_max must be > 0".to_string());
        }

        // Validate DNS cache TTL
        if self.proxy.dns_cache_ttl > 3600 {
            errors.push(format!(
                "dns_cache_ttl should be <= 3600 (1 hour), got {} seconds",
                self.proxy.dns_cache_ttl
            ));
        }

        // Validate DNS negative cache TTL
        if self.proxy.dns_negative_cache_ttl > 300 {
            errors.push(format!(
                "dns_negative_cache_ttl should be <= 300 (5 min), got {} seconds",
                self.proxy.dns_negative_cache_ttl
            ));
        }

        // Validate proxy.matcher against the supported set. Unknown values would
        // otherwise silently fall back to prefix matching (MatcherKind::from_config),
        // broadening routes and potentially over-exposing backends with no signal.
        if !matches!(
            self.proxy.matcher.as_str(),
            "" | "prefix" | "iprefix" | "glob" | "exact"
        ) {
            errors.push(format!(
                "proxy.matcher must be one of prefix|iprefix|glob|exact, got '{}'",
                self.proxy.matcher
            ));
        }

        // Validate proxy.strategy. Unknown values silently fall back to round-robin.
        if !matches!(
            self.proxy.strategy.as_str(),
            "" | "round-robin" | "rr" | "random" | "rnd" | "least-connections" | "lc"
        ) {
            errors.push(format!(
                "proxy.strategy must be one of round-robin|random|least-connections, got '{}'",
                self.proxy.strategy
            ));
        }

        // Health-check debounce counts must be >= 1; 0 makes a single probe flip
        // health, defeating the consecutive-sample debounce.
        if self.proxy.health_check_rise == 0 {
            errors.push("proxy.health_check_rise must be >= 1".to_string());
        }
        if self.proxy.health_check_fall == 0 {
            errors.push("proxy.health_check_fall must be >= 1".to_string());
        }

        // no_route_status must be a valid HTTP status code.
        if !(100..=599).contains(&self.proxy.no_route_status) {
            errors.push(format!(
                "proxy.no_route_status must be a valid HTTP status (100-599), got {}",
                self.proxy.no_route_status
            ));
        }

        // request_id_header, when set, must be a valid HTTP header name — otherwise
        // the per-request insert_header would error and fail all proxying.
        if !self.proxy.request_id_header.is_empty()
            && self
                .proxy
                .request_id_header
                .parse::<http::header::HeaderName>()
                .is_err()
        {
            errors.push(format!(
                "proxy.request_id_header is not a valid HTTP header name: '{}'",
                self.proxy.request_id_header
            ));
        }

        // Validate trusted_proxies CIDR format
        for cidr in &self.proxy.trusted_proxies {
            if let Err(e) = validate_cidr(cidr) {
                errors.push(format!("Invalid CIDR '{}': {}", cidr, e));
            }
        }

        // Validate health_check_path starts with '/' and doesn't contain traversal
        if !self.proxy.health_check_path.starts_with('/') {
            errors.push(format!(
                "health_check_path must start with '/', got '{}'",
                self.proxy.health_check_path
            ));
        }
        if self.proxy.health_check_path.contains("..") {
            errors.push(format!(
                "health_check_path must not contain '..' (path traversal), got '{}'",
                self.proxy.health_check_path
            ));
        }

        // Validate admin token length (security warning)
        if !self.server.admin_token.is_empty() && self.server.admin_token.len() < 16 {
            tracing::warn!(
                "admin_token is {} characters, recommend >= 16 for security",
                self.server.admin_token.len()
            );
        }

        // Validate TLS cert path when source=file
        if self.tls.source == "file" {
            if self.tls.cert_path.is_empty() {
                errors.push("tls.cert_path required when tls.source='file'".to_string());
            }
            if self.tls.key_path.is_empty() {
                errors.push("tls.key_path required when tls.source='file'".to_string());
            }
        }

        // Validate consul_cert_prefix format
        if !self.tls.consul_cert_prefix.is_empty() && !self.tls.consul_cert_prefix.starts_with('/')
        {
            errors.push("tls.consul_cert_prefix must start with '/'".to_string());
        }

        // Validate client_auth values
        if !self.tls.client_auth.is_empty()
            && self.tls.client_auth != "optional"
            && self.tls.client_auth != "required"
        {
            errors.push("tls.client_auth must be 'optional', 'required', or empty".to_string());
        }

        // Validate additional TLS listeners
        for (i, listener) in self.tls_listeners.iter().enumerate() {
            let tag = format!("tls_listeners[{}]", i);

            // Must have a listen address
            if listener.listen.trim().is_empty() {
                errors.push(format!(
                    "{tag}.listen is required for additional TLS listeners"
                ));
            }

            // Validate source
            if listener.source == "file" {
                if listener.cert_path.is_empty() {
                    errors.push(format!("{tag}.cert_path required when {tag}.source='file'"));
                }
                if listener.key_path.is_empty() {
                    errors.push(format!("{tag}.key_path required when {tag}.source='file'"));
                }
            }

            // Validate client_auth values
            if !listener.client_auth.is_empty()
                && listener.client_auth != "optional"
                && listener.client_auth != "required"
            {
                errors.push(format!(
                    "{tag}.client_auth must be 'optional', 'required', or empty"
                ));
            }

            // Validate consul_cert_prefix
            if !listener.consul_cert_prefix.is_empty()
                && !listener.consul_cert_prefix.starts_with('/')
            {
                errors.push(format!("{tag}.consul_cert_prefix must start with '/'"));
            }

            // Check for duplicate listen addresses
            if listener.listen == self.tls.listen {
                errors.push(format!(
                    "{tag}.listen '{}' conflicts with primary [tls].listen",
                    listener.listen
                ));
            }
            for (j, prev) in self.tls_listeners[..i].iter().enumerate() {
                if listener.listen == prev.listen {
                    errors.push(format!(
                        "{tag}.listen '{}' conflicts with tls_listeners[{j}].listen",
                        listener.listen
                    ));
                }
            }
        }

        // Validate workers
        if self.server.workers > 256 {
            errors.push(format!(
                "workers should be <= 256, got {} (consider 0 for auto)",
                self.server.workers
            ));
        }

        // Validate upstream_h2_max_streams
        if self.proxy.upstream_h2_max_streams > 1000 {
            errors.push(format!(
                "upstream_h2_max_streams should be <= 1000, got {}",
                self.proxy.upstream_h2_max_streams
            ));
        }

        if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        }
    }
}

/// Validate a TCP keepalive spec. Empty/blank disables keepalive (valid).
/// Otherwise must be `idle,interval,count` with valid durations and a positive
/// integer count.
fn validate_keepalive_field(errors: &mut Vec<String>, name: &str, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() != 3 {
        errors.push(format!(
            "{name} must be 'idle,interval,count' (e.g. '15s,5s,3') or empty, got '{trimmed}'"
        ));
        return;
    }
    if Config::parse_optional_duration(parts[0]).is_none_or(|d| d.is_zero()) {
        errors.push(format!(
            "{name} idle must be a positive duration, got '{}'",
            parts[0]
        ));
    }
    if Config::parse_optional_duration(parts[1]).is_none_or(|d| d.is_zero()) {
        errors.push(format!(
            "{name} interval must be a positive duration, got '{}'",
            parts[1]
        ));
    }
    if parts[2].parse::<usize>().ok().filter(|c| *c > 0).is_none() {
        errors.push(format!(
            "{name} count must be a positive integer, got '{}'",
            parts[2]
        ));
    }
}

fn validate_duration_field(errors: &mut Vec<String>, name: &str, value: &str, allow_zero: bool) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        errors.push(format!("{name} must not be empty"));
        return;
    }

    match Config::parse_optional_duration(trimmed) {
        Some(duration) if allow_zero || !duration.is_zero() => {}
        Some(_) => errors.push(format!("{name} must be > 0, got {trimmed}")),
        None => errors.push(format!(
            "{name} has invalid duration '{trimmed}' (expected e.g. 150ms, 5s, 2m)"
        )),
    }
}

pub(crate) fn validate_cidr(cidr: &str) -> Result<(), String> {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return Err("empty CIDR".to_string());
    }

    let (ip, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("CIDR '{}' missing '/' separator", cidr))?;

    // Validate IP part
    ip.parse::<std::net::IpAddr>()
        .map_err(|e| format!("invalid IP '{}': {}", ip, e))?;

    // Validate prefix
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| format!("prefix '{}' not a number", prefix_str))?;

    // Check prefix range for the IP family
    let ip_is_v4 = ip.contains('.') && !ip.contains(':');
    let max_prefix = if ip_is_v4 { 32 } else { 128 };

    if prefix > max_prefix {
        return Err(format!(
            "prefix {} > {} for {}",
            prefix,
            max_prefix,
            if ip_is_v4 { "IPv4" } else { "IPv6" }
        ));
    }

    Ok(())
}
