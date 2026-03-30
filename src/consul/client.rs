//! Consul HTTP client for Sentirum LB
//! Implements KV watching and service discovery using Consul's REST API

use crate::config::ConsulConfig as AppConsulConfig;
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, Url};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

/// Consul client configuration
#[derive(Clone)]
pub struct ConsulConfig {
    /// Consul agent address (e.g., "127.0.0.1:8500")
    pub address: String,
    /// URL scheme (http or https)
    pub scheme: String,
    /// ACL token (optional, masked in Debug)
    pub token: Option<String>,
    /// KV prefix path for routes
    pub kv_prefix: String,
    /// Tag prefix for service routes (e.g., "urlprefix-")
    pub tag_prefix: String,
    /// Allow stale reads for better performance
    pub allow_stale: bool,
    /// Require consistent reads
    pub require_consistent: bool,
    /// Maximum duration for blocking queries when index is provided
    pub query_wait: String,
}

impl std::fmt::Debug for ConsulConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsulConfig")
            .field("address", &self.address)
            .field("scheme", &self.scheme)
            .field("token", &self.token.as_ref().map(|_| "***"))
            .field("kv_prefix", &self.kv_prefix)
            .field("tag_prefix", &self.tag_prefix)
            .field("allow_stale", &self.allow_stale)
            .field("require_consistent", &self.require_consistent)
            .field("query_wait", &self.query_wait)
            .finish()
    }
}

impl From<&AppConsulConfig> for ConsulConfig {
    fn from(cfg: &AppConsulConfig) -> Self {
        Self {
            address: cfg.address.clone(),
            scheme: cfg.scheme.clone(),
            token: if cfg.token.is_empty() { None } else { Some(cfg.token.clone()) },
            kv_prefix: cfg.kv_prefix.clone(),
            tag_prefix: cfg.tag_prefix.clone(),
            allow_stale: true,
            require_consistent: false,
            query_wait: if cfg.poll_interval.trim().is_empty() {
                "5m".to_string()
            } else {
                cfg.poll_interval.clone()
            },
        }
    }
}

impl Default for ConsulConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:8500".to_string(),
            scheme: "http".to_string(),
            token: None,
            kv_prefix: "/sentirum-lb/routes".to_string(),
            tag_prefix: "urlprefix-".to_string(),
            allow_stale: true,
            require_consistent: false,
            query_wait: "5m".to_string(),
        }
    }
}

/// Consul client for interacting with Consul's HTTP API
#[derive(Debug, Clone)]
pub struct ConsulClient {
    client: Client,
    config: ConsulConfig,
    base_url: String,
}

impl ConsulClient {
    fn kv_watch_url(&self, path: &str, index: u64) -> Result<Url, ConsulError> {
        let mut url = Url::parse(&format!(
            "{}/v1/kv/{}",
            self.base_url,
            path.trim_start_matches('/')
        ))
        .map_err(|e| ConsulError::ClientError(e.to_string()))?;

        {
            let mut query = url.query_pairs_mut();
            query.append_pair("recurse", "true");
            if self.config.allow_stale {
                query.append_pair("stale", "true");
            }
            if self.config.require_consistent {
                query.append_pair("consistent", "true");
            }
            if index > 0 {
                query.append_pair("index", &index.to_string());
                query.append_pair("wait", &self.config.query_wait);
            }
        }

        Ok(url)
    }

    fn health_checks_url(&self, index: u64) -> Result<Url, ConsulError> {
        let mut url = Url::parse(&format!("{}/v1/health/state/any", self.base_url))
            .map_err(|e| ConsulError::ClientError(e.to_string()))?;

        {
            let mut query = url.query_pairs_mut();
            if self.config.allow_stale {
                query.append_pair("stale", "true");
            }
            if self.config.require_consistent {
                query.append_pair("consistent", "true");
            }
            if index > 0 {
                query.append_pair("index", &index.to_string());
                query.append_pair("wait", &self.config.query_wait);
            }
        }

        Ok(url)
    }

    /// Create a new Consul client
    pub fn new(config: ConsulConfig) -> Result<Self, ConsulError> {
        let query_wait = crate::config::Config::parse_duration(&config.query_wait);
        let query_wait = if query_wait.is_zero() { Duration::from_secs(300) } else { query_wait };
        let http_timeout = query_wait + Duration::from_secs(10);

        let client = Client::builder()
            .timeout(http_timeout)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| ConsulError::ClientError(e.to_string()))?;

        let base_url = format!("{}://{}", config.scheme, config.address);

        Ok(Self {
            client,
            config,
            base_url,
        })
    }

    /// Get the datacenter from Consul agent
    pub async fn get_datacenter(&self) -> Result<String, ConsulError> {
        #[derive(Deserialize)]
        #[allow(non_snake_case)]
        struct AgentSelf {
            Config: HashMap<String, serde_json::Value>,
        }

        let url = format!("{}/v1/agent/self", self.base_url);
        let mut request = self.client.get(&url);

        if let Some(token) = &self.config.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await?;
        let agent_self: AgentSelf = response.json().await?;

        let dc = agent_self
            .Config
            .get("Datacenter")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ConsulError::ParseError("Datacenter not found".to_string()))?;

        Ok(dc.to_string())
    }

    /// Watch Consul KV for route configuration changes (blocking query)
    /// Returns (value, index) on change
    pub async fn watch_kv(
        &self,
        path: &str,
        index: u64,
    ) -> Result<(Option<String>, u64), ConsulError> {
        let url = self.kv_watch_url(path, index)?;
        let mut request = self.client.get(url);

        if let Some(token) = &self.config.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await?;

        // Check for Consul index in response headers
        let new_index: u64 = response
            .headers()
            .get("X-Consul-Index")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        #[derive(Deserialize)]
        #[allow(non_snake_case)]
        struct KVPair {
            Key: String,
            Value: Option<String>,
        }

        let kv_pairs: Vec<KVPair> = response.json().await?;

        if kv_pairs.is_empty() {
            return Ok((None, new_index));
        }

        // Combine all KV values with key separators (like Fabio)
        let mut parts = Vec::new();
        for kv in kv_pairs {
            let raw_value = kv.Value.unwrap_or_default();
            if raw_value.trim().is_empty() {
                continue;
            }

            let decoded = match STANDARD.decode(raw_value.trim()) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(key = %kv.Key, error = %e, "Failed to base64 decode KV value; skipping");
                    continue;
                }
            };
            let decoded_text = match String::from_utf8(decoded) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(key = %kv.Key, error = %e, "Failed to UTF-8 decode KV value; skipping");
                    continue;
                }
            };
            let trimmed = decoded_text.trim();
            if !trimmed.is_empty() {
                parts.push(format!("# --- {}\n{}", kv.Key, trimmed));
            }
        }

        let combined = if parts.is_empty() {
            None
        } else {
            Some(parts.join("\n\n"))
        };

        Ok((combined, new_index))
    }

    /// Get health checks for all services
    pub async fn get_health_checks(&self, index: u64) -> Result<(Vec<HealthCheck>, u64), ConsulError> {
        let url = self.health_checks_url(index)?;
        let mut request = self.client.get(url);

        if let Some(token) = &self.config.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await?;

        let new_index: u64 = response
            .headers()
            .get("X-Consul-Index")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let checks: Vec<HealthCheck> = response.json().await?;

        Ok((checks, new_index))
    }

    /// Get service instances from catalog
    pub async fn get_catalog_service(
        &self,
        service_name: &str,
    ) -> Result<Vec<CatalogService>, ConsulError> {
        let mut url = Url::parse(&format!("{}/v1/catalog/service/{}", self.base_url, service_name))
            .map_err(|e| ConsulError::ClientError(e.to_string()))?;

        {
            let mut query = url.query_pairs_mut();
            if self.config.allow_stale {
                query.append_pair("stale", "true");
            }
            if self.config.require_consistent {
                query.append_pair("consistent", "true");
            }
        }

        let mut request = self.client.get(url);

        if let Some(token) = &self.config.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await?;
        let services: Vec<CatalogService> = response.json().await?;

        Ok(services)
    }

    /// Get all keys under a KV path
    pub async fn list_keys(&self, path: &str) -> Result<Vec<String>, ConsulError> {
        let mut url = Url::parse(&format!(
            "{}/v1/kv/{}",
            self.base_url,
            path.trim_start_matches('/'),
        ))
        .map_err(|e| ConsulError::ClientError(e.to_string()))?;

        {
            let mut query = url.query_pairs_mut();
            query.append_pair("keys", "true");
            if self.config.allow_stale {
                query.append_pair("stale", "true");
            }
            if self.config.require_consistent {
                query.append_pair("consistent", "true");
            }
        }

        let mut request = self.client.get(url);

        if let Some(token) = &self.config.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await?;
        let keys: Vec<String> = response.json().await?;

        Ok(keys)
    }
}

/// Health check from Consul
#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheck {
    #[serde(default, alias = "Node")]
    pub node: String,
    #[serde(default, alias = "CheckID")]
    pub check_id: String,
    #[serde(default, alias = "Name")]
    pub name: String,
    #[serde(default, alias = "Status")]
    pub status: String,
    #[serde(default, alias = "ServiceName")]
    pub service_name: String,
    #[serde(default, alias = "ServiceID")]
    pub service_id: String,
    #[serde(default, alias = "ServiceTags")]
    pub service_tags: Vec<String>,
}

/// Service entry from Consul catalog
#[derive(Debug, Deserialize, Clone)]
pub struct CatalogService {
    #[serde(default, alias = "ServiceID")]
    pub id: String,
    #[serde(default, alias = "Node")]
    pub node: String,
    #[serde(default, alias = "Address")]
    pub address: String,
    #[serde(default, alias = "ServiceAddress")]
    pub service_address: String,
    #[serde(default, alias = "ServicePort")]
    pub service_port: u16,
    #[serde(default, alias = "ServiceTags")]
    pub service_tags: Vec<String>,
    #[serde(default, alias = "ServiceMeta")]
    pub service_meta: HashMap<String, String>,
}

/// Consul error types
#[derive(Debug, thiserror::Error)]
pub enum ConsulError {
    #[error("HTTP client error: {0}")]
    ClientError(String),

    #[error("Consul API error: {0}")]
    ApiError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),
}

/// Health status constants
pub const HEALTH_STATUS_PASSING: &str = "passing";
pub const HEALTH_STATUS_WARNING: &str = "warning";
pub const HEALTH_STATUS_CRITICAL: &str = "critical";

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client() -> ConsulClient {
        ConsulClient::new(ConsulConfig::default()).expect("client should build")
    }

    #[test]
    fn watch_kv_uses_query_params_for_blocking() {
        let client = make_client();
        let url = client.kv_watch_url("/sentirum-lb/routes", 42).unwrap();
        let query = url.query().unwrap_or_default();

        assert!(query.contains("recurse=true"));
        assert!(query.contains("stale=true"));
        assert!(!query.contains("consistent="));
        assert!(query.contains("index=42"));
        assert!(query.contains("wait=5m"));
    }

    #[test]
    fn initial_watch_does_not_block() {
        let client = make_client();
        let kv_url = client.kv_watch_url("/sentirum-lb/routes", 0).unwrap();
        let health_url = client.health_checks_url(0).unwrap();

        let kv_query = kv_url.query().unwrap_or_default();
        let health_query = health_url.query().unwrap_or_default();

        assert!(!kv_query.contains("index="));
        assert!(!kv_query.contains("wait="));
        assert!(!health_query.contains("index="));
        assert!(!health_query.contains("wait="));
    }
}
