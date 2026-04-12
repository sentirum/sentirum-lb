use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Command type for route operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RouteCmd {
    Add,
    Del,
    Weight,
}

/// Source of a route definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RouteSource {
    #[default]
    Static,
    ConsulKv,
    ConsulService,
}

/// A route definition parsed from route commands.
/// Compatible with Fabio's route format.
///
/// Format: `route add <svc> <src> <dst> [weight <w>] [tags "<t1>,<t2>"] [opts "k1=v1 k2=v2"]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDef {
    /// The command type (add, del, weight)
    pub cmd: RouteCmd,
    /// Service name
    pub service: String,
    /// Source pattern (e.g. "myhost.com/" or "myhost.com/api/")
    pub src: String,
    /// Destination URL (e.g. "http://10.0.0.1:8080/")
    pub dst: String,
    /// Weight for traffic distribution (0 = dynamic)
    #[serde(default)]
    pub weight: f64,
    /// Tags associated with this route
    #[serde(default)]
    pub tags: Vec<String>,
    /// Additional options (strip, prepend, proto, tlsskipverify, host)
    #[serde(default)]
    pub opts: HashMap<String, String>,
    /// Origin of this route definition
    #[serde(default)]
    pub source: RouteSource,
}

impl RouteDef {
    /// Extract the host from the source pattern.
    /// e.g. "myhost.com/api/" -> "myhost.com"
    pub fn src_host(&self) -> &str {
        self.src.split('/').next().unwrap_or("")
    }

    /// Extract the path from the source pattern.
    /// e.g. "myhost.com/api/" -> "/api/"
    pub fn src_path(&self) -> &str {
        let parts: Vec<&str> = self.src.splitn(2, '/').collect();
        if parts.len() > 1 { parts[1] } else { "" }
    }
}
