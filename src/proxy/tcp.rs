//! TCP proxy support.
//!
//! TCP proxying will be implemented in Phase 5.
//! This module provides the scaffolding for future TCP stream proxy support,
//! which allows proxying raw TCP connections (not just HTTP) based on routing rules.
//!
//! Target configuration:
//! - `opts "proto=tcp"` enables TCP proxy mode
//! - The route will forward raw TCP traffic instead of HTTP

/// TCP proxy configuration placeholder
#[derive(Debug, Clone, Default)]
pub struct TcpProxyConfig {
    /// Whether TCP proxy is enabled
    pub enabled: bool,
}
