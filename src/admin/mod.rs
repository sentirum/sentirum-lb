//! Admin API — dashboard, auth, config, routes, metrics, TLS certs, logs.
//!
//! Submodules handle specific endpoint groups to keep the codebase modular:
//! - `auth`: login/logout/session management
//! - `config_handler`: GET/PUT/reset runtime config
//! - `routes_handler`: GET/POST/DELETE routes
//! - `metrics_handler`: Prometheus metrics, targets, topology
//! - `certs_handler`: TLS cert status and hot-reload
//! - `logs`: in-memory ring buffer and SSE stream

pub mod api;
pub mod auth;
pub mod certs_handler;
pub mod config_handler;
pub mod logs;
pub mod metrics_handler;
pub mod routes_handler;

pub use api::{AdminState, SessionEntry, build_router, run_admin_server};
