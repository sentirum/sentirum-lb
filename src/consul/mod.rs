//! Consul integration module for Sentirum LB
//!
//! Provides Consul KV watching and service discovery for dynamic routing.
//!
//! # Example
//! ```ignore
//! use sentirum_lb::consul::{ConsulClient, ConsulConfig};
//! use sentirum_lb::route::table::RouteTable;
//!
//! # async fn example() {
//! let config = ConsulConfig::default();
//! let client = ConsulClient::new(config.clone()).unwrap();
//! let route_table = RouteTable::new();
//! // Start watching...
//! # }
//! ```

pub mod client;
pub mod watcher;

pub use client::{ConsulClient, ConsulConfig};
pub use watcher::{ConsulWatcher, RouteUpdate};
