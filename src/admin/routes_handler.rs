//! Route inspection and dynamic route management handlers.

use super::api::AdminState;
use crate::route::parser::parse_route_commands;
use axum::extract::{Json, State};
use serde::Deserialize;

/// Request body for adding routes dynamically.
#[derive(Debug, Deserialize)]
pub(super) struct AddRoutesRequest {
    commands: String,
}

pub(super) async fn routes_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    let table = state.route_table.get();
    let route_count = table.route_count();
    let target_count = table.target_count();
    let hosts = table.hosts();
    let config = state.config.load();
    let default_matcher = config.proxy.matcher.clone();
    drop(config);

    let routes_info: Vec<serde_json::Value> = hosts
        .iter()
        .flat_map(|host| {
            let routes = table.get_routes(host).unwrap();
            let default_matcher = default_matcher.clone();
            routes.iter().map(move |route| {
                let targets: Vec<serde_json::Value> = route
                    .targets
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "service": t.service,
                            "url": t.url,
                            "weight": t.weight,
                            "protocol": format!("{:?}", t.upstream_protocol()).to_lowercase(),
                            "tls": t.upstream_tls(),
                            "http2": t.requires_http2(),
                            "websocket": t.is_websocket(),
                            "opts": t.opts,
                        })
                    })
                    .collect();

                let matcher = if route.glob.is_some() {
                    "glob".to_string()
                } else {
                    default_matcher.clone()
                };

                serde_json::json!({
                    "host": host,
                    "path": route.path,
                    "matcher": matcher,
                    "targets": targets,
                })
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "route_count": route_count,
        "target_count": target_count,
        "routes": routes_info,
    }))
}

pub(super) async fn routes_add_handler(
    State(state): State<AdminState>,
    Json(body): Json<AddRoutesRequest>,
) -> axum::Json<serde_json::Value> {
    if body.commands.trim().is_empty() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "No route commands provided"
        }));
    }

    let new_defs = parse_route_commands(&body.commands);
    if new_defs.is_empty() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "No valid route commands parsed from input"
        }));
    }

    let added_count = new_defs.len();
    let added_services: Vec<String> = new_defs.iter().map(|d| d.service.clone()).collect();

    state.route_table.append_static(new_defs);

    tracing::info!(
        count = added_count,
        services = ?added_services,
        "Dynamically added routes via admin API"
    );

    let metrics = crate::metrics::prometheus::global();
    metrics.record_route_reload("static");

    axum::Json(serde_json::json!({
        "success": true,
        "added": added_count,
        "services": added_services,
    }))
}

pub(super) async fn routes_static_clear_handler(
    State(state): State<AdminState>,
) -> axum::Json<serde_json::Value> {
    state.route_table.load_static(&[]);
    tracing::info!("Cleared all static routes via admin API");

    axum::Json(serde_json::json!({
        "success": true,
        "message": "All static routes cleared"
    }))
}
