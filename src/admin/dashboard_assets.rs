//! Embedded dashboard static assets.
//!
//! Splits the admin dashboard into separate HTML/CSS/JS payloads without
//! requiring a frontend build step. JS modules are concatenated at compile
//! time via `concat!` + `include_str!` — zero runtime overhead.

use axum::http::header::CONTENT_TYPE;
use axum::response::{Html, IntoResponse};

pub async fn dashboard_html() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

pub async fn dashboard_css() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("dashboard.css"),
    )
}

/// Concatenated JS modules — compile-time merged, zero overhead.
///
/// Order matters: state → helpers → events → sidebar → auth → nav →
/// sse → refresh/charts → targets → topology → dns → consul →
/// routes → overview → logs → config → certs → export → init.
pub async fn dashboard_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        concat!(
            include_str!("js/0-state.js"),
            include_str!("js/1-helpers.js"),
            include_str!("js/2-events.js"),
            include_str!("js/3-sidebar.js"),
            include_str!("js/4-auth.js"),
            include_str!("js/5-navigation.js"),
            include_str!("js/6-sse.js"),
            include_str!("js/7-refresh-charts.js"),
            include_str!("js/a-targets.js"),
            include_str!("js/b-topology.js"),
            include_str!("js/c-dns.js"),
            include_str!("js/d-consul.js"),
            include_str!("js/e-routes.js"),
            include_str!("js/f-overview.js"),
            include_str!("js/g-logs.js"),
            include_str!("js/h-config.js"),
            include_str!("js/i-certs.js"),
            include_str!("js/9-export.js"),
            include_str!("js/z-init.js"),
        ),
    )
}
