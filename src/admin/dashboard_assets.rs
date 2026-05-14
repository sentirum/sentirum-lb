//! Embedded dashboard static assets.
//!
//! Splits the admin dashboard into separate HTML/CSS/JS payloads without
//! requiring a frontend build step.

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

pub async fn dashboard_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        include_str!("dashboard.js"),
    )
}
