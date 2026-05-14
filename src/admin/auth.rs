//! Admin API authentication — session management, login/logout, middleware.

use super::api::{AdminState, LoginRequest, LoginResponse, SessionEntry};
use axum::extract::{Json, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bcrypt::verify;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Maximum session lifetime in seconds (24 hours).
pub(super) const SESSION_TTL_SECS: u64 = 24 * 60 * 60;
/// Maximum number of concurrent sessions before oldest is evicted.
pub(super) const SESSION_MAX_CAPACITY: usize = 10_000;
/// Maximum login attempts per username before rate-limiting.
pub(super) const LOGIN_MAX_ATTEMPTS: u32 = 5;
/// Login rate-limit window in seconds.
pub(super) const LOGIN_WINDOW_SECS: u64 = 60;

/// Login handler
pub(super) async fn login_handler(
    State(state): State<AdminState>,
    Json(req): Json<LoginRequest>,
) -> axum::Json<LoginResponse> {
    if req.username.len() > 256 || req.password.len() > 256 {
        return axum::Json(LoginResponse {
            success: false,
            message: "Invalid credentials".to_string(),
            user: None,
            token: None,
        });
    }

    let now = std::time::Instant::now();
    state.login_attempts.retain(|_, (_, window_start)| {
        now.duration_since(*window_start).as_secs() < LOGIN_WINDOW_SECS
    });
    if let Some(pair) = state.login_attempts.get(&req.username) {
        let (count, window_start) = pair.value();
        if now.duration_since(*window_start).as_secs() < LOGIN_WINDOW_SECS
            && *count >= LOGIN_MAX_ATTEMPTS
        {
            return axum::Json(LoginResponse {
                success: false,
                message: "Too many login attempts".to_string(),
                user: None,
                token: None,
            });
        }
    }

    let config = state.config.load();
    let valid = config
        .server
        .admin_users
        .iter()
        .any(|u| u.username == req.username && verify_password(&req.password, &u.password));
    let legacy_valid = !config.server.admin_token.is_empty()
        && constant_time_eq(&req.password, &config.server.admin_token);

    if valid || legacy_valid {
        let user = if valid {
            config
                .server
                .admin_users
                .iter()
                .find(|u| u.username == req.username)
                .map(|u| u.username.clone())
                .unwrap_or(req.username.clone())
        } else {
            "admin".to_string()
        };

        let token = generate_token();
        let mut sessions = state.sessions.write().await;
        evict_expired_sessions(&mut sessions);
        sessions.insert(
            token.clone(),
            SessionEntry {
                user: user.clone(),
                created_at: std::time::Instant::now(),
            },
        );
        drop(sessions);
        state.login_attempts.remove(&req.username);

        axum::Json(LoginResponse {
            success: true,
            message: "Login successful".to_string(),
            user: Some(user),
            token: Some(token),
        })
    } else {
        let now = std::time::Instant::now();
        state
            .login_attempts
            .entry(req.username.clone())
            .and_modify(|(count, window_start)| {
                if now.duration_since(*window_start).as_secs() >= LOGIN_WINDOW_SECS {
                    *count = 1;
                    *window_start = now;
                } else {
                    *count += 1;
                }
            })
            .or_insert((1, now));

        axum::Json(LoginResponse {
            success: false,
            message: "Invalid credentials".to_string(),
            user: None,
            token: None,
        })
    }
}

/// Logout handler
pub(super) async fn logout_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> axum::Json<serde_json::Value> {
    if let Some(auth) = headers.get(AUTHORIZATION)
        && let Ok(token) = auth.to_str()
        && let Some(bearer) = token.strip_prefix("Bearer ")
    {
        let mut sessions = state.sessions.write().await;
        sessions.remove(bearer);
    }
    axum::Json(serde_json::json!({ "success": true, "message": "Logged out" }))
}

/// Get current user
pub(super) async fn me_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> axum::Json<serde_json::Value> {
    if let Some(auth) = headers.get(AUTHORIZATION)
        && let Ok(token) = auth.to_str()
        && let Some(bearer) = token.strip_prefix("Bearer ")
    {
        let sessions = state.sessions.read().await;
        if let Some(entry) = sessions.get(bearer) {
            return axum::Json(serde_json::json!({
                "authenticated": true,
                "user": entry.user
            }));
        }
    }
    axum::Json(serde_json::json!({ "authenticated": false }))
}

/// Verify password against hash
fn verify_password(password: &str, hash: &str) -> bool {
    if hash.starts_with("$2") {
        verify(password, hash).unwrap_or(false)
    } else {
        constant_time_eq(password, hash)
    }
}

/// Generate a random session token
fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    BASE64.encode(&bytes)
}

/// Constant-time comparison to prevent timing side-channel attacks on the admin token.
pub(super) fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let max_len = a_bytes.len().max(b_bytes.len());
    let mut diff = (a_bytes.len() ^ b_bytes.len()) as u8;
    for i in 0..max_len {
        diff |= a_bytes.get(i).copied().unwrap_or(0) ^ b_bytes.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// Decode a single hex byte (0-9, A-F, a-f) to its numeric value.
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Admin authentication middleware
pub(super) async fn admin_auth_middleware(
    State(state): State<AdminState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    let config = state.config.load();
    let expected = config.server.admin_token.clone();
    let token_auth = if !expected.is_empty() {
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(|value| constant_time_eq(value, &expected))
            .unwrap_or(false)
            || headers
                .get("x-admin-token")
                .and_then(|value| value.to_str().ok())
                .map(|value| constant_time_eq(value, &expected))
                .unwrap_or(false)
    } else {
        false
    };
    drop(config);

    let session_auth = if !token_auth {
        if let Some(bearer) = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        {
            let sessions = state.sessions.read().await;
            sessions.get(bearer).is_some()
        } else {
            false
        }
    } else {
        false
    };

    let query_auth = if !token_auth && !session_auth {
        request
            .uri()
            .query()
            .and_then(|qs| {
                qs.split('&')
                    .filter_map(|pair| pair.split_once('='))
                    .find(|(k, _)| *k == "token")
                    .map(|(_, v)| {
                        let mut decoded = String::with_capacity(v.len());
                        let mut bytes = v.bytes();
                        while let Some(b) = bytes.next() {
                            if b == b'%' {
                                let hi = bytes.next().unwrap_or(b'0');
                                let lo = bytes.next().unwrap_or(b'0');
                                let val = hex_val(hi) << 4 | hex_val(lo);
                                decoded.push(val as char);
                            } else if b == b'+' {
                                decoded.push(' ');
                            } else {
                                decoded.push(b as char);
                            }
                        }
                        decoded
                    })
            })
            .map(|token| {
                let matches_admin = !expected.is_empty() && constant_time_eq(&token, &expected);
                if matches_admin {
                    return true;
                }
                if let Ok(sessions) = state.sessions.try_read() {
                    sessions.get(&token).is_some()
                } else {
                    false
                }
            })
            .unwrap_or(false)
    } else {
        false
    };

    if token_auth || session_auth || query_auth {
        Ok(next.run(request).await)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(
                serde_json::json!({"error": "unauthorized", "message": "Valid Bearer token or X-Admin-Token required"}),
            ),
        ))
    }
}

/// Evict sessions that have exceeded SESSION_TTL_SECS or when the map
/// exceeds SESSION_MAX_CAPACITY.
pub(super) fn evict_expired_sessions(sessions: &mut HashMap<String, SessionEntry>) {
    let now = std::time::Instant::now();
    sessions.retain(|_, entry| now.duration_since(entry.created_at).as_secs() < SESSION_TTL_SECS);
    if sessions.len() > SESSION_MAX_CAPACITY {
        let mut entries: Vec<(String, std::time::Instant)> = sessions
            .iter()
            .map(|(k, v)| (k.clone(), v.created_at))
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        let to_remove = sessions.len() - SESSION_MAX_CAPACITY;
        for (key, _) in entries.into_iter().take(to_remove) {
            sessions.remove(&key);
        }
    }
}

/// Background service that periodically cleans up expired sessions.
pub struct SessionCleanupBackground {
    pub sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

impl SessionCleanupBackground {
    pub fn new(sessions: Arc<RwLock<HashMap<String, SessionEntry>>>) -> Self {
        Self { sessions }
    }

    pub async fn run(&self) {
        const CLEANUP_INTERVAL_SECS: u64 = 60;
        let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

        loop {
            interval.tick().await;
            let now = std::time::Instant::now();

            let Ok(mut sessions) = self.sessions.try_write() else {
                continue;
            };
            let before = sessions.len();
            sessions.retain(|_, entry| {
                now.duration_since(entry.created_at).as_secs() < SESSION_TTL_SECS
            });
            let evicted = before.saturating_sub(sessions.len());
            if evicted > 0 {
                tracing::debug!(
                    evicted,
                    remaining = sessions.len(),
                    "Expired sessions evicted"
                );
            }
        }
    }
}
