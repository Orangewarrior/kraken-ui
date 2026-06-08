use axum::{
    extract::Request,
    http::{HeaderValue, header::CACHE_CONTROL},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use tower_sessions::Session;
use tracing::error;

use crate::controllers::auth;

/// Only `admin` sessions may reach ACL administration routes.
pub async fn require_admin(session: Session, request: Request, next: Next) -> Response {
    guard(session, request, next, &["admin"]).await
}

/// Day-to-day console routes (dashboard, attacks table, self-service password
/// change, logout) are open to both administrators and operators.
pub async fn require_operator(session: Session, request: Request, next: Next) -> Response {
    guard(session, request, next, &["admin", "operator"]).await
}

/// The single-attack detail view is a read-only investigative page; it is shared
/// by every authenticated role that is allowed to inspect WAF findings.
pub async fn require_attack_viewer(session: Session, request: Request, next: Next) -> Response {
    guard(session, request, next, &["admin", "operator", "auditor"]).await
}

async fn guard(session: Session, request: Request, next: Next, allowed_types: &[&str]) -> Response {
    let mut response = match auth::authenticated_operator_type(&session).await {
        Ok(Some(operator_type)) if allowed_types.contains(&operator_type.as_str()) => {
            next.run(request).await
        }
        Ok(_) => Redirect::to("/kraken_ui/login").into_response(),
        Err(_) => {
            error!("failed to read authentication session");
            Redirect::to("/kraken_ui/login").into_response()
        }
    };
    // Authenticated pages can contain operator and attack data; never let them
    // be stored by the browser or any shared cache.
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
