use axum::{
    extract::Request,
    http::{HeaderValue, header::CACHE_CONTROL},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use tower_sessions::Session;
use tracing::error;

use crate::{controllers::auth, models::operator::OperatorRole};

/// Only `admin` sessions may reach ACL administration routes.
pub async fn require_admin(session: Session, request: Request, next: Next) -> Response {
    guard(session, request, next, &[OperatorRole::Admin]).await
}

/// Operator-grade routes (rule management) are open to administrators and
/// operators, but not auditors: changing WAF detection is outside an auditor's
/// read-only remit.
pub async fn require_operator(session: Session, request: Request, next: Next) -> Response {
    guard(
        session,
        request,
        next,
        &[OperatorRole::Admin, OperatorRole::Operator],
    )
    .await
}

/// The read-only console surface — dashboard, attacks monitor (table and the
/// single-attack detail view), and self-service account settings (password and
/// two-factor) plus logout — shared by every authenticated role, including the
/// auditor. The detail view still masks secret parameter values for non-admins.
pub async fn require_console_viewer(session: Session, request: Request, next: Next) -> Response {
    guard(session, request, next, &OperatorRole::ALL).await
}

async fn guard(
    session: Session,
    request: Request,
    next: Next,
    allowed_roles: &[OperatorRole],
) -> Response {
    let mut response = match auth::authenticated_role(&session).await {
        Ok(Some(role)) if allowed_roles.contains(&role) => next.run(request).await,
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
