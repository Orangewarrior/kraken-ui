use axum::{
    extract::Request,
    http::{HeaderValue, header::CACHE_CONTROL},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use tower_sessions::Session;
use tracing::error;

use crate::controllers::auth;

pub async fn require_admin(session: Session, request: Request, next: Next) -> Response {
    let mut response = match auth::authenticated_operator_type(&session).await {
        Ok(Some(operator_type)) if operator_type == "admin" => next.run(request).await,
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
