use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use tower_sessions::Session;
use tracing::error;

use crate::controllers::auth;

pub async fn require_admin(session: Session, request: Request, next: Next) -> Response {
    match auth::authenticated_operator_type(&session).await {
        Ok(Some(operator_type)) if operator_type == "admin" => next.run(request).await,
        Ok(_) => Redirect::to("/kraken_ui/login").into_response(),
        Err(_) => {
            error!("failed to read authentication session");
            Redirect::to("/kraken_ui/login").into_response()
        }
    }
}
