use anyhow::anyhow;
use axum::{
    Form, Json,
    extract::State,
    response::{IntoResponse, Response},
};
use axum_csrf::CsrfToken;
use serde::Deserialize;
use tower_sessions::Session;
use tracing::info;

use crate::{
    controllers::auth,
    error::AppError,
    security::csrf,
    state::AppState,
    view::{UpdateKrakenUiTemplate, csrf_error_response, nav, render},
};

#[derive(Deserialize)]
pub struct UpdateForm {
    csrf_token: String,
}

pub async fn page(token: CsrfToken) -> Result<Response, AppError> {
    let authenticity_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(UpdateKrakenUiTemplate {
        active_page: nav::UPDATES,
        csrf_token: authenticity_token,
        show_acl: true,
        current_version: env!("CARGO_PKG_VERSION"),
    })?;
    Ok((token, response).into_response())
}

pub async fn start(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<UpdateForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let started = state.source_update.start().await;
    if started {
        let username = auth::authenticated_username(&session)
            .await
            .unwrap_or_else(|| "unknown".to_owned());
        info!(
            target: "audit",
            event = "source_update_started",
            username = %username,
            current_version = env!("CARGO_PKG_VERSION"),
            "administrator started a Kraken UI source update"
        );
    }
    Ok(Json(state.source_update.status().await).into_response())
}

pub async fn status(
    State(state): State<AppState>,
) -> Json<crate::services::source_update::UpdateStatus> {
    Json(state.source_update.status().await)
}
