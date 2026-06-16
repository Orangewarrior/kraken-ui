//! Rule-management console: lists KrakenWAF CMC detection modules and applies
//! enable/disable changes through the Rorschach-authenticated client.
//!
//! These routes are open to administrators and operators (the `require_operator`
//! guard). The backend proxies to KrakenWAF so the browser never holds a
//! Rorschach secret and the token is minted server-side per request.

use std::collections::BTreeMap;

use anyhow::anyhow;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_csrf::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_sessions::Session;
use tracing::{info, warn};

use crate::{
    controllers::auth,
    error::AppError,
    security::csrf,
    state::AppState,
    view::{RuleManagementCmcTemplate, nav, render},
};

/// Maximum modules accepted in a single update, a guard against an oversized or
/// abusive request body.
const MAX_MODULES: usize = 1024;
const WAF_ERROR_MESSAGE: &str = "error in WAF server";

#[derive(Serialize)]
struct CmcModuleRow {
    /// The CMC module name extracted from the WAF JSON.
    name: String,
    /// Whether the module is currently enabled (`true`) or disabled (`false`).
    status: bool,
}

#[derive(Serialize)]
struct CmcListBody {
    data: Vec<CmcModuleRow>,
}

#[derive(Deserialize)]
pub struct CmcUpdateForm {
    csrf_token: String,
    /// Desired state per module: `true` enables it, `false` disables it.
    #[serde(default)]
    modules: BTreeMap<String, bool>,
}

/// Renders the "List CMC rules" page with its datatable and "Submit all" button.
pub async fn cmc_page(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
) -> Result<Response, AppError> {
    let csrf_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(RuleManagementCmcTemplate {
        active_page: nav::RULE_MANAGEMENT,
        csrf_token,
        show_acl: auth::is_admin(&session).await?,
        configured: state.rule_management.is_some(),
    })?;
    Ok((token, response).into_response())
}

/// Populates the datatable: GETs the live module state from KrakenWAF
/// (`/rule/control/cmc/list`) and returns one row per module.
pub async fn api_cmc_list(State(state): State<AppState>) -> Result<Response, AppError> {
    let Some(service) = state.rule_management.as_ref() else {
        return Ok(not_configured());
    };
    match service.list_cmc().await {
        Ok(modules) => {
            let mut data: Vec<CmcModuleRow> = modules
                .into_iter()
                .map(|(name, status)| CmcModuleRow { name, status })
                .collect();
            data.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(Json(CmcListBody { data }).into_response())
        }
        Err(error) => {
            // Detail (status code, transport error) goes to the application log;
            // it never contains the token or secrets. The operator sees only the
            // generic WAF error.
            warn!(error = %format!("{error:#}"), "WAF rule-management list failed");
            Ok(waf_error())
        }
    }
}

/// Applies every checkbox at once: ticked modules are enabled (`true`), unticked
/// modules are disabled (`false`), forwarded to `/rule/control/cmc/update`.
pub async fn cmc_update(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Json(form): Json<CmcUpdateForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "invalid csrf token" })),
        )
            .into_response());
    }
    let Some(service) = state.rule_management.as_ref() else {
        return Ok(not_configured());
    };
    if form.modules.is_empty()
        || form.modules.len() > MAX_MODULES
        || !form.modules.keys().all(|name| is_valid_module_name(name))
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid module set" })),
        )
            .into_response());
    }
    match service.update_cmc(form.modules).await {
        Ok(outcome) => {
            let username = auth::authenticated_username(&session)
                .await
                .unwrap_or_else(|| "unknown".to_owned());
            // Module names are not secret; the token and Rorschach secrets are
            // never part of this event.
            info!(
                target: "audit",
                event = "cmc_rules_update",
                username = %username,
                enabled = ?outcome.updated.enabled,
                disabled = ?outcome.updated.disabled,
                "operator updated CMC rule modules"
            );
            Ok(Json(json!({
                "status": "ok",
                "enabled": outcome.updated.enabled,
                "disabled": outcome.updated.disabled,
            }))
            .into_response())
        }
        Err(error) => {
            warn!(error = %format!("{error:#}"), "WAF rule-management update failed");
            Ok(waf_error())
        }
    }
}

/// CMC module names are simple identifiers (e.g. `HPP_detect`); reject anything
/// outside `[A-Za-z0-9_-]` so a malformed key never reaches the WAF payload.
fn is_valid_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn waf_error() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": WAF_ERROR_MESSAGE })),
    )
        .into_response()
}

fn not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "Rule management is not configured" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::is_valid_module_name;

    #[test]
    fn accepts_simple_module_identifiers() {
        assert!(is_valid_module_name("HPP_detect"));
        assert!(is_valid_module_name("Silent_sql_errors"));
        assert!(is_valid_module_name("overflow-detect"));
    }

    #[test]
    fn rejects_empty_oversized_or_punctuated_names() {
        assert!(!is_valid_module_name(""));
        assert!(!is_valid_module_name("has space"));
        assert!(!is_valid_module_name("drop;table"));
        assert!(!is_valid_module_name(&"a".repeat(129)));
    }
}
