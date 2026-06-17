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
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
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
    services::regex_rules::{RegexRuleList, codec_for},
    state::AppState,
    view::{
        RuleManagementCmcTemplate, RuleManagementRegexEditTemplate,
        RuleManagementRegexSelectTemplate, nav, render,
    },
};

/// Where the regex select page lives; reused as a redirect target when a rule
/// name is missing or off the allowlist.
const REGEX_SELECT_PATH: &str = "/kraken_ui/auth/rule_management/regex";

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

/// The rule name carried in the editor URL (`?rule=body_regex`) and the update
/// query string. It is always re-validated against the allowlist before use.
#[derive(Deserialize)]
pub struct RegexRuleQuery {
    #[serde(default)]
    rule: String,
}

#[derive(Deserialize)]
pub struct RegexUpdateForm {
    csrf_token: String,
    /// The full rule content typed into the editor.
    #[serde(default)]
    content: String,
}

/// Renders the "Rule editor" selection page: the select box of editable rule
/// lists and the "submit rule to edit" button.
pub async fn regex_select_page(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
) -> Result<Response, AppError> {
    let csrf_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let rule_lists = RegexRuleList::ALL
        .iter()
        .map(RegexRuleList::as_str)
        .collect();
    let response = render(RuleManagementRegexSelectTemplate {
        active_page: nav::RULE_MANAGEMENT,
        csrf_token,
        show_acl: auth::is_admin(&session).await?,
        configured: state.rule_management.is_some(),
        rule_lists,
    })?;
    Ok((token, response).into_response())
}

/// Renders the editor for one rule list. The rule content is fetched server-side
/// from KrakenWAF (`POST /rule/control/regex/view`); the browser never sees that
/// call or holds a Rorschach secret.
pub async fn regex_edit_page(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Query(query): Query<RegexRuleQuery>,
) -> Result<Response, AppError> {
    let list = match RegexRuleList::parse(&query.rule) {
        Some(list) => list,
        // An unknown or missing rule name sends the operator back to the picker
        // rather than rendering an editor bound to nothing.
        None => return Ok(Redirect::to(REGEX_SELECT_PATH).into_response()),
    };
    let csrf_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let (content, loaded, error_message) = match state.rule_management.as_ref() {
        None => (
            String::new(),
            false,
            "Rule management is not configured.".to_owned(),
        ),
        Some(service) => match service.view_regex(list.as_str()).await {
            Ok(content) => (content, true, String::new()),
            Err(error) => {
                warn!(error = %format!("{error:#}"), "WAF regex view failed");
                (String::new(), false, WAF_ERROR_MESSAGE.to_owned())
            }
        },
    };
    let response = render(RuleManagementRegexEditTemplate {
        active_page: nav::RULE_MANAGEMENT,
        csrf_token,
        show_acl: auth::is_admin(&session).await?,
        rule_name: list.as_str(),
        editor_mode: list.editor_mode(),
        content,
        loaded,
        error_message,
    })?;
    Ok((token, response).into_response())
}

/// Validates the edited content for its rule-list shape and, if it passes,
/// forwards it to KrakenWAF (`POST /rule/control/regex/update/<name>`). The rule
/// name arrives in the query string and the content in the JSON body.
pub async fn regex_update(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Query(query): Query<RegexRuleQuery>,
    Json(form): Json<RegexUpdateForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "invalid csrf token" })),
        )
            .into_response());
    }
    let list = match RegexRuleList::parse(&query.rule) {
        Some(list) => list,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "unknown rule list" })),
            )
                .into_response());
        }
    };
    let Some(service) = state.rule_management.as_ref() else {
        return Ok(not_configured());
    };
    // Validate before contacting the WAF: a broken document, an empty file or a
    // rule missing a required field is rejected here with an actionable message.
    let body = match codec_for(list).build_update_body(&form.content) {
        Ok(body) => body,
        Err(error) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": error.to_string() })),
            )
                .into_response());
        }
    };
    match service.update_regex(list.as_str(), body).await {
        Ok(outcome) => {
            let username = auth::authenticated_username(&session)
                .await
                .unwrap_or_else(|| "unknown".to_owned());
            info!(
                target: "audit",
                event = "regex_rules_update",
                username = %username,
                rule = %list.as_str(),
                rules_written = outcome.rules_written,
                "operator updated a regex rule list"
            );
            Ok(Json(json!({
                "status": "ok",
                "rule": list.as_str(),
                "rules_written": outcome.rules_written,
            }))
            .into_response())
        }
        Err(error) => {
            warn!(error = %format!("{error:#}"), "WAF regex update failed");
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
