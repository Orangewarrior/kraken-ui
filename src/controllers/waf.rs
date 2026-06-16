use std::collections::HashMap;

use anyhow::anyhow;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_csrf::CsrfToken;
use serde::Serialize;
use time::{
    OffsetDateTime, PrimitiveDateTime, UtcOffset, format_description::well_known::Rfc3339,
    macros::format_description,
};
use tower_sessions::Session;

use crate::{
    controllers::{
        auth,
        pagination::{PageResponse, parse_query_u64},
    },
    error::AppError,
    models::vulnerability_repository::{AttackSearchField, AttackSort, VulnerabilityRepository},
    security::{redact, sanitize},
    state::AppState,
    view::{ShowAttacksTemplate, ViewWafRequestTemplate, nav, render},
};

#[derive(Serialize)]
pub struct AttackRow {
    id: i32,
    severity: String,
    title: String,
    client_ip: String,
    request_uri: String,
    rule_match: String,
    occurred_at: String,
    country: String,
}

pub async fn show_attacks(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
) -> Result<Response, AppError> {
    let csrf_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(ShowAttacksTemplate {
        active_page: nav::MONITOR,
        csrf_token,
        show_acl: auth::is_admin(&session).await?,
        database_available: state.waf_database.is_some(),
    })?;
    Ok((token, response).into_response())
}

/// Renders the standalone detail page for a single WAF finding. Reachable from
/// the attacks table (clicking the ID or IP column) and opened in a new tab for
/// administrators, operators and auditors.
///
/// The captured request/response evidence (URI, full-path evidence and the
/// matched payload) often carries credentials. Only an administrator sees those
/// bytes in clear: for every other role the value of any parameter named after a
/// well-known secret (`password`, `token`, `senha`, `密码`, …) is replaced with
/// `+++++` by [`redact::redact_sensitive_values`] before the page is rendered.
pub async fn view_waf_request(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let reveal_secrets = auth::is_admin(&session).await?;
    let Some(id) = query
        .get("id")
        .map(|value| sanitize::plain_text(value))
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|id| *id > 0)
    else {
        return Ok((StatusCode::BAD_REQUEST, "Invalid attack ID").into_response());
    };
    let Some(database) = state.waf_database.clone() else {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            "The WAF database configured in db-waf-alerts is not available.",
        )
            .into_response());
    };
    let Some(attack) = VulnerabilityRepository::new(database)
        .find_by_id(id)
        .await?
    else {
        return Ok((StatusCode::NOT_FOUND, "Attack not found").into_response());
    };
    // Mask secret parameter values for everyone but an administrator. The three
    // request/response evidence fields are the ones that carry attacker- and
    // victim-supplied parameters; the rest (title, CWE, rule match, …) are
    // describing metadata and are shown unchanged to every viewer.
    let reveal = |value: String| {
        if reveal_secrets {
            value
        } else {
            redact::redact_sensitive_values(&value)
        }
    };
    let response = render(ViewWafRequestTemplate {
        attack_id: attack.id,
        title: attack.title,
        severity_class: severity_class(&attack.severity),
        severity: attack.severity,
        cwe: attack.cwe,
        description: attack.description,
        reference_url: attack.reference_url,
        occurred_at: humanize_timestamp(&attack.occurred_at),
        rule_match: attack.rule_match,
        rule_line_match: attack.rule_line_match,
        client_ip: attack.client_ip,
        request_uri: reveal(attack.request_uri),
        fullpath_evidence: reveal(attack.fullpath_evidence),
        // Rendered through the template's default HTML escaping, so the exact
        // attack bytes are shown inert rather than silently stripped. Secret
        // parameter values are masked for non-administrators before escaping.
        request_payload: reveal(attack.request_payload),
    })?;
    Ok(response)
}

/// Maps a severity string to the CSS modifier that colours it: low is green,
/// medium orange, high red and critical maroon (bordô).
fn severity_class(severity: &str) -> &'static str {
    match severity.trim().to_ascii_lowercase().as_str() {
        "low" => "sev-low",
        "medium" => "sev-medium",
        "high" => "sev-high",
        "critical" => "sev-critical",
        _ => "sev-unknown",
    }
}

/// Renders the stored timestamp in a human-friendly form. The WAF database stores
/// `occurred_at` as text; we accept RFC 3339 and a couple of common SQL shapes
/// and fall back to the raw value if none parse.
fn humanize_timestamp(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let output =
        format_description!("[day] [month repr:long] [year], [hour]:[minute]:[second] UTC");
    if let Ok(parsed) = OffsetDateTime::parse(trimmed, &Rfc3339)
        && let Ok(formatted) = parsed.to_offset(UtcOffset::UTC).format(&output)
    {
        return formatted;
    }
    for description in [
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"),
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]"),
    ] {
        if let Ok(parsed) = PrimitiveDateTime::parse(trimmed, description)
            && let Ok(formatted) = parsed.format(&output)
        {
            return formatted;
        }
    }
    trimmed.to_owned()
}

pub async fn api_attacks(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let Some(database) = state.waf_database.clone() else {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(PageResponse::<AttackRow> {
                draw: 1,
                records_total: 0,
                records_filtered: 0,
                data: Vec::new(),
            }),
        )
            .into_response());
    };
    let draw = parse_query_u64(&query, "draw", 1);
    let start = parse_query_u64(&query, "start", 0);
    let length = parse_query_u64(&query, "length", 50).clamp(1, 100);
    let search = query
        .get("search[value]")
        .or_else(|| query.get("search"))
        .map(|value| sanitize::plain_text(value))
        .unwrap_or_default();
    // The select box in front of the search input narrows the LIKE to a single
    // column; absent or unknown tokens search every column.
    let search_field = query
        .get("search_field")
        .map(|value| sanitize::plain_text(value))
        .map_or(AttackSearchField::All, |value| {
            AttackSearchField::from_token(&value)
        });
    // The clicked column header drives the sort: severity (default) or occurred
    // at. A missing direction means descending, so occurred-at opens newest-first.
    let sort = query
        .get("sort")
        .map(|value| sanitize::plain_text(value))
        .map_or(AttackSort::Severity, |value| AttackSort::from_token(&value));
    let descending = query
        .get("order")
        .map(|value| sanitize::plain_text(value))
        .is_none_or(|value| value != "asc");
    let page = VulnerabilityRepository::new(database)
        .page(start, length, &search, search_field, sort, descending)
        .await?;
    let data = page
        .vulnerabilities
        .into_iter()
        .map(|item| AttackRow {
            id: item.id,
            severity: item.severity,
            title: item.title,
            client_ip: item.client_ip,
            request_uri: item.request_uri,
            rule_match: item.rule_match,
            occurred_at: item.occurred_at,
            country: item.country,
        })
        .collect();
    Ok(Json(PageResponse {
        draw,
        records_total: page.records_total,
        records_filtered: page.records_filtered,
        data,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::{humanize_timestamp, severity_class};

    #[test]
    fn maps_every_known_severity_to_a_colour_class() {
        assert_eq!(severity_class("low"), "sev-low");
        assert_eq!(severity_class("Medium"), "sev-medium");
        assert_eq!(severity_class(" HIGH "), "sev-high");
        assert_eq!(severity_class("critical"), "sev-critical");
        assert_eq!(severity_class("weird"), "sev-unknown");
    }

    #[test]
    fn humanizes_rfc3339_and_sql_timestamps() {
        assert_eq!(
            humanize_timestamp("2024-01-15T13:45:30Z"),
            "15 January 2024, 13:45:30 UTC"
        );
        assert_eq!(
            humanize_timestamp("2024-01-15 13:45:30"),
            "15 January 2024, 13:45:30 UTC"
        );
    }

    #[test]
    fn falls_back_to_the_raw_value_when_parsing_fails() {
        assert_eq!(humanize_timestamp("not a date"), "not a date");
        assert_eq!(humanize_timestamp(""), "");
    }
}
