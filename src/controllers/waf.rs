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

use crate::{
    error::AppError,
    models::vulnerability_repository::VulnerabilityRepository,
    security::sanitize,
    state::AppState,
    view::{ShowAttacksTemplate, render},
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

#[derive(Serialize)]
pub struct AttackPageResponse {
    draw: u64,
    #[serde(rename = "recordsTotal")]
    records_total: u64,
    #[serde(rename = "recordsFiltered")]
    records_filtered: u64,
    data: Vec<AttackRow>,
}

pub async fn show_attacks(
    State(state): State<AppState>,
    token: CsrfToken,
) -> Result<Response, AppError> {
    let csrf_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(ShowAttacksTemplate {
        active_page: "monitor",
        csrf_token,
        database_available: state.waf_database.is_some(),
    })?;
    Ok((token, response).into_response())
}

pub async fn api_attacks(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let Some(database) = state.waf_database.clone() else {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(AttackPageResponse {
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
    let severity_descending = query
        .get("severity_order")
        .map(|value| sanitize::plain_text(value))
        .is_none_or(|value| value != "asc");
    let page = VulnerabilityRepository::new(database)
        .page(start, length, &search, severity_descending)
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
    Ok(Json(AttackPageResponse {
        draw,
        records_total: page.records_total,
        records_filtered: page.records_filtered,
        data,
    })
    .into_response())
}

fn parse_query_u64(query: &HashMap<String, String>, key: &str, fallback: u64) -> u64 {
    query
        .get(key)
        .map(|value| sanitize::plain_text(value))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(fallback)
}
