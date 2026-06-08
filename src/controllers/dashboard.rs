use anyhow::anyhow;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use axum_csrf::CsrfToken;
use serde::Serialize;
use tower_sessions::Session;
use tracing::warn;

use crate::{
    controllers::auth,
    error::AppError,
    models::vulnerability_repository::VulnerabilityRepository,
    services::waf_metrics::{ModuleMetric, WafMetricsSnapshot},
    state::AppState,
    view::{DashboardTemplate, nav, render},
};

#[derive(Serialize)]
pub struct DashboardData {
    metrics_available: bool,
    database_available: bool,
    metrics: WafMetricsSnapshot,
    average_latency_ms: f64,
    cmc_detections: Vec<ChartValue>,
    module_blocks: Vec<ModuleMetric>,
    countries: Vec<ChartValue>,
    client_ips: Vec<ChartValue>,
}

#[derive(Serialize)]
pub struct ChartValue {
    label: String,
    value: f64,
}

pub async fn get(token: CsrfToken, session: Session) -> Result<Response, AppError> {
    let authenticity_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(DashboardTemplate {
        active_page: nav::DASHBOARD,
        csrf_token: authenticity_token,
        show_acl: auth::is_admin(&session).await?,
    })?;
    Ok((token, response).into_response())
}

pub async fn api(State(state): State<AppState>) -> Result<Json<DashboardData>, AppError> {
    let (metrics_available, metrics) = match state.waf_metrics.fetch().await {
        Ok(metrics) => (true, metrics),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "WAF metrics are temporarily unavailable");
            (false, WafMetricsSnapshot::default())
        }
    };
    let average_latency_ms = if metrics.request_duration_count > 0.0 {
        metrics.request_duration_sum / metrics.request_duration_count
    } else {
        0.0
    };
    let module_blocks = metrics.module_blocks.clone();
    let (database_available, cmc_detections, countries, client_ips) =
        if let Some(database) = state.waf_database.clone() {
            let repository = VulnerabilityRepository::new(database);
            let cmc_detections = repository
                .cmc_module_counts()
                .await?
                .into_iter()
                .map(|(label, value)| ChartValue {
                    label,
                    value: value as f64,
                })
                .collect();
            let countries = repository
                .top_countries(10)
                .await?
                .into_iter()
                .map(|(label, value)| ChartValue {
                    label,
                    value: value as f64,
                })
                .collect();
            let client_ips = repository
                .top_client_ips(10)
                .await?
                .into_iter()
                .map(|(label, value)| ChartValue {
                    label,
                    value: value as f64,
                })
                .collect();
            (true, cmc_detections, countries, client_ips)
        } else {
            (false, Vec::new(), Vec::new(), Vec::new())
        };
    Ok(Json(DashboardData {
        metrics_available,
        database_available,
        metrics,
        average_latency_ms,
        cmc_detections,
        module_blocks,
        countries,
        client_ips,
    }))
}
