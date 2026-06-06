use std::{
    env,
    net::{IpAddr, SocketAddr},
};

use axum::{
    Form, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    controllers::acl::{valid_email, valid_username},
    error::AppError,
    models::operator_repository::{NewOperator, OperatorRepository},
    security::sanitize,
    state::AppState,
};

const FIRST_TIME_TOKEN_ENV: &str = "KRAKEN_UI_FIRST_TIME_TOKEN";

#[derive(Deserialize)]
pub struct FirstTimeForm {
    username: String,
    email: String,
    password: String,
    user_type: String,
    #[serde(default)]
    token: String,
}

#[derive(Serialize)]
struct FirstTimeResponse {
    status: &'static str,
    message: &'static str,
}

pub async fn first_time(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<FirstTimeForm>,
) -> Result<Response, AppError> {
    if !is_loopback(peer.ip()) {
        return Ok(forbidden("first_time accepts loopback clients only"));
    }
    // A reverse proxy that forwards to loopback would make every request appear
    // local, defeating the loopback guard. Refuse requests that carry proxy
    // forwarding headers.
    if has_forwarding_headers(&headers) {
        warn!("rejected first_time request carrying proxy forwarding headers");
        return Ok(forbidden(
            "first_time refuses proxied requests; run it directly against loopback",
        ));
    }
    // When a bootstrap token is configured, require it in addition to the
    // loopback check. This is the recommended posture for any host that is not
    // strictly single-tenant during bootstrap.
    match env::var(FIRST_TIME_TOKEN_ENV) {
        Ok(expected) if !expected.is_empty() => {
            if !constant_time_eq(form.token.as_bytes(), expected.as_bytes()) {
                warn!("rejected first_time request with an invalid bootstrap token");
                return Ok(forbidden("invalid bootstrap token"));
            }
        }
        _ => {}
    }
    let _guard = state.first_time_lock.lock().await;
    let repository = OperatorRepository::new(state.database.clone(), state.password_crypto.clone());
    if repository.count().await? > 0 {
        return Ok((
            StatusCode::GONE,
            Json(FirstTimeResponse {
                status: "closed",
                message: "first_time was already consumed",
            }),
        )
            .into_response());
    }

    let username = sanitize::plain_text(&form.username).to_ascii_lowercase();
    let email = sanitize::plain_text(&form.email).to_ascii_lowercase();
    let operator_type = sanitize::plain_text(&form.user_type).to_ascii_lowercase();
    if !valid_username(&username)
        || !valid_email(&email)
        || operator_type != "admin"
        || sanitize::secret_has_rejected_markup(&form.password)
        || state
            .password_policy
            .validate(&form.password, &username)
            .is_err()
        || state
            .password_policy
            .validate(
                &form.password,
                email.split('@').next().unwrap_or(email.as_str()),
            )
            .is_err()
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(FirstTimeResponse {
                status: "invalid",
                message: "invalid admin registration data or weak password",
            }),
        )
            .into_response());
    }
    let created = repository
        .create(NewOperator {
            username: &username,
            email: &email,
            operator_type: "admin",
            password: &form.password,
        })
        .await?;
    info!(
        target: "audit",
        event = "first_time",
        id_user = created.id_user,
        username = %created.username,
        "initial administrator created via first_time"
    );
    Ok((
        StatusCode::CREATED,
        Json(FirstTimeResponse {
            status: "created",
            message: "initial administrator created; endpoint is now closed",
        }),
    )
        .into_response())
}

fn is_loopback(ip_address: IpAddr) -> bool {
    ip_address.is_loopback()
}

fn forbidden(message: &'static str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(FirstTimeResponse {
            status: "forbidden",
            message,
        }),
    )
        .into_response()
}

fn has_forwarding_headers(headers: &HeaderMap) -> bool {
    [
        "x-forwarded-for",
        "forwarded",
        "x-real-ip",
        "x-forwarded-host",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
}

/// Compares two byte slices in time that does not depend on the contents, only
/// the length, so a configured bootstrap token cannot be recovered by timing.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::is_loopback;

    #[test]
    fn first_time_accepts_only_loopback_addresses() {
        assert!(is_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_loopback(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }
}
