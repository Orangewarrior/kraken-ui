use std::net::{IpAddr, SocketAddr};

use axum::{
    Form, Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    controllers::acl::{valid_email, valid_username},
    error::AppError,
    models::operator_repository::{NewOperator, OperatorRepository},
    security::sanitize,
    state::AppState,
};

#[derive(Deserialize)]
pub struct FirstTimeForm {
    username: String,
    email: String,
    password: String,
    user_type: String,
}

#[derive(Serialize)]
struct FirstTimeResponse {
    status: &'static str,
    message: &'static str,
}

pub async fn first_time(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Form(form): Form<FirstTimeForm>,
) -> Result<Response, AppError> {
    if !is_loopback(peer.ip()) {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(FirstTimeResponse {
                status: "forbidden",
                message: "first_time accepts loopback clients only",
            }),
        )
            .into_response());
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
    repository
        .create(NewOperator {
            username: &username,
            email: &email,
            operator_type: "admin",
            password: &form.password,
        })
        .await?;
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
