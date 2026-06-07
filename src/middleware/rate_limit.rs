use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::state::AppState;

/// A global, per-IP request cap applied to every route as defence in depth.
///
/// The client address is read from the request extensions (populated by
/// `into_make_service_with_connect_info`). When it is absent — for example in
/// unit tests that drive the router directly — the limiter is skipped rather
/// than rejecting the request.
pub async fn apply(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>()
        && !state.request_rate_limiter.check(&peer.ip().to_string())
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response();
    }
    next.run(request).await
}
