use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

use crate::state::AppState;

pub async fn apply(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in state.security_headers.iter() {
        response.headers_mut().insert(name, value.clone());
    }
    response
}
