use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::error;

pub struct AppError {
    status: StatusCode,
    public_message: &'static str,
    source: anyhow::Error,
}

impl AppError {
    pub fn internal(source: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            public_message: "Internal server error",
            source: source.into(),
        }
    }

    pub fn unauthorized(source: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            public_message: "Invalid credentials",
            source: source.into(),
        }
    }

    pub fn bad_request(source: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            public_message: "Invalid request data",
            source: source.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!(
            status = self.status.as_u16(),
            error = %self.source,
            "request failed"
        );
        (self.status, self.public_message).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(source: E) -> Self {
        Self::internal(source)
    }
}
