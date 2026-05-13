use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("crypto error")]
    Crypto,

    #[error("auth error: {0}")]
    Auth(String),

    #[error("not found")]
    NotFound,

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::NotFound  => (StatusCode::NOT_FOUND, "not found".into()),
            AppError::Crypto    => (StatusCode::INTERNAL_SERVER_ERROR, "crypto error".into()),
            AppError::Db(e)     => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
        };
        (status, message).into_response()
    }
}