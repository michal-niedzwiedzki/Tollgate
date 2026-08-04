use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing required environment variable: {0}")]
    MissingEnvVar(String),
    #[error("invalid value for environment variable {var}: {message}")]
    InvalidEnvVar { var: String, message: String },

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),

    #[error("invalid numeric value: {0}")]
    InvalidNumeric(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Shared JSON error body: `{"error": {"code": "...", "message": "..."}}`.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        ErrorBody {
            error: ErrorDetail {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}
