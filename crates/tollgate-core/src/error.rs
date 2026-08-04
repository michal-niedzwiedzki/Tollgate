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
}

pub type Result<T> = std::result::Result<T, Error>;
