#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing required environment variable: {0}")]
    MissingEnvVar(String),
    #[error("invalid value for environment variable {var}: {message}")]
    InvalidEnvVar { var: String, message: String },
}

pub type Result<T> = std::result::Result<T, Error>;
