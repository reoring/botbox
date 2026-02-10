use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("secret not found: {0}")]
    SecretNotFound(String),

    #[error("invalid header name: {0}")]
    InvalidHeaderName(String),

    #[error("invalid header value")]
    InvalidHeaderValue,
}
