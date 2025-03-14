#[cfg(feature = "ql")]
use yft_service_sdk::external::async_graphql;

#[derive(Debug, Clone)]
pub enum YftAuthError {
    InvalidSecretKey,
    InvalidToken,
    InvalidTokenClaims,
}
impl YftAuthError {
    pub fn as_err_str(&self) -> String {
        "InvalidToken".to_string()
    }
}

#[cfg(feature = "ql")]
impl From<YftAuthError> for async_graphql::Error {
    fn from(value: YftAuthError) -> Self {
        Self::new(value.as_err_str())
    }
}
