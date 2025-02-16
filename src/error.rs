#[derive(Debug, Clone)]
pub enum YftAuthError{
    InvalidSecretKey,
    InvalidToken,
    InvalidTokenClaims,
}