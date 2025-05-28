use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use yft_service_sdk::external::axum::{
    RequestPartsExt, async_trait,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

use crate::auth_jwt::AuthJwt;

pub struct ExtractBearerToken(pub String);

impl ExtractBearerToken {
    pub fn get_token_as_struct(&self, auth_secret: &str) -> Result<AuthJwt, (StatusCode, String)> {
        AuthJwt::verify_token(self.0.clone(), auth_secret)
            .map_err(|x| (StatusCode::UNAUTHORIZED, "Invalid auth token".to_string()))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for ExtractBearerToken
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                let err: Result<Self, Self::Rejection> = Err((
                    StatusCode::UNAUTHORIZED,
                    "`Authorization` header is missing".to_string(),
                ));
                err
            });

        let Ok(token) = header else {
            return Err((
                StatusCode::UNAUTHORIZED,
                "`auth` header is missing".to_string(),
            ));
        };

        Ok(ExtractBearerToken(token.0.token().to_string()))
    }
}
