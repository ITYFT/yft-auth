use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use yft_service_sdk::external::{
    async_graphql::{self, Error},
    axum::{
        extract::FromRequestParts,
        http::{request::Parts, StatusCode},
        RequestPartsExt,
    },
};

pub struct ExtractQlBearerToken(pub Option<String>);

impl ExtractQlBearerToken {
    pub fn get_token(&self) -> async_graphql::Result<String> {
        self.0.clone().ok_or(Error::new("InvalidToken"))
    }
}

impl<S> FromRequestParts<S> for ExtractQlBearerToken
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let header = parts.extract::<TypedHeader<Authorization<Bearer>>>().await;

        let Ok(token) = header else {
            return Ok(ExtractQlBearerToken(None));
        };

        Ok(ExtractQlBearerToken(Some(token.0.token().to_string())))
    }
}
