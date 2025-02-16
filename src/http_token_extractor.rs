use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use yft_service_sdk::external::axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    RequestPartsExt,
};

pub struct ExtractBearerToken(pub String);

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
