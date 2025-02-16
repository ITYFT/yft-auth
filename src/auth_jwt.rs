use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hmac::{digest::KeyInit, Hmac};
use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use sha2::Sha256;

use crate::error::YftAuthError;

#[derive(Debug, Clone)]
pub struct AuthJwt {
    pub creads_id: String,
    pub issue_date: DateTime<Utc>,
    pub expire_date: DateTime<Utc>,
}

impl AuthJwt {
    pub fn new(creads_id: &str, expire_date: DateTime<Utc>) -> Self {
        Self {
            creads_id: creads_id.to_string(),
            issue_date: Utc::now(),
            expire_date,
        }
    }

    pub fn to_jwt(&self, secret_key: &str) -> Result<String, YftAuthError> {
        let mut token_jwt = BTreeMap::new();

        let issue_date = self.issue_date.timestamp().to_string();
        let expire_date = self.expire_date.timestamp().to_string();

        token_jwt.insert("id", self.creads_id.as_str());
        token_jwt.insert("iat", issue_date.as_str());
        token_jwt.insert("exp", expire_date.as_str());
        token_jwt.insert("_type", "auth");

        let key: Hmac<Sha256> = Hmac::new_from_slice(secret_key.as_bytes()).unwrap();
        token_jwt
            .sign_with_key(&key)
            .map_err(|_| YftAuthError::InvalidSecretKey)
    }

    pub fn verify_token(token_string: String, secret_key: &str) -> Result<AuthJwt, YftAuthError> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(secret_key.as_bytes()).unwrap();

        let token: Token<Header, BTreeMap<String, String>, _> = token_string
            .verify_with_key(&key)
            .map_err(|_| YftAuthError::InvalidToken)?;

        let claims = token.claims();

        let _type = claims
            .get("_type")
            .ok_or(YftAuthError::InvalidTokenClaims)
            .cloned()?;

        if _type != "auth" {
            return Err(YftAuthError::InvalidToken);
        }

        let creads_id = claims
            .get("id")
            .ok_or(YftAuthError::InvalidToken)
            .cloned()?;

        let issue_date = claims
            .get("iat")
            .ok_or(YftAuthError::InvalidTokenClaims)
            .cloned()?
            .parse::<i64>()
            .map_err(|_| YftAuthError::InvalidTokenClaims)?;

        let expire_date = claims
            .get("exp")
            .ok_or(YftAuthError::InvalidTokenClaims)
            .cloned()?
            .parse::<i64>()
            .map_err(|_| YftAuthError::InvalidTokenClaims)?;

        let issue_date =
            DateTime::from_timestamp(issue_date, 0).ok_or(YftAuthError::InvalidTokenClaims)?;
        let expire_date =
            DateTime::from_timestamp(expire_date, 0).ok_or(YftAuthError::InvalidTokenClaims)?;

        if expire_date < Utc::now() {
            return Err(YftAuthError::InvalidToken);
        }

        Ok(Self {
            creads_id: creads_id,
            issue_date,
            expire_date,
        })
    }
}

#[cfg(test)]
mod test {
    use chrono::{Days, Duration, Utc};
    use jwt::VerifyWithKey;

    use super::AuthJwt;

    #[test]
    pub fn test_token_full_flow() {
        let secret = "test_secret";

        let new_token = AuthJwt {
            creads_id: "test".to_string(),
            issue_date: Utc::now(),
            expire_date: Utc::now().checked_add_days(Days::new(10)).unwrap(),
        };

        let jwt_string = new_token.to_jwt(&secret).unwrap();
        println!("Token: {}", jwt_string);

        let failed_signed_jwt = new_token.to_jwt("bad_secret").unwrap();
        assert!(AuthJwt::verify_token(failed_signed_jwt, secret).is_err());

        let verified_jwt = AuthJwt::verify_token(jwt_string, secret);
        assert!(verified_jwt.is_ok());

        let parsed_jwt = verified_jwt.unwrap();

        assert_eq!(new_token.creads_id, parsed_jwt.creads_id);
    }
}
