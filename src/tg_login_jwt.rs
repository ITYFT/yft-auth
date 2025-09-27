use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hmac::{Hmac, digest::KeyInit};
use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use sha2::Sha256;

use crate::error::YftAuthError;

#[derive(Debug, Clone)]
pub struct TgLoginJwt {
    pub tg_id: String,
    pub first_name: String,
    pub tg_chat: String,
    pub last_name: Option<String>,
    pub username: Option<String>,
    pub language_code: Option<String>,
    pub issue_date: DateTime<Utc>,
    pub expire_date: DateTime<Utc>,
}

impl TgLoginJwt {
    pub fn to_jwt(&self, secret_key: &str) -> Result<String, YftAuthError> {
        let mut token_jwt = BTreeMap::new();

        let issue_date = self.issue_date.timestamp().to_string();
        let expire_date = self.expire_date.timestamp().to_string();

        token_jwt.insert("tg_id", self.tg_id.as_str());
        token_jwt.insert("first_name", self.first_name.as_str());
        token_jwt.insert("tg_chat", self.tg_chat.as_str());
        if let Some(last_name) = &self.last_name {
            token_jwt.insert("last_name", last_name.as_str());
        }
        if let Some(username) = &self.username {
            token_jwt.insert("username", username.as_str());
        }
        if let Some(language_code) = &self.language_code {
            token_jwt.insert("language_code", language_code.as_str());
        }
        token_jwt.insert("iat", issue_date.as_str());
        token_jwt.insert("exp", expire_date.as_str());
        token_jwt.insert("_type", "tg_login");

        let key: Hmac<Sha256> = Hmac::new_from_slice(secret_key.as_bytes()).unwrap();
        token_jwt
            .sign_with_key(&key)
            .map_err(|_| YftAuthError::InvalidSecretKey)
    }

    pub fn verify_token(
        token_string: String,
        secret_key: &str,
    ) -> Result<TgLoginJwt, YftAuthError> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(secret_key.as_bytes()).unwrap();

        let token: Token<Header, BTreeMap<String, String>, _> = token_string
            .verify_with_key(&key)
            .map_err(|_| YftAuthError::InvalidToken)?;

        let claims = token.claims();

        let _type = claims
            .get("_type")
            .ok_or(YftAuthError::InvalidTokenClaims)
            .cloned()?;

        if _type != "tg_login" {
            return Err(YftAuthError::InvalidToken);
        }

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

        let tg_id = claims
            .get("tg_id")
            .ok_or(YftAuthError::InvalidTokenClaims)
            .cloned()?
            .parse::<String>()
            .map_err(|_| YftAuthError::InvalidTokenClaims)?;

        let first_name = claims
            .get("first_name")
            .ok_or(YftAuthError::InvalidTokenClaims)
            .cloned()?
            .parse::<String>()
            .map_err(|_| YftAuthError::InvalidTokenClaims)?;

        let tg_chat = claims
            .get("tg_chat")
            .ok_or(YftAuthError::InvalidTokenClaims)
            .cloned()?
            .parse::<String>()
            .map_err(|_| YftAuthError::InvalidTokenClaims)?;

        let last_name = claims.get("last_name").map(|x| x.clone());
        let username = claims.get("username").map(|x| x.clone());
        let language_code = claims.get("language_code").map(|x| x.clone());

        let issue_date =
            DateTime::from_timestamp(issue_date, 0).ok_or(YftAuthError::InvalidTokenClaims)?;
        let expire_date =
            DateTime::from_timestamp(expire_date, 0).ok_or(YftAuthError::InvalidTokenClaims)?;

        if expire_date < Utc::now() {
            return Err(YftAuthError::InvalidToken);
        }

        Ok(Self {
            tg_id: tg_id,
            first_name: first_name,
            tg_chat: tg_chat,
            last_name,
            username,
            language_code,
            issue_date,
            expire_date,
        })
    }
}

#[cfg(test)]
mod test {
    use chrono::{Days, Duration, Utc};
    use jwt::VerifyWithKey;

    use super::TgLoginJwt;

    #[test]
    pub fn test_token_full_flow() {
        let secret = "test_secret";

        let new_token = TgLoginJwt {
            issue_date: Utc::now(),
            expire_date: Utc::now().checked_add_days(Days::new(10)).unwrap(),
            tg_id: "tg_id".to_string(),
            first_name: "first_name".to_string(),
            tg_chat: "tg_chat".to_string(),
            last_name: Some("last_name".to_string()),
            username: Some("username".to_string()),
            language_code: Some("language_code".to_string()),
        };

        let jwt_string = new_token.to_jwt(&secret).unwrap();
        println!("Token: {}", jwt_string);

        let failed_signed_jwt = new_token.to_jwt("bad_secret").unwrap();
        assert!(TgLoginJwt::verify_token(failed_signed_jwt, secret).is_err());

        let verified_jwt = TgLoginJwt::verify_token(jwt_string, secret);
        assert!(verified_jwt.is_ok());

        let parsed_jwt = verified_jwt.unwrap();

        assert_eq!(new_token.tg_id, parsed_jwt.tg_id);
        assert_eq!(new_token.first_name, parsed_jwt.first_name);
        assert_eq!(new_token.tg_chat, parsed_jwt.tg_chat);
        assert_eq!(new_token.last_name, parsed_jwt.last_name);
        assert_eq!(new_token.username, parsed_jwt.username);
        assert_eq!(new_token.language_code, parsed_jwt.language_code);
    }
}
