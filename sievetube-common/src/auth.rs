use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::error::SieveTubeError;

/// Claims embedded in the JWT used by Connectors to authenticate with Edges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelClaims {
    /// Subject: unique tenant identifier
    pub sub: String,
    /// List of hostnames this tenant is allowed to expose
    pub hostnames: Vec<String>,
    /// Expiry (Unix timestamp)
    pub exp: u64,
    /// Issued at (Unix timestamp)
    pub iat: u64,
}

pub fn sign_jwt(claims: &TunnelClaims, secret: &[u8]) -> Result<String, SieveTubeError> {
    jsonwebtoken::encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| SieveTubeError::Auth(e.to_string()))
}

pub fn verify_jwt(token: &str, secret: &[u8]) -> Result<TokenData<TunnelClaims>, SieveTubeError> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.leeway = 0;

    jsonwebtoken::decode::<TunnelClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map_err(|e| SieveTubeError::Auth(e.to_string()))
}

/// Verify with the active secret and any retained rotation secrets. Secrets
/// should be ordered newest first; signing always remains a separate operation
/// using only the active key.
pub fn verify_jwt_any(
    token: &str,
    secrets: &[Vec<u8>],
) -> Result<TokenData<TunnelClaims>, SieveTubeError> {
    let mut first_error = None;
    for secret in secrets {
        match verify_jwt(token, secret) {
            Ok(data) => return Ok(data),
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    Err(first_error.unwrap_or_else(|| SieveTubeError::Auth("no JWT secrets configured".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(exp_offset_secs: i64) -> TunnelClaims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        TunnelClaims {
            sub: "tenant-123".to_string(),
            hostnames: vec!["web.example.com".to_string()],
            exp: (now as i64 + exp_offset_secs) as u64,
            iat: now,
        }
    }

    #[test]
    fn valid_jwt_roundtrip() {
        let secret = b"supersecret";
        let claims = make_claims(3600);
        let token = sign_jwt(&claims, secret).unwrap();
        let decoded = verify_jwt(&token, secret).unwrap();
        assert_eq!(decoded.claims.sub, "tenant-123");
        assert_eq!(decoded.claims.hostnames, vec!["web.example.com"]);
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = sign_jwt(&make_claims(3600), b"secret-a").unwrap();
        assert!(verify_jwt(&token, b"secret-b").is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let claims = make_claims(-3600);
        let token = sign_jwt(&claims, b"secret").unwrap();
        assert!(verify_jwt(&token, b"secret").is_err());
    }

    #[test]
    fn retained_secret_allows_rolling_rotation() {
        let token = sign_jwt(&make_claims(3600), b"old-secret").unwrap();
        let secrets = vec![b"new-secret".to_vec(), b"old-secret".to_vec()];
        assert!(verify_jwt_any(&token, &secrets).is_ok());
    }
}
