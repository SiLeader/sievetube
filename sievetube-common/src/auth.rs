use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::error::SieveTubeError;

/// HS256 requires a key at least as long as its 256-bit hash output.
pub const MIN_JWT_SECRET_LEN: usize = 32;

/// Enforce a minimum key size and reject well-known documentation values.
pub fn validate_jwt_secret(secret: &[u8]) -> Result<(), SieveTubeError> {
    if secret.len() < MIN_JWT_SECRET_LEN {
        return Err(SieveTubeError::Auth(format!(
            "JWT secret must be at least {MIN_JWT_SECRET_LEN} bytes"
        )));
    }
    const PLACEHOLDERS: [&[u8]; 3] = [
        b"change-me-to-a-long-random-secret",
        b"replace-with-at-least-32-random-bytes",
        b"this-is-not-a-secure-production-secret",
    ];
    if PLACEHOLDERS.contains(&secret) || secret.iter().all(|byte| *byte == secret[0]) {
        return Err(SieveTubeError::Auth(
            "JWT secret is a known placeholder; generate a random secret".into(),
        ));
    }
    Ok(())
}

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
    validate_jwt_secret(secret)?;
    jsonwebtoken::encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| SieveTubeError::Auth(e.to_string()))
}

pub fn verify_jwt(token: &str, secret: &[u8]) -> Result<TokenData<TunnelClaims>, SieveTubeError> {
    validate_jwt_secret(secret)?;
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
        let secret = b"supersecret-supersecret-0123456789";
        let claims = make_claims(3600);
        let token = sign_jwt(&claims, secret).unwrap();
        let decoded = verify_jwt(&token, secret).unwrap();
        assert_eq!(decoded.claims.sub, "tenant-123");
        assert_eq!(decoded.claims.hostnames, vec!["web.example.com"]);
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = sign_jwt(&make_claims(3600), b"secret-a-secret-a-secret-a-123456").unwrap();
        assert!(verify_jwt(&token, b"secret-b-secret-b-secret-b-123456").is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let claims = make_claims(-3600);
        let secret = b"secret-secret-secret-secret-12345678";
        let token = sign_jwt(&claims, secret).unwrap();
        assert!(verify_jwt(&token, secret).is_err());
    }

    #[test]
    fn retained_secret_allows_rolling_rotation() {
        let old_secret = b"old-secret-old-secret-old-secret-12";
        let token = sign_jwt(&make_claims(3600), old_secret).unwrap();
        let secrets = vec![
            b"new-secret-new-secret-new-secret-12".to_vec(),
            old_secret.to_vec(),
        ];
        assert!(verify_jwt_any(&token, &secrets).is_ok());
    }

    #[test]
    fn weak_and_placeholder_secrets_are_rejected() {
        assert!(validate_jwt_secret(b"short").is_err());
        assert!(validate_jwt_secret(b"change-me-to-a-long-random-secret").is_err());
        assert!(validate_jwt_secret(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
    }
}
