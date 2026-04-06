use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use secrecy::ExposeSecret;

use crate::config::secrets::{JwtAlgorithm, SecretsConfig};
use crate::error::AppError;

use super::claims::JwtClaims;

pub const DEFAULT_LOCAL_TOKEN_TTL_SECS: u64 = 5 * 60;

pub fn validate_bearer_token(
    authorization_header: &str,
    secrets: &SecretsConfig,
) -> Result<JwtClaims, AppError> {
    let mut parts = authorization_header.trim().split_ascii_whitespace();
    let scheme = parts.next().ok_or(AppError::InvalidToken)?;
    let token = parts.next().ok_or(AppError::InvalidToken)?;

    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || parts.next().is_some() {
        return Err(AppError::InvalidToken);
    }

    validate_token(token, secrets)
}

pub fn validate_token(token: &str, secrets: &SecretsConfig) -> Result<JwtClaims, AppError> {
    if token.trim().is_empty() {
        return Err(AppError::InvalidToken);
    }

    let header = decode_header(token).map_err(|_| AppError::InvalidToken)?;

    if header.alg != Algorithm::HS256 {
        return Err(AppError::InvalidToken);
    }

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[secrets.jwt.issuer.as_str()]);
    validation.set_audience(&[secrets.jwt.audience.as_str()]);
    validation.required_spec_claims = ["exp", "iat", "iss", "aud"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    validation.validate_nbf = false;

    let token_data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secrets.jwt.shared_secret.expose_secret().as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::InvalidToken)?;

    let claims = token_data.claims;

    if claims.api.is_empty() || claims.api != claims.api.to_ascii_lowercase() {
        return Err(AppError::InvalidToken);
    }

    if !secrets.apis.contains_key(&claims.api) {
        return Err(AppError::ForbiddenApi { api: claims.api });
    }

    Ok(claims)
}

pub fn sign_local_test_token(api: &str, secrets: &SecretsConfig) -> Result<String, AppError> {
    let issued_at = current_timestamp()?;
    sign_local_test_token_at(api, secrets, issued_at, DEFAULT_LOCAL_TOKEN_TTL_SECS)
}

pub fn sign_local_test_token_at(
    api: &str,
    secrets: &SecretsConfig,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<String, AppError> {
    if api.is_empty() || api != api.to_ascii_lowercase() {
        return Err(AppError::InvalidToken);
    }

    if !secrets.apis.contains_key(api) {
        return Err(AppError::ForbiddenApi {
            api: api.to_owned(),
        });
    }

    let algorithm = match secrets.jwt.algorithm {
        JwtAlgorithm::Hs256 => Algorithm::HS256,
    };

    let claims = JwtClaims {
        api: api.to_owned(),
        iss: secrets.jwt.issuer.clone(),
        aud: secrets.jwt.audience.clone(),
        iat: issued_at,
        exp: issued_at.saturating_add(ttl_secs),
    };

    encode(
        &Header::new(algorithm),
        &claims,
        &EncodingKey::from_secret(secrets.jwt.shared_secret.expose_secret().as_bytes()),
    )
    .map_err(|error| AppError::Internal(format!("failed to sign local test token: {error}")))
}

fn current_timestamp() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| AppError::Internal(format!("system clock is invalid: {error}")))
}
