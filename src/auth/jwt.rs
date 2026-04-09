use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;

use crate::config::secrets::{ClientConfig, SecretsConfig, is_valid_slug};
use crate::error::AppError;
use crate::time::unix_timestamp_secs;

use super::claims::JwtClaims;

pub const DEFAULT_LOCAL_TOKEN_TTL_SECS: u64 = 10 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedRequest {
    pub client_slug: String,
    pub claims: JwtClaims,
}

pub fn validate_bearer_token(
    authorization_header: &str,
    secrets: &SecretsConfig,
) -> Result<JwtClaims, AppError> {
    Ok(validate_bearer_authorized_request(authorization_header, secrets)?.claims)
}

pub fn validate_bearer_authorized_request(
    authorization_header: &str,
    secrets: &SecretsConfig,
) -> Result<AuthorizedRequest, AppError> {
    let mut parts = authorization_header.trim().split_ascii_whitespace();
    let scheme = parts.next().ok_or(AppError::InvalidToken)?;
    let token = parts.next().ok_or(AppError::InvalidToken)?;

    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || parts.next().is_some() {
        return Err(AppError::InvalidToken);
    }

    validate_authorized_request(token, secrets)
}

pub fn validate_token(token: &str, secrets: &SecretsConfig) -> Result<JwtClaims, AppError> {
    if token.trim().is_empty() {
        return Err(AppError::InvalidToken);
    }

    Ok(validate_authorized_request(token, secrets)?.claims)
}

pub fn validate_authorized_request(
    token: &str,
    secrets: &SecretsConfig,
) -> Result<AuthorizedRequest, AppError> {
    if token.trim().is_empty() {
        return Err(AppError::InvalidToken);
    }

    let claims = decode_verified_claims(token, secrets)?;
    let client_slug = validate_slug_claim(claims.sub.clone())?;
    let claims_api_slugs = validate_api_slugs(&claims.apis())?;
    let client = secrets
        .clients
        .get(&client_slug)
        .ok_or(AppError::InvalidToken)?;

    for api_slug in &claims_api_slugs {
        if !client.allowed_apis.contains(api_slug) {
            return Err(AppError::ForbiddenApi {
                api: api_slug.clone(),
            });
        }

        if !secrets.apis.contains_key(api_slug) {
            return Err(AppError::ForbiddenApi {
                api: api_slug.clone(),
            });
        }
    }

    Ok(AuthorizedRequest {
        client_slug,
        claims,
    })
}

fn decode_verified_claims(token: &str, secrets: &SecretsConfig) -> Result<JwtClaims, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[secrets.auth.issuer.as_str()]);
    validation.set_audience(&[secrets.auth.audience.as_str()]);
    validation.required_spec_claims = ["sub", "apis", "exp", "iat", "iss", "aud"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    validation.validate_nbf = false;

    let token_data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secrets.auth.signing_secret.expose_secret().as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::InvalidToken)?;

    let claims = token_data.claims;
    let current_timestamp = unix_timestamp_secs()?;

    if !is_valid_slug(&claims.sub) {
        return Err(AppError::InvalidToken);
    }

    if claims.iat > current_timestamp {
        return Err(AppError::InvalidToken);
    }

    validate_api_slugs(&claims.apis())?;

    Ok(claims)
}

pub fn sign_local_test_token(api: &str, secrets: &SecretsConfig) -> Result<String, AppError> {
    let issued_at = unix_timestamp_secs()?;
    sign_local_test_token_at(api, secrets, issued_at, DEFAULT_LOCAL_TOKEN_TTL_SECS)
}

pub fn sign_local_test_token_at(
    api: &str,
    secrets: &SecretsConfig,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<String, AppError> {
    let client = secrets
        .default_client()
        .map_err(|error| AppError::Internal(format!("missing default client config: {error}")))?;

    sign_local_test_token_with_client(client, api, issued_at, ttl_secs, secrets)
}

pub fn sign_local_test_token_for_client_at(
    client_slug: &str,
    api: &str,
    secrets: &SecretsConfig,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<String, AppError> {
    let client = secrets
        .clients
        .get(client_slug)
        .ok_or(AppError::InvalidToken)?;

    sign_local_test_token_with_client(client, api, issued_at, ttl_secs, secrets)
}

fn sign_local_test_token_with_client(
    client: &ClientConfig,
    api: &str,
    issued_at: u64,
    ttl_secs: u64,
    secrets: &SecretsConfig,
) -> Result<String, AppError> {
    sign_access_token_for_client(client, &[api.to_owned()], secrets, issued_at, ttl_secs)
}

pub(crate) fn sign_access_token_for_client(
    client: &ClientConfig,
    apis: &[String],
    secrets: &SecretsConfig,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<String, AppError> {
    let normalized_apis = validate_api_slugs(apis)?;

    for api in &normalized_apis {
        if !client.allowed_apis.contains(api) || !secrets.apis.contains_key(api) {
            return Err(AppError::ForbiddenApi { api: api.clone() });
        }
    }

    let claims = JwtClaims::new(
        client.slug.clone(),
        normalized_apis,
        secrets.auth.issuer.clone(),
        secrets.auth.audience.clone(),
        issued_at,
        issued_at.saturating_add(ttl_secs),
    );

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secrets.auth.signing_secret.expose_secret().as_bytes()),
    )
    .map_err(|error| AppError::Internal(format!("failed to sign local test token: {error}")))
}

fn validate_slug_claim(value: String) -> Result<String, AppError> {
    if !is_valid_slug(&value) {
        return Err(AppError::InvalidToken);
    }

    Ok(value)
}

fn validate_api_slugs(apis: &[String]) -> Result<Vec<String>, AppError> {
    if apis.is_empty() {
        return Err(AppError::InvalidToken);
    }

    let mut normalized_apis = apis.to_vec();
    normalized_apis.sort();
    normalized_apis.dedup();

    if normalized_apis.is_empty() || normalized_apis.iter().any(|api| !is_valid_slug(api)) {
        return Err(AppError::InvalidToken);
    }

    Ok(normalized_apis)
}
