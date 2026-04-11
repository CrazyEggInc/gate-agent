use std::collections::BTreeMap;

use crate::{
    config::secrets::{AccessLevel, SecretsConfig},
    error::AppError,
    time::unix_timestamp_secs_i64,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedApiAccess {
    pub apis: BTreeMap<String, AccessLevel>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedRequest {
    pub client_slug: String,
    pub access: AuthorizedApiAccess,
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

    validate_token(token, secrets)
}

pub fn validate_token(token: &str, secrets: &SecretsConfig) -> Result<AuthorizedRequest, AppError> {
    if token.trim().is_empty() {
        return Err(AppError::InvalidToken);
    }

    let (token_id, _) = token.split_once('.').ok_or(AppError::InvalidToken)?;

    if token_id.is_empty() || token.ends_with('.') || token.matches('.').count() != 1 {
        return Err(AppError::InvalidToken);
    }

    let (client_slug, client) = secrets
        .clients
        .iter()
        .find(|(_, client)| client.bearer_token_id == token_id)
        .ok_or(AppError::InvalidToken)?;

    if client.bearer_token_expires_at.unix_timestamp() <= unix_timestamp_secs_i64()? {
        return Err(AppError::InvalidToken);
    }

    if !client.bearer_token_hash.matches_token(token) {
        return Err(AppError::InvalidToken);
    }

    Ok(AuthorizedRequest {
        client_slug: client_slug.clone(),
        access: AuthorizedApiAccess {
            apis: client.api_access.clone(),
        },
    })
}
