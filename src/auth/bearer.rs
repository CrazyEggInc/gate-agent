use std::collections::BTreeMap;

use http::{HeaderMap, Method, header};

use crate::{
    config::secrets::{ApiAccessMethod, ApiAccessRule, SecretsConfig},
    error::AppError,
    time::unix_timestamp_secs_i64,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedApiAccess {
    pub apis: BTreeMap<String, Vec<ApiAccessRule>>,
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

pub fn extract_authorization_header(headers: &HeaderMap) -> Result<&str, AppError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(AppError::InvalidToken)?;

    if values.next().is_some() {
        return Err(AppError::InvalidToken);
    }

    value.to_str().map_err(|_| AppError::InvalidToken)
}

pub fn api_access_allows(
    authorized: &AuthorizedRequest,
    api: &str,
    method: &Method,
    path_and_query: &str,
) -> bool {
    let Some(rules) = authorized.access.apis.get(api) else {
        return false;
    };

    let path = path_only(path_and_query);
    if has_dot_segment(path) {
        return false;
    }

    rules.iter().any(|rule| rule_matches(rule, method, path))
}

fn path_only(path_and_query: &str) -> &str {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);

    if path.is_empty() { "/" } else { path }
}

fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|segment| {
        let decoded = decode_dot_segment(segment);
        decoded == "." || decoded == ".."
    })
}

fn decode_dot_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut decoded = String::with_capacity(segment.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].eq_ignore_ascii_case(&b'2')
            && bytes[index + 2].eq_ignore_ascii_case(&b'e')
        {
            decoded.push('.');
            index += 3;
        } else {
            decoded.push(bytes[index] as char);
            index += 1;
        }
    }

    decoded
}

fn rule_matches(rule: &ApiAccessRule, method: &Method, path: &str) -> bool {
    match &rule.method {
        ApiAccessMethod::Any => glob_matches(&rule.path, path),
        ApiAccessMethod::Exact(expected) => expected == method && glob_matches(&rule.path, path),
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return pattern == value;
    }

    let mut remaining = value;
    let mut parts = pattern.split('*').peekable();

    if let Some(first) = parts.next()
        && !first.is_empty()
    {
        let Some(stripped) = remaining.strip_prefix(first) else {
            return false;
        };
        remaining = stripped;
    }

    while let Some(part) = parts.next() {
        if part.is_empty() {
            continue;
        }

        if parts.peek().is_none() && !pattern.ends_with('*') {
            return remaining.ends_with(part);
        }

        let Some(index) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[index + part.len()..];
    }

    true
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
