use std::time::{Duration, Instant};

use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, header};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{
    config::secrets::{ApiAuth, ApiConfig},
    error::AppError,
};

const MAX_AUTH_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_EXPIRY_SAFETY_MARGIN_SECS: u64 = 30;

#[derive(Debug, Default)]
pub struct ApiAuthState {
    cache: Mutex<AuthCache>,
}

#[derive(Debug, Default)]
struct AuthCache {
    token: Option<CachedToken>,
    next_generation: u64,
}

#[derive(Debug)]
struct CachedToken {
    value: SecretString,
    refresh_at: Option<Instant>,
    generation: u64,
}

#[derive(Clone, Debug)]
pub struct ResolvedAuthToken {
    pub value: SecretString,
    generation: u64,
}

#[derive(Debug)]
pub enum AuthResolution {
    Token(ResolvedAuthToken),
    EndpointResponse(reqwest::Response),
}

impl ApiAuthState {
    pub async fn resolve(
        &self,
        client: &reqwest::Client,
        api_config: &ApiConfig,
    ) -> Result<AuthResolution, AppError> {
        tokio::time::timeout(
            Duration::from_millis(api_config.timeout_ms),
            self.resolve_inner(client, api_config),
        )
        .await
        .map_err(|_| AppError::UpstreamTimeout)?
    }

    async fn resolve_inner(
        &self,
        client: &reqwest::Client,
        api_config: &ApiConfig,
    ) -> Result<AuthResolution, AppError> {
        let auth = api_config.auth.as_ref().ok_or_else(|| {
            AppError::Internal(format!(
                "missing auth config for dynamic auth state '{}'",
                api_config.slug
            ))
        })?;
        let mut cache = self.cache.lock().await;

        if let Some(token) = cache.token.as_ref()
            && token
                .refresh_at
                .is_none_or(|refresh_at| Instant::now() < refresh_at)
        {
            return Ok(AuthResolution::Token(ResolvedAuthToken {
                value: token.value.clone(),
                generation: token.generation,
            }));
        }

        cache.token = None;
        let (value, expires_in) = match request_token(client, auth, api_config.timeout_ms).await? {
            TokenResponse::Token { value, expires_in } => (value, expires_in),
            TokenResponse::EndpointResponse(response) => {
                return Ok(AuthResolution::EndpointResponse(response));
            }
        };

        let generation = cache.next_generation;
        cache.next_generation = cache.next_generation.wrapping_add(1);
        let refresh_at = expires_in.map(refresh_instant).transpose()?;
        cache.token = Some(CachedToken {
            value: value.clone(),
            refresh_at,
            generation,
        });

        Ok(AuthResolution::Token(ResolvedAuthToken {
            value,
            generation,
        }))
    }

    pub async fn invalidate(&self, token: &ResolvedAuthToken) {
        let mut cache = self.cache.lock().await;
        if cache
            .token
            .as_ref()
            .is_some_and(|cached| cached.generation == token.generation)
        {
            cache.token = None;
        }
    }
}

enum TokenResponse {
    Token {
        value: SecretString,
        expires_in: Option<u64>,
    },
    EndpointResponse(reqwest::Response),
}

async fn request_token(
    client: &reqwest::Client,
    auth: &ApiAuth,
    timeout_ms: u64,
) -> Result<TokenResponse, AppError> {
    let request = build_auth_request(auth)?;
    let timeout = Duration::from_millis(timeout_ms);

    tokio::time::timeout(timeout, async {
        let response = client.execute(request).await.map_err(|error| {
            if error.is_timeout() {
                AppError::UpstreamTimeout
            } else {
                AppError::UpstreamRequest(format!("auth endpoint request failed: {error}"))
            }
        })?;
        if !response.status().is_success() {
            return Ok(TokenResponse::EndpointResponse(response));
        }

        let payload = read_auth_response(response).await?;
        parse_token_response(auth, &payload)
    })
    .await
    .map_err(|_| AppError::UpstreamTimeout)?
}

fn build_auth_request(auth: &ApiAuth) -> Result<reqwest::Request, AppError> {
    let mut request = reqwest::Request::new(auth.method.clone(), auth.url.clone());
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, auth.content_type.clone());
    for (name, value) in &auth.headers {
        let value = HeaderValue::from_str(value.expose_secret()).map_err(|error| {
            AppError::UpstreamBuild(format!("invalid configured auth header: {error}"))
        })?;
        headers.insert(name.clone(), value);
    }
    *request.headers_mut() = headers;
    *request.body_mut() = Some(reqwest::Body::from(auth.body.expose_secret().to_owned()));
    Ok(request)
}

async fn read_auth_response(response: reqwest::Response) -> Result<Vec<u8>, AppError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AUTH_RESPONSE_BYTES as u64)
    {
        return Err(AppError::UpstreamRequest(
            "auth endpoint response is too large".to_owned(),
        ));
    }

    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            AppError::UpstreamRequest(format!("failed to read auth endpoint response: {error}"))
        })?;
        if bytes.len().saturating_add(chunk.len()) > MAX_AUTH_RESPONSE_BYTES {
            return Err(AppError::UpstreamRequest(
                "auth endpoint response is too large".to_owned(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn parse_token_response(auth: &ApiAuth, payload: &[u8]) -> Result<TokenResponse, AppError> {
    let response: Value = serde_json::from_slice(payload).map_err(|error| {
        AppError::UpstreamRequest(format!("auth endpoint returned invalid JSON: {error}"))
    })?;
    let token = response
        .get(&auth.response.token)
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            AppError::UpstreamRequest(format!(
                "auth endpoint response field '{}' must be a non-empty string",
                auth.response.token
            ))
        })?;
    let expires_in = auth
        .response
        .expires_in
        .as_ref()
        .map(|field| {
            response.get(field).and_then(Value::as_u64).ok_or_else(|| {
                AppError::UpstreamRequest(format!(
                    "auth endpoint response field '{field}' must be an unsigned integer"
                ))
            })
        })
        .transpose()?;

    Ok(TokenResponse::Token {
        value: SecretString::from(token.to_owned()),
        expires_in,
    })
}

fn refresh_instant(expires_in: u64) -> Result<Instant, AppError> {
    let margin = (expires_in / 10).min(MAX_EXPIRY_SAFETY_MARGIN_SECS);
    Instant::now()
        .checked_add(Duration::from_secs(expires_in.saturating_sub(margin)))
        .ok_or_else(|| {
            AppError::UpstreamRequest("auth endpoint returned an invalid token lifetime".to_owned())
        })
}
