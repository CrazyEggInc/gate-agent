use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
};
use http_body_util::{BodyExt, Limited};
use serde::{Deserialize, Serialize};

use crate::{
    app::AppState,
    config::secrets::{ClientConfig, is_valid_slug},
    error::AppError,
    telemetry::{LoggedClient, LoggedRequestContext, sanitize_request_uri_for_logs},
    time::unix_timestamp_secs,
};

use super::jwt::sign_access_token_for_client;

pub const EXCHANGE_TOKEN_TTL_SECS: u64 = 10 * 60;
const MAX_EXCHANGE_BODY_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ExchangeRequest {
    pub apis: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

pub async fn exchange_handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    let request_id = request_id_from_request(&request);
    let request_context = LoggedRequestContext {
        request_id: request_id.clone().unwrap_or_else(|| "-".to_owned()),
        method: request.method().to_string(),
        uri: sanitize_request_uri_for_logs(request.uri()),
    };

    let mut response = match handle_exchange_request(state, request).await {
        Ok(response) => response,
        Err(error) => error.response(request_id.as_deref()),
    };

    if let Some(request_id) = request_id {
        response.headers_mut().insert(
            "x-request-id",
            http::HeaderValue::from_str(&request_id)
                .expect("request id should always be a valid header value"),
        );
    }

    response.extensions_mut().insert(request_context);

    response
}

async fn handle_exchange_request(
    state: AppState,
    request: Request<Body>,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    let api_key = extract_api_key(&parts.headers)?;
    let client = state
        .client_for_api_key(api_key)
        .map_err(remap_api_key_error)?;
    let body = Limited::new(body, MAX_EXCHANGE_BODY_BYTES)
        .collect()
        .await
        .map_err(|_| AppError::BadRequest("request body is too large or invalid".to_owned()))?
        .to_bytes();
    let payload: ExchangeRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("request body must be valid JSON".to_owned()))?;
    let requested_apis = normalize_requested_apis(payload.apis)?;

    validate_requested_apis(client, &requested_apis, &state)?;

    let issued_at = unix_timestamp_secs()?;
    let access_token = sign_access_token_for_client(
        client,
        &requested_apis,
        state.secrets(),
        issued_at,
        EXCHANGE_TOKEN_TTL_SECS,
    )?;

    let mut response = (
        StatusCode::OK,
        Json(ExchangeResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: EXCHANGE_TOKEN_TTL_SECS,
        }),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(LoggedClient(client.slug.clone()));

    Ok(response)
}

fn normalize_requested_apis(apis: Vec<String>) -> Result<Vec<String>, AppError> {
    let mut normalized = apis
        .into_iter()
        .map(|api| api.to_ascii_lowercase())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();

    if normalized.is_empty() {
        return Err(AppError::BadRequest("apis must not be empty".to_owned()));
    }

    if let Some(invalid_api) = normalized.iter().find(|api| !is_valid_slug(api)) {
        return Err(AppError::BadRequest(format!(
            "apis must contain only valid slugs: {invalid_api}"
        )));
    }

    Ok(normalized)
}

fn validate_requested_apis(
    client: &ClientConfig,
    requested_apis: &[String],
    state: &AppState,
) -> Result<(), AppError> {
    for api in requested_apis {
        if !state.secrets().apis.contains_key(api) || !client.allowed_apis.contains(api) {
            return Err(AppError::ForbiddenApi { api: api.clone() });
        }
    }

    Ok(())
}

fn extract_api_key(headers: &HeaderMap) -> Result<&str, AppError> {
    let mut values = headers.get_all("x-api-key").iter();
    let value = values.next().ok_or(AppError::InvalidApiKey)?;

    if values.next().is_some() {
        return Err(AppError::InvalidApiKey);
    }

    let value = value.to_str().map_err(|_| AppError::InvalidApiKey)?;

    if value.trim().is_empty() {
        return Err(AppError::InvalidApiKey);
    }

    Ok(value)
}

fn remap_api_key_error(error: AppError) -> AppError {
    match error {
        AppError::InvalidToken => AppError::InvalidApiKey,
        other => other,
    }
}

fn request_id_from_request(request: &Request<Body>) -> Option<String> {
    request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
