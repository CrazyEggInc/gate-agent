use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};

use crate::{
    app::AppState,
    config::secrets::{ClientConfig, is_valid_slug},
    error::AppError,
    time::unix_timestamp_secs,
};

use super::jwt::sign_access_token_for_client;

pub const EXCHANGE_TOKEN_TTL_SECS: u64 = 10 * 60;

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

    response
}

async fn handle_exchange_request(
    state: AppState,
    request: Request<Body>,
) -> Result<Response, AppError> {
    let (parts, body) = request.into_parts();
    let api_key = parts
        .headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::InvalidApiKey)?;
    let client = state
        .client_for_api_key(api_key)
        .map_err(remap_api_key_error)?;
    let body = body
        .collect()
        .await
        .map_err(|_| AppError::BadRequest("request body must be valid JSON".to_owned()))?
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

    Ok((
        StatusCode::OK,
        Json(ExchangeResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: EXCHANGE_TOKEN_TTL_SECS,
        }),
    )
        .into_response())
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
        return Err(AppError::ForbiddenApi {
            api: invalid_api.clone(),
        });
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
