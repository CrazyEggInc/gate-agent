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
    proxy::router::{LoggedClientId, UNKNOWN_CLIENT_ID},
    time::unix_timestamp_secs,
};

use super::jwt::sign_access_token_for_client;

pub const EXCHANGE_TOKEN_TTL_SECS: u64 = 10 * 60;
const MAX_EXCHANGE_BODY_BYTES: usize = 16 * 1024;

#[derive(Debug)]
struct ExchangeResponseError {
    error: AppError,
    client_id: Option<String>,
}

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
        Err(error) => {
            let mut response = error.error.response(request_id.as_deref());

            if let Some(client_id) = error.client_id {
                response.extensions_mut().insert(LoggedClientId(client_id));
            }

            response
        }
    };

    response
        .extensions_mut()
        .get_or_insert_with(|| LoggedClientId(UNKNOWN_CLIENT_ID.to_owned()));

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
) -> Result<Response, ExchangeResponseError> {
    let (parts, body) = request.into_parts();
    let api_key = extract_api_key(&parts.headers).map_err(|error| ExchangeResponseError {
        error,
        client_id: None,
    })?;
    let client = state
        .client_for_api_key(api_key)
        .map_err(remap_api_key_error)
        .map_err(|error| ExchangeResponseError {
            error,
            client_id: None,
        })?;
    let client_id = client.slug.clone();
    let body = Limited::new(body, MAX_EXCHANGE_BODY_BYTES)
        .collect()
        .await
        .map_err(|_| ExchangeResponseError {
            error: AppError::BadRequest("request body is too large or invalid".to_owned()),
            client_id: Some(client_id.clone()),
        })?
        .to_bytes();
    let payload: ExchangeRequest =
        serde_json::from_slice(&body).map_err(|_| ExchangeResponseError {
            error: AppError::BadRequest("request body must be valid JSON".to_owned()),
            client_id: Some(client_id.clone()),
        })?;
    let requested_apis =
        normalize_requested_apis(payload.apis).map_err(|error| ExchangeResponseError {
            error,
            client_id: Some(client_id.clone()),
        })?;

    validate_requested_apis(client, &requested_apis, &state).map_err(|error| {
        ExchangeResponseError {
            error,
            client_id: Some(client_id.clone()),
        }
    })?;

    let issued_at = unix_timestamp_secs().map_err(|error| ExchangeResponseError {
        error,
        client_id: Some(client_id.clone()),
    })?;
    let access_token = sign_access_token_for_client(
        client,
        &requested_apis,
        state.secrets(),
        issued_at,
        EXCHANGE_TOKEN_TTL_SECS,
    )
    .map_err(|error| ExchangeResponseError {
        error,
        client_id: Some(client_id.clone()),
    })?;

    let mut response = (
        StatusCode::OK,
        Json(ExchangeResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: EXCHANGE_TOKEN_TTL_SECS,
        }),
    )
        .into_response();
    response.extensions_mut().insert(LoggedClientId(client_id));

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
