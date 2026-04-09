use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode, header},
    response::Response,
    routing::{any, post},
};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{Level, info};

use crate::app::AppState;
use crate::auth::exchange::exchange_handler;
use crate::auth::jwt::validate_bearer_authorized_request;
use crate::error::{AppError, LoggedErrorCode};
use crate::telemetry::{sanitize_request_uri_for_logs, sanitize_url_for_logs};

use super::{request::map_request, response::map_response, upstream::execute_request};

const ROUTER_TIMEOUT_SECS: u64 = 60;
pub(crate) const UNKNOWN_CLIENT_ID: &str = "<unknown>";

#[derive(Clone, Debug)]
pub(crate) struct LoggedClientId(pub String);

#[derive(Debug)]
struct ProxyResponseError {
    error: AppError,
    client_id: Option<String>,
}

#[derive(Clone, Debug)]
struct LoggedUpstreamRequest {
    api: String,
    upstream_method: String,
    upstream_url: String,
    upstream_status: String,
    timeout_ms: u64,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/auth/exchange", post(exchange_handler))
        .route("/proxy/{api}", any(proxy_handler))
        .route("/proxy/{api}/", any(proxy_handler))
        .route("/proxy/{api}/{*path}", any(proxy_handler_with_path))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(ROUTER_TIMEOUT_SECS),
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    tracing::span!(
                        Level::INFO,
                        "http_request",
                        request_id = %request_id_from_request(request).unwrap_or_else(|| "-".to_owned()),
                        method = %request.method(),
                        uri = %sanitize_request_uri_for_logs(request.uri()),
                    )
                })
                .on_response(|response: &Response, latency: Duration, span: &tracing::Span| {
                    let _enter = span.enter();
                    let client_id = response
                        .extensions()
                        .get::<LoggedClientId>()
                        .map(|value| value.0.as_str())
                        .unwrap_or(UNKNOWN_CLIENT_ID);
                    let error_code = response
                        .extensions()
                        .get::<LoggedErrorCode>()
                        .map(|value| value.0);
                    let upstream_request = response.extensions().get::<LoggedUpstreamRequest>();

                    match (error_code, upstream_request) {
                        (Some(error_code), Some(upstream_request)) => info!(
                            client_id = %client_id,
                            status = %response.status(),
                            latency_ms = latency.as_millis(),
                            error_code,
                            api = %upstream_request.api,
                            upstream_method = %upstream_request.upstream_method,
                            upstream_url = %upstream_request.upstream_url,
                            upstream_status = %upstream_request.upstream_status,
                            timeout_ms = upstream_request.timeout_ms,
                        ),
                        (Some(error_code), None) => info!(
                            client_id = %client_id,
                            status = %response.status(),
                            latency_ms = latency.as_millis(),
                            error_code,
                        ),
                        (None, Some(upstream_request)) => info!(
                            client_id = %client_id,
                            status = %response.status(),
                            latency_ms = latency.as_millis(),
                            api = %upstream_request.api,
                            upstream_method = %upstream_request.upstream_method,
                            upstream_url = %upstream_request.upstream_url,
                            upstream_status = %upstream_request.upstream_status,
                            timeout_ms = upstream_request.timeout_ms,
                        ),
                        (None, None) => info!(
                            client_id = %client_id,
                            status = %response.status(),
                            latency_ms = latency.as_millis(),
                        ),
                    }
                })
        )
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        .with_state(state)
}

async fn proxy_handler(
    State(state): State<AppState>,
    Path(api_slug): Path<String>,
    request: Request<Body>,
) -> Response {
    proxy_response(state, api_slug, request).await
}

async fn proxy_handler_with_path(
    State(state): State<AppState>,
    Path((api_slug, _path)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    proxy_response(state, api_slug, request).await
}

async fn proxy_response(state: AppState, api_slug: String, request: Request<Body>) -> Response {
    let request_id = request_id_from_request(&request);

    let mut response = match handle_proxy_request(state, api_slug, request).await {
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

async fn handle_proxy_request(
    state: AppState,
    api_slug: String,
    request: Request<Body>,
) -> Result<Response, ProxyResponseError> {
    let authorization_header = request.headers();
    let authorization_header =
        extract_authorization_header(authorization_header).map_err(|error| ProxyResponseError {
            error,
            client_id: None,
        })?;

    let authorized = validate_bearer_authorized_request(authorization_header, state.secrets())
        .map_err(|error| ProxyResponseError {
            error,
            client_id: None,
        })?;
    let client_id = authorized.client_slug.clone();
    if !authorized.claims.apis().contains(&api_slug) {
        return Err(ProxyResponseError {
            error: AppError::ForbiddenApi { api: api_slug },
            client_id: Some(client_id),
        });
    }

    let api_config = state
        .api_config(&api_slug)
        .map_err(|error| ProxyResponseError {
            error,
            client_id: Some(client_id.clone()),
        })?;
    let outbound_request =
        map_request(request, &api_slug, api_config).map_err(|error| ProxyResponseError {
            error,
            client_id: Some(client_id.clone()),
        })?;
    let upstream_method = outbound_request.method().clone();
    let upstream_url = sanitize_url_for_logs(outbound_request.url().as_ref());
    let timeout_ms = api_config.timeout_ms;
    let upstream_response = execute_request(state.client(), outbound_request, timeout_ms)
        .await
        .map_err(|error| ProxyResponseError {
            error,
            client_id: Some(client_id.clone()),
        })?;
    let upstream_status = upstream_response.status().to_string();
    let mut response = map_response(upstream_response).map_err(|error| ProxyResponseError {
        error,
        client_id: Some(client_id.clone()),
    })?;
    response.extensions_mut().insert(LoggedClientId(client_id));
    response.extensions_mut().insert(LoggedUpstreamRequest {
        api: api_slug,
        upstream_method: upstream_method.to_string(),
        upstream_url,
        upstream_status,
        timeout_ms,
    });

    Ok(response)
}

fn extract_authorization_header(headers: &http::HeaderMap) -> Result<&str, AppError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(AppError::InvalidToken)?;

    if values.next().is_some() {
        return Err(AppError::InvalidToken);
    }

    value.to_str().map_err(|_| AppError::InvalidToken)
}

fn request_id_from_request(request: &Request<Body>) -> Option<String> {
    request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
