use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{any, get},
};
use tower_http::timeout::TimeoutLayer;
use tracing::{debug, info};

use crate::app::AppState;
use crate::auth::bearer::{extract_authorization_header, validate_bearer_authorized_request};
use crate::error::{AppError, LoggedErrorCode};
use crate::mcp::router::mcp_handler;
use crate::telemetry::{
    GATE_AGENT_REQUEST_ID_HEADER, LoggedClient, LoggedMcpRequest, LoggedRequestContext,
    LoggedUpstreamRequest, generate_internal_request_id, sanitize_request_uri_for_logs,
    sanitize_url_for_logs,
};

use super::forward::forward_proxy_request;

const ROUTER_TIMEOUT_SECS: u64 = 60;

#[derive(Debug)]
struct ProxyResponseError {
    error: AppError,
    client: Option<String>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", axum::routing::post(mcp_handler))
        .route("/proxy/{api}", any(proxy_handler))
        .route("/proxy/{api}/", any(proxy_handler))
        .route("/proxy/{api}/{*path}", any(proxy_handler_with_path))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(ROUTER_TIMEOUT_SECS),
        ))
        .layer(middleware::from_fn(log_request))
        .with_state(state)
}

async fn log_request(request: Request<Body>, next: Next) -> Response {
    let method = request.method().to_string();
    let uri = sanitize_request_uri_for_logs(request.uri());
    let response = next.run(request).await;

    log_response(&method, &uri, &response);

    response
}

fn log_response(default_method: &str, default_uri: &str, response: &Response) {
    let request_context = response.extensions().get::<LoggedRequestContext>();
    let error_code = response
        .extensions()
        .get::<LoggedErrorCode>()
        .map(|value| value.0);

    let Some(request_context) = request_context else {
        log_response_without_request_id(default_method, default_uri, response, error_code);

        return;
    };

    let client = response
        .extensions()
        .get::<LoggedClient>()
        .map(|value| &value.0);
    let mcp_request = response.extensions().get::<LoggedMcpRequest>();
    let upstream_request = response.extensions().get::<LoggedUpstreamRequest>();

    let request_id = request_context.request_id.as_str();
    let method = request_context.method.as_str();
    let uri = request_context.uri.as_str();

    macro_rules! completion {
        ($($field:tt)*) => {
            if logs_at_info(uri) {
                info!($($field)*)
            } else {
                debug!($($field)*)
            }
        };
    }

    match (error_code, client, mcp_request, upstream_request) {
        (Some(error_code), Some(client), Some(mcp_request), Some(upstream_request)) => completion!(
            client = %client,
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
            mcp_method = %mcp_request.mcp_method,
            mcp_name = %mcp_request.mcp_name,
            upstream_api = %upstream_request.api,
            upstream_method = %upstream_request.upstream_method,
            upstream_url = %upstream_request.upstream_url,
            upstream_status = %upstream_request.upstream_status,
            upstream_ms = upstream_request.upstream_ms,
            timeout_ms = upstream_request.timeout_ms,
        ),
        (Some(error_code), Some(client), Some(mcp_request), None) => completion!(
            client = %client,
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
            mcp_method = %mcp_request.mcp_method,
            mcp_name = %mcp_request.mcp_name,
        ),
        (None, Some(client), Some(mcp_request), Some(upstream_request)) => completion!(
            client = %client,
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            mcp_method = %mcp_request.mcp_method,
            mcp_name = %mcp_request.mcp_name,
            upstream_api = %upstream_request.api,
            upstream_method = %upstream_request.upstream_method,
            upstream_url = %upstream_request.upstream_url,
            upstream_status = %upstream_request.upstream_status,
            upstream_ms = upstream_request.upstream_ms,
            timeout_ms = upstream_request.timeout_ms,
        ),
        (None, Some(client), Some(mcp_request), None) => completion!(
            client = %client,
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            mcp_method = %mcp_request.mcp_method,
            mcp_name = %mcp_request.mcp_name,
        ),
        (Some(error_code), Some(client), None, Some(upstream_request)) => completion!(
            client = %client,
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
            upstream_api = %upstream_request.api,
            upstream_method = %upstream_request.upstream_method,
            upstream_url = %upstream_request.upstream_url,
            upstream_status = %upstream_request.upstream_status,
            upstream_ms = upstream_request.upstream_ms,
            timeout_ms = upstream_request.timeout_ms,
        ),
        (Some(error_code), Some(client), None, None) => completion!(
            client = %client,
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
        ),
        (None, Some(client), None, Some(upstream_request)) => completion!(
            client = %client,
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            upstream_api = %upstream_request.api,
            upstream_method = %upstream_request.upstream_method,
            upstream_url = %upstream_request.upstream_url,
            upstream_status = %upstream_request.upstream_status,
            upstream_ms = upstream_request.upstream_ms,
            timeout_ms = upstream_request.timeout_ms,
        ),
        (None, Some(client), None, None) => completion!(
            client = %client,
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
        ),
        (Some(error_code), None, Some(mcp_request), Some(upstream_request)) => completion!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
            mcp_method = %mcp_request.mcp_method,
            mcp_name = %mcp_request.mcp_name,
            upstream_api = %upstream_request.api,
            upstream_method = %upstream_request.upstream_method,
            upstream_url = %upstream_request.upstream_url,
            upstream_status = %upstream_request.upstream_status,
            upstream_ms = upstream_request.upstream_ms,
            timeout_ms = upstream_request.timeout_ms,
        ),
        (Some(error_code), None, Some(mcp_request), None) => completion!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
            mcp_method = %mcp_request.mcp_method,
            mcp_name = %mcp_request.mcp_name,
        ),
        (None, None, Some(mcp_request), Some(upstream_request)) => completion!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            mcp_method = %mcp_request.mcp_method,
            mcp_name = %mcp_request.mcp_name,
            upstream_api = %upstream_request.api,
            upstream_method = %upstream_request.upstream_method,
            upstream_url = %upstream_request.upstream_url,
            upstream_status = %upstream_request.upstream_status,
            upstream_ms = upstream_request.upstream_ms,
            timeout_ms = upstream_request.timeout_ms,
        ),
        (None, None, Some(mcp_request), None) => completion!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            mcp_method = %mcp_request.mcp_method,
            mcp_name = %mcp_request.mcp_name,
        ),
        (Some(error_code), None, None, Some(upstream_request)) => completion!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
            upstream_api = %upstream_request.api,
            upstream_method = %upstream_request.upstream_method,
            upstream_url = %upstream_request.upstream_url,
            upstream_status = %upstream_request.upstream_status,
            upstream_ms = upstream_request.upstream_ms,
            timeout_ms = upstream_request.timeout_ms,
        ),
        (Some(error_code), None, None, None) => completion!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
        ),
        (None, None, None, Some(upstream_request)) => completion!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
            upstream_api = %upstream_request.api,
            upstream_method = %upstream_request.upstream_method,
            upstream_url = %upstream_request.upstream_url,
            upstream_status = %upstream_request.upstream_status,
            upstream_ms = upstream_request.upstream_ms,
            timeout_ms = upstream_request.timeout_ms,
        ),
        (None, None, None, None) => completion!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %response.status(),
        ),
    }
}

fn log_response_without_request_id(
    method: &str,
    uri: &str,
    response: &Response,
    error_code: Option<&'static str>,
) {
    macro_rules! completion {
        ($($field:tt)*) => {
            if logs_at_info(uri) {
                info!($($field)*)
            } else {
                debug!($($field)*)
            }
        };
    }

    if let Some(error_code) = error_code {
        completion!(
            method = %method,
            uri = %uri,
            status = %response.status(),
            error_code,
        );
    } else {
        completion!(
            method = %method,
            uri = %uri,
            status = %response.status(),
        );
    }
}

fn logs_at_info(uri: &str) -> bool {
    uri == "/mcp" || uri.starts_with("/proxy/")
}

async fn health_handler() -> &'static str {
    "OK"
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

async fn proxy_response(state: AppState, api_slug: String, mut request: Request<Body>) -> Response {
    let request_id = generate_internal_request_id();
    request.headers_mut().insert(
        GATE_AGENT_REQUEST_ID_HEADER,
        http::HeaderValue::from_str(&request_id)
            .expect("request id should always be a valid header value"),
    );
    let request_context = LoggedRequestContext {
        request_id: request_id.clone(),
        method: request.method().to_string(),
        uri: sanitize_request_uri_for_logs(request.uri()),
    };

    let mut response = match handle_proxy_request(state, api_slug, request).await {
        Ok(response) => response,
        Err(proxy_error) => {
            let mut response = proxy_error.error.response(Some(&request_id));
            if let Some(client) = proxy_error.client {
                response.extensions_mut().insert(LoggedClient(client));
            }
            response
        }
    };

    response.headers_mut().insert(
        GATE_AGENT_REQUEST_ID_HEADER,
        http::HeaderValue::from_str(&request_id)
            .expect("request id should always be a valid header value"),
    );

    response.extensions_mut().insert(request_context);

    response
}

async fn handle_proxy_request(
    state: AppState,
    api_slug: String,
    request: Request<Body>,
) -> Result<Response, ProxyResponseError> {
    let authorization_header =
        extract_authorization_header(request.headers()).map_err(proxy_error_without_client)?;

    let authorized = validate_bearer_authorized_request(authorization_header, state.secrets())
        .map_err(proxy_error_without_client)?;
    let client_slug = authorized.client_slug.clone();
    let forward = forward_proxy_request(&state, request, &api_slug, authorized)
        .await
        .map_err(|error| proxy_error_with_client(error, client_slug.clone()))?;
    let mut response = forward.response.into_axum_response();
    response.extensions_mut().insert(LoggedClient(client_slug));
    response.extensions_mut().insert(LoggedUpstreamRequest {
        api: api_slug,
        upstream_method: forward.upstream_method,
        upstream_url: sanitize_url_for_logs(&forward.upstream_url),
        upstream_status: forward.upstream_status,
        upstream_ms: forward.upstream_ms,
        timeout_ms: forward.timeout_ms,
    });

    Ok(response)
}

fn proxy_error_without_client(error: AppError) -> ProxyResponseError {
    ProxyResponseError {
        error,
        client: None,
    }
}

fn proxy_error_with_client(error: AppError, client: String) -> ProxyResponseError {
    ProxyResponseError {
        error,
        client: Some(client),
    }
}
