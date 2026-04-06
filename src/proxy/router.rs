use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    response::Response,
    routing::any,
};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
};

use crate::app::AppState;
use crate::auth::jwt::validate_bearer_token;
use crate::error::AppError;

use super::{request::map_request, response::map_response, upstream::execute_request};

const ROUTER_TIMEOUT_SECS: u64 = 60;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/proxy", any(proxy_handler))
        .route("/proxy/", any(proxy_handler))
        .route("/proxy/{*path}", any(proxy_handler))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(ROUTER_TIMEOUT_SECS),
        ))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        .with_state(state)
}

async fn proxy_handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    proxy_response(state, request).await
}

async fn proxy_response(state: AppState, request: Request<Body>) -> Response {
    let request_id = request_id_from_request(&request);

    let mut response = match handle_proxy_request(state, request).await {
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

async fn handle_proxy_request(
    state: AppState,
    request: Request<Body>,
) -> Result<Response, AppError> {
    let authorization_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::InvalidToken)?;

    let claims = validate_bearer_token(authorization_header, state.secrets())?;
    let api_config = state.api_config(&claims.api)?;
    let outbound_request = map_request(request, api_config)?;
    let upstream_response = execute_request(state.client(), outbound_request, api_config).await?;

    map_response(upstream_response)
}

fn request_id_from_request(request: &Request<Body>) -> Option<String> {
    request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
