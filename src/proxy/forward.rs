use axum::body::Body;

use crate::{
    app::AppState,
    auth::bearer::{AuthorizedRequest, api_access_allows},
    error::AppError,
};

use super::{
    request::{ForwardRequest, forward_request_from_proxy_request, map_forward_request},
    response::{ForwardedResponse, map_response},
    upstream::execute_request,
};

#[derive(Debug)]
pub struct PreparedForwardRequest {
    pub request: ForwardRequest,
}

#[derive(Debug)]
pub struct ForwardSuccess {
    pub response: ForwardedResponse,
    pub upstream_method: String,
    pub upstream_url: String,
    pub upstream_status: String,
    pub timeout_ms: u64,
}

pub fn prepare_authorized_forward_request(
    request: ForwardRequest,
    authorized: &AuthorizedRequest,
) -> Result<PreparedForwardRequest, AppError> {
    authorize_forward_request(&request, authorized)?;

    Ok(PreparedForwardRequest { request })
}

pub fn prepare_proxy_forward_request(
    request: axum::http::Request<Body>,
    api_slug: &str,
    authorized: AuthorizedRequest,
) -> Result<PreparedForwardRequest, AppError> {
    let request = forward_request_from_proxy_request(request, api_slug)?;
    prepare_authorized_forward_request(request, &authorized)
}

fn authorize_forward_request(
    request: &ForwardRequest,
    authorized: &AuthorizedRequest,
) -> Result<(), AppError> {
    if request.method == http::Method::TRACE {
        return Err(AppError::BadRequest(
            "TRACE requests are not supported".to_owned(),
        ));
    }

    if api_access_allows(
        authorized,
        &request.api_slug,
        &request.method,
        &request.path_and_query,
    ) {
        return Ok(());
    }

    Err(AppError::ForbiddenApi {
        api: request.api_slug.clone(),
    })
}

pub async fn forward_prepared_request(
    state: &AppState,
    prepared: PreparedForwardRequest,
) -> Result<ForwardSuccess, AppError> {
    let api_config = state.api_config(&prepared.request.api_slug)?;
    let timeout_ms = api_config.timeout_ms;
    let outbound_request = map_forward_request(prepared.request, api_config)?;
    let upstream_method = outbound_request.method().to_string();
    let upstream_url = outbound_request.url().to_string();
    let upstream_response = execute_request(state.client(), outbound_request, timeout_ms).await?;
    let upstream_status = upstream_response.status().to_string();
    let response = map_response(upstream_response)?;

    Ok(ForwardSuccess {
        response,
        upstream_method,
        upstream_url,
        upstream_status,
        timeout_ms,
    })
}

pub async fn forward_proxy_request(
    state: &AppState,
    request: axum::http::Request<Body>,
    api_slug: &str,
    authorized: AuthorizedRequest,
) -> Result<ForwardSuccess, AppError> {
    let prepared = prepare_proxy_forward_request(request, api_slug, authorized)?;

    forward_prepared_request(state, prepared).await
}
