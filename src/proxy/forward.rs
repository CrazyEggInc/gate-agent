use std::time::Instant;

use axum::body::Body;

use crate::{
    app::AppState,
    auth::bearer::{AuthorizedRequest, api_access_allows},
    error::AppError,
};

use super::{
    request::{
        ForwardRequest, forward_request_from_proxy_request, has_dot_segment,
        map_forward_request_with_token,
    },
    response::{ForwardedResponse, map_response},
    upstream::execute_request,
    upstream_auth::AuthResolution,
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
    pub upstream_ms: u128,
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
    if has_dot_segment(request.path_only()) {
        return Err(AppError::BadProxyPath(
            "request path must not contain dot segments".to_owned(),
        ));
    }

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
    let upstream_started = Instant::now();
    let auth_token = if let Some(auth_config) = &api_config.auth {
        let auth_state = state.api_auth_state(&api_config.slug).ok_or_else(|| {
            AppError::Internal(format!(
                "missing dynamic auth state for '{}'",
                api_config.slug
            ))
        })?;
        match auth_state.resolve(state.client(), api_config).await? {
            AuthResolution::Token(token) => Some(token),
            AuthResolution::EndpointResponse(response) => {
                let upstream_status = response.status().to_string();
                let upstream_url = response.url().to_string();
                let response = map_response(response)?;
                return Ok(ForwardSuccess {
                    response,
                    upstream_method: auth_config.method.to_string(),
                    upstream_url,
                    upstream_status,
                    upstream_ms: upstream_started.elapsed().as_millis(),
                    timeout_ms,
                });
            }
        }
    } else {
        None
    };
    let outbound_request = map_forward_request_with_token(
        prepared.request,
        api_config,
        auth_token.as_ref().map(|token| &token.value),
    )?;
    let upstream_method = outbound_request.method().to_string();
    let upstream_url = outbound_request.url().to_string();
    let upstream_response = execute_request(state.client(), outbound_request, timeout_ms).await?;
    let upstream_ms = upstream_started.elapsed().as_millis();
    let upstream_status = upstream_response.status().to_string();
    if upstream_response.status() == http::StatusCode::UNAUTHORIZED
        && let Some(token) = auth_token.as_ref()
        && let Some(auth_state) = state.api_auth_state(&api_config.slug)
    {
        auth_state.invalidate(token).await;
    }
    let response = map_response(upstream_response)?;

    Ok(ForwardSuccess {
        response,
        upstream_method,
        upstream_url,
        upstream_status,
        upstream_ms,
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
