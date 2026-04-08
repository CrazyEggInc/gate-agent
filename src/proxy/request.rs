use axum::body::Body;
use http::{
    HeaderMap, Request, Uri,
    header::{self, HeaderValue},
};
use secrecy::ExposeSecret;
use url::{Position, Url};

use crate::{config::secrets::ApiConfig, error::AppError};

use super::{connection_bound_header_names, is_hop_by_hop_header};

pub fn map_request(
    request: Request<Body>,
    api_slug: &str,
    api_config: &ApiConfig,
) -> Result<reqwest::Request, AppError> {
    let (parts, body) = request.into_parts();
    let raw_suffix = raw_proxy_suffix(&parts.uri, api_slug)?;
    let url = build_upstream_url(&api_config.base_url, &raw_suffix)?;
    let mut outbound_request = reqwest::Request::new(parts.method, url);

    *outbound_request.headers_mut() = filter_request_headers(&parts.headers);
    inject_upstream_auth_header(outbound_request.headers_mut(), api_config)?;
    *outbound_request.body_mut() = Some(reqwest::Body::wrap_stream(body.into_data_stream()));

    Ok(outbound_request)
}

fn raw_proxy_suffix(uri: &Uri, api_slug: &str) -> Result<String, AppError> {
    let Some(path_and_query) = uri.path_and_query().map(|value| value.as_str()) else {
        return Err(AppError::BadProxyPath(
            "proxy request is missing path and query".to_owned(),
        ));
    };

    let proxy_prefix = format!("/proxy/{api_slug}");
    let raw_suffix = path_and_query.strip_prefix(&proxy_prefix).ok_or_else(|| {
        AppError::BadProxyPath(format!("request path must start with {proxy_prefix}"))
    })?;

    if raw_suffix.is_empty() || raw_suffix.starts_with('/') || raw_suffix.starts_with('?') {
        return Ok(raw_suffix.to_owned());
    }

    Err(AppError::BadProxyPath(format!(
        "request path must start with {proxy_prefix}/ or {proxy_prefix}?"
    )))
}

fn build_upstream_url(base_url: &Url, raw_suffix: &str) -> Result<Url, AppError> {
    let (raw_path, query) = match raw_suffix.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (raw_suffix, None),
    };

    let base_path = base_url.path().trim_end_matches('/');
    let joined_path = match raw_path {
        "" => base_path.to_owned(),
        path if path.starts_with('/') => format!("{base_path}{path}"),
        path => format!("{base_path}/{path}"),
    };
    let path_and_query = match query.filter(|value| !value.is_empty()) {
        Some(query) => format!("{joined_path}?{query}"),
        None => joined_path,
    };
    let upstream_url = format!("{}{}", &base_url[..Position::BeforePath], path_and_query);

    Url::parse(&upstream_url)
        .map_err(|error| AppError::UpstreamBuild(format!("failed to build upstream url: {error}")))
}

fn filter_request_headers(headers: &HeaderMap) -> HeaderMap {
    let connection_bound_names = connection_bound_header_names(headers);
    let mut filtered_headers = HeaderMap::new();

    for (name, value) in headers {
        if name == header::AUTHORIZATION
            || name == header::HOST
            || is_hop_by_hop_header(name, &connection_bound_names)
        {
            continue;
        }

        filtered_headers.append(name.clone(), value.clone());
    }

    filtered_headers
}

fn inject_upstream_auth_header(
    headers: &mut HeaderMap,
    api_config: &ApiConfig,
) -> Result<(), AppError> {
    let auth_value = match api_config.auth_scheme.as_deref() {
        Some(scheme) => format!("{scheme} {}", api_config.auth_value.expose_secret()),
        None => api_config.auth_value.expose_secret().to_owned(),
    };
    let auth_value = HeaderValue::from_str(&auth_value).map_err(|error| {
        AppError::UpstreamBuild(format!("invalid upstream auth header: {error}"))
    })?;

    headers.insert(api_config.auth_header.clone(), auth_value);

    Ok(())
}
