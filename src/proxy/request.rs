use axum::body::Body;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{
    HeaderMap, Method, Request, Uri,
    header::{self, HeaderName, HeaderValue},
};
use secrecy::ExposeSecret;
use std::collections::HashSet;
use url::{Position, Url};

use crate::{config::secrets::ApiConfig, error::AppError};

use super::{connection_bound_header_names, is_hop_by_hop_header};

#[derive(Debug)]
pub struct ForwardRequest {
    pub api_slug: String,
    pub method: Method,
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: Body,
}

impl ForwardRequest {
    pub fn path_only(&self) -> &str {
        let path = self
            .path_and_query
            .split_once('?')
            .map_or(self.path_and_query.as_str(), |(path, _)| path);

        if path.is_empty() { "/" } else { path }
    }
}

pub fn map_request(
    request: Request<Body>,
    api_slug: &str,
    api_config: &ApiConfig,
) -> Result<reqwest::Request, AppError> {
    let request = forward_request_from_proxy_request(request, api_slug)?;

    map_forward_request(request, api_config)
}

pub fn forward_request_from_proxy_request(
    request: Request<Body>,
    api_slug: &str,
) -> Result<ForwardRequest, AppError> {
    let (parts, body) = request.into_parts();
    let path_and_query = raw_proxy_suffix(&parts.uri, api_slug)?;

    Ok(ForwardRequest {
        api_slug: api_slug.to_owned(),
        method: parts.method,
        path_and_query,
        headers: parts.headers,
        body,
    })
}

pub fn map_forward_request(
    request: ForwardRequest,
    api_config: &ApiConfig,
) -> Result<reqwest::Request, AppError> {
    let ForwardRequest {
        method,
        path_and_query,
        headers,
        body,
        ..
    } = request;
    let url = build_upstream_url(&api_config.base_url, &path_and_query)?;
    let mut outbound_request = reqwest::Request::new(method, url);

    *outbound_request.headers_mut() = filter_request_headers(&headers);
    overlay_configured_headers(outbound_request.headers_mut(), api_config)?;
    overlay_basic_auth(outbound_request.headers_mut(), api_config)?;
    if !matches!(*outbound_request.method(), Method::GET | Method::HEAD) {
        *outbound_request.body_mut() = Some(reqwest::Body::wrap_stream(body.into_data_stream()));
    }

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

    reject_dot_segments(raw_path)?;

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

fn reject_dot_segments(raw_path: &str) -> Result<(), AppError> {
    if raw_path.split('/').any(is_dot_segment) {
        return Err(AppError::BadProxyPath(
            "request path must not contain dot segments".to_owned(),
        ));
    }

    Ok(())
}

fn is_dot_segment(segment: &str) -> bool {
    let decoded = decode_percent_encoded_dots(segment);

    matches!(decoded.as_str(), "." | "..")
}

fn decode_percent_encoded_dots(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut decoded = String::with_capacity(segment.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            && (high << 4) | low == b'.'
        {
            decoded.push('.');
            index += 3;
            continue;
        }

        decoded.push(bytes[index] as char);
        index += 1;
    }

    decoded
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn filter_request_headers(headers: &HeaderMap) -> HeaderMap {
    let connection_bound_names = connection_bound_header_names(headers);
    let mut filtered_headers = HeaderMap::new();

    for (name, value) in headers {
        if name == header::AUTHORIZATION
            || name == header::HOST
            || name == header::CONTENT_LENGTH
            || is_client_forwarding_header(name)
            || is_hop_by_hop_header(name, &connection_bound_names)
        {
            continue;
        }

        filtered_headers.append(name.clone(), value.clone());
    }

    filtered_headers
}

fn is_client_forwarding_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-forwarded-prefix"
            | "x-real-ip"
            | "via"
    )
}

fn overlay_configured_headers(
    headers: &mut HeaderMap,
    api_config: &ApiConfig,
) -> Result<(), AppError> {
    for (name, value) in &api_config.headers {
        if is_reserved_configured_header(name) {
            return Err(AppError::UpstreamBuild(format!(
                "reserved header in config: {name}"
            )));
        }

        let value = HeaderValue::from_str(value.expose_secret()).map_err(|error| {
            AppError::UpstreamBuild(format!("invalid configured upstream header: {error}"))
        })?;
        headers.insert(name.clone(), value);
    }

    Ok(())
}

fn overlay_basic_auth(headers: &mut HeaderMap, api_config: &ApiConfig) -> Result<(), AppError> {
    let Some(basic_auth) = &api_config.basic_auth else {
        return Ok(());
    };

    let value = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            basic_auth.username,
            basic_auth.password.expose_secret()
        ))
    );
    let value = HeaderValue::from_str(&value).map_err(|error| {
        AppError::UpstreamBuild(format!("invalid configured upstream basic auth: {error}"))
    })?;
    headers.insert(header::AUTHORIZATION, value);

    Ok(())
}

fn is_reserved_configured_header(name: &HeaderName) -> bool {
    let connection_bound_names = HashSet::new();

    name == header::HOST
        || is_client_forwarding_header(name)
        || is_hop_by_hop_header(name, &connection_bound_names)
}
