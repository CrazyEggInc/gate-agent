use axum::{body::Body, response::Response};
use bytes::Bytes;
use http::{HeaderMap, StatusCode};

use crate::error::AppError;

use super::{connection_bound_header_names, is_hop_by_hop_header};

#[derive(Debug)]
pub struct ForwardedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    upstream_response: reqwest::Response,
}

impl ForwardedResponse {
    pub fn into_axum_response(self) -> Response {
        let mut response = Response::new(Body::from_stream(self.upstream_response.bytes_stream()));

        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;

        response
    }

    pub fn into_body_stream(
        self,
    ) -> impl futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> {
        self.upstream_response.bytes_stream()
    }

    pub async fn into_bytes(self) -> Result<Bytes, AppError> {
        self.upstream_response.bytes().await.map_err(|error| {
            AppError::ResponseMapping(format!("failed to read upstream response body: {error}"))
        })
    }
}

pub fn map_response(upstream_response: reqwest::Response) -> Result<ForwardedResponse, AppError> {
    let status = upstream_response.status();
    let headers = filter_response_headers(upstream_response.headers());

    Ok(ForwardedResponse {
        status,
        headers,
        upstream_response,
    })
}

fn filter_response_headers(headers: &HeaderMap) -> HeaderMap {
    let connection_bound_names = connection_bound_header_names(headers);
    let mut filtered_headers = HeaderMap::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name, &connection_bound_names)
            || is_sensitive_response_header(name.as_str())
        {
            continue;
        }

        filtered_headers.append(name.clone(), value.clone());
    }

    filtered_headers
}

fn is_sensitive_response_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();

    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "set-cookie"
            | "www-authenticate"
    ) || name.contains("token")
        || name.contains("secret")
        || name.contains("api-key")
}
