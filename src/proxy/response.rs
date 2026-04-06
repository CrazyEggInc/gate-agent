use axum::{body::Body, response::Response};
use http::HeaderMap;

use crate::error::AppError;

use super::{connection_bound_header_names, is_hop_by_hop_header};

pub fn map_response(upstream_response: reqwest::Response) -> Result<Response, AppError> {
    let status = upstream_response.status();
    let headers = filter_response_headers(upstream_response.headers());
    let body = Body::from_stream(upstream_response.bytes_stream());
    let mut response = Response::new(body);

    *response.status_mut() = status;
    *response.headers_mut() = headers;

    Ok(response)
}

fn filter_response_headers(headers: &HeaderMap) -> HeaderMap {
    let connection_bound_names = connection_bound_header_names(headers);
    let mut filtered_headers = HeaderMap::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name, &connection_bound_names) {
            continue;
        }

        filtered_headers.append(name.clone(), value.clone());
    }

    filtered_headers
}
