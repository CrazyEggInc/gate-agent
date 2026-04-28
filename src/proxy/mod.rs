use std::collections::HashSet;

use http::{HeaderMap, HeaderName, header};

pub mod forward;
pub mod request;
pub mod response;
pub mod router;
pub mod upstream;

pub(crate) fn connection_bound_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect()
}

pub(crate) fn is_hop_by_hop_header(
    name: &HeaderName,
    connection_bound_names: &HashSet<HeaderName>,
) -> bool {
    let keep_alive = HeaderName::from_static("keep-alive");

    connection_bound_names.contains(name)
        || name == header::CONNECTION
        || name == keep_alive
        || name == header::PROXY_AUTHENTICATE
        || name == header::PROXY_AUTHORIZATION
        || name == header::TE
        || name == header::TRAILER
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("proxy-connection")
}
