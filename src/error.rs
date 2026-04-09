use axum::{
    Json,
    http::{
        StatusCode,
        header::{HeaderValue, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct LoggedErrorCode(pub &'static str);

#[derive(Debug, Error)]
pub enum AppError {
    #[error("config load failed: {0}")]
    ConfigLoad(String),
    #[error("secrets load failed: {0}")]
    SecretsLoad(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("api key validation failed")]
    InvalidApiKey,
    #[error("token validation failed")]
    InvalidToken,
    #[error("api is not allowed: {api}")]
    ForbiddenApi { api: String },
    #[error("bad proxy path: {0}")]
    BadProxyPath(String),
    #[error("failed to build upstream request: {0}")]
    UpstreamBuild(String),
    #[error("upstream request failed: {0}")]
    UpstreamRequest(String),
    #[error("upstream request timed out")]
    UpstreamTimeout,
    #[error("failed to map upstream response: {0}")]
    ResponseMapping(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorPayload {
    pub error: ErrorPayloadBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorPayloadBody {
    pub code: &'static str,
    pub message: &'static str,
    pub request_id: Option<String>,
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::InvalidApiKey => StatusCode::UNAUTHORIZED,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::ForbiddenApi { .. } => StatusCode::FORBIDDEN,
            Self::BadProxyPath(_) => StatusCode::BAD_REQUEST,
            Self::UpstreamBuild(_) | Self::UpstreamRequest(_) | Self::ResponseMapping(_) => {
                StatusCode::BAD_GATEWAY
            }
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::ConfigLoad(_) | Self::SecretsLoad(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::ConfigLoad(_) => "config_load",
            Self::SecretsLoad(_) => "secrets_load",
            Self::BadRequest(_) => "bad_request",
            Self::InvalidApiKey => "invalid_api_key",
            Self::InvalidToken => "invalid_token",
            Self::ForbiddenApi { .. } => "forbidden_api",
            Self::BadProxyPath(_) => "bad_proxy_path",
            Self::UpstreamBuild(_) => "upstream_build",
            Self::UpstreamRequest(_) => "upstream_request",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::ResponseMapping(_) => "response_mapping",
            Self::Internal(_) => "internal",
        }
    }

    pub fn safe_message(&self) -> &'static str {
        match self {
            Self::ConfigLoad(_) | Self::SecretsLoad(_) | Self::Internal(_) => {
                "internal server error"
            }
            Self::BadRequest(_) => "request is invalid",
            Self::InvalidApiKey => "authentication failed",
            Self::InvalidToken => "authentication failed",
            Self::ForbiddenApi { .. } => "api access is forbidden",
            Self::BadProxyPath(_) => "request path is invalid",
            Self::UpstreamBuild(_) => "failed to build upstream request",
            Self::UpstreamRequest(_) => "upstream request failed",
            Self::UpstreamTimeout => "upstream request timed out",
            Self::ResponseMapping(_) => "failed to map upstream response",
        }
    }

    pub fn payload(&self, request_id: Option<&str>) -> ErrorPayload {
        ErrorPayload {
            error: ErrorPayloadBody {
                code: self.code(),
                message: self.safe_message(),
                request_id: request_id.map(str::to_owned),
            },
        }
    }

    pub fn response(&self, request_id: Option<&str>) -> Response {
        let mut response = (self.status_code(), Json(self.payload(request_id))).into_response();
        response
            .extensions_mut()
            .insert(LoggedErrorCode(self.code()));

        if matches!(self, Self::InvalidToken) {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{StatusCode, header::WWW_AUTHENTICATE};
    use serde_json::json;

    use super::AppError;

    #[test]
    fn invalid_token_maps_to_expected_http_payload() {
        let error = AppError::InvalidToken;
        let payload = error.payload(Some("req-123"));

        assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(payload.error.code, "invalid_token");
        assert_eq!(payload.error.message, "authentication failed");
        assert_eq!(payload.error.request_id.as_deref(), Some("req-123"));
    }

    #[test]
    fn internal_payload_keeps_request_id_field_when_missing() {
        let payload = AppError::Internal("boom".to_owned()).payload(None);

        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            json!({
                "error": {
                    "code": "internal",
                    "message": "internal server error",
                    "request_id": null
                }
            })
        );
    }

    #[test]
    fn invalid_token_response_includes_www_authenticate_header() {
        let response = AppError::InvalidToken.response(Some("req-123"));

        assert_eq!(response.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");
    }
}
