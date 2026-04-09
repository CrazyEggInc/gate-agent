use std::path::PathBuf;

use axum::{
    body::Body,
    http::{Request, StatusCode, header::HeaderValue},
};
use gate_agent::{
    app::AppState,
    auth::{exchange::ExchangeResponse, jwt::validate_token},
    config::{app_config::AppConfig, secrets::SecretsConfig},
    proxy::router::build_router,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn write_secrets_file(
    contents: &str,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    std::fs::write(&secrets_file, contents)?;
    Ok((temp_dir, secrets_file))
}

fn load_config(contents: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_secrets_file(contents)?;

    Ok(AppConfig {
        bind: "127.0.0.1:0".parse()?,
        log_level: "debug".to_owned(),
        config_file: config_file.clone(),
        secrets: SecretsConfig::load_from_file(&config_file)?,
    })
}

const VALID_SECRETS: &str = r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "default-client-key"
api_key_expires_at = "2030-01-02T03:04:05Z"
allowed_apis = ["projects", "billing"]

[clients.partner]
api_key = "partner-client-key"
api_key_expires_at = "2030-01-03T03:04:05Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000

[apis.billing]
base_url = "https://billing.internal.example"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#;

#[tokio::test]
async fn auth_exchange_returns_server_signed_token_for_one_api()
-> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["PROJECTS"]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let exchange: ExchangeResponse =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    let claims = validate_token(&exchange.access_token, &config.secrets)?;

    assert_eq!(exchange.token_type, "Bearer");
    assert_eq!(exchange.expires_in, 600);
    assert_eq!(claims.sub, "default");
    assert_eq!(claims.apis(), vec!["projects"]);
    assert_eq!(claims.iss, "gate-agent-dev");
    assert_eq!(claims.aud, "gate-agent-clients");
    assert_eq!(claims.exp - claims.iat, 600);

    Ok(())
}

#[tokio::test]
async fn auth_exchange_normalizes_multiple_requested_apis_before_signing()
-> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["Projects","billing","projects"]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let exchange: ExchangeResponse =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    let claims = validate_token(&exchange.access_token, &config.secrets)?;

    assert_eq!(claims.sub, "default");
    assert_eq!(claims.apis(), vec!["billing", "projects"]);
    assert_eq!(claims.exp - claims.iat, 600);

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_empty_api_list() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":[]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "bad_request");

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_unknown_api_for_entire_request()
-> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["projects","missing"]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "forbidden_api");

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_unauthorized_api_for_entire_request()
-> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "partner-client-key")
                .body(Body::from(r#"{"apis":["projects","billing"]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "forbidden_api");

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_expired_api_key() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "rotate-me"

[clients.default]
api_key = "expired-client-key"
api_key_expires_at = "2020-01-02T03:04:05Z"
allowed_apis = ["projects"]

[apis.projects]
base_url = "https://projects.internal.example"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000
"#,
    )?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "expired-client-key")
                .body(Body::from(r#"{"apis":["projects"]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "invalid_api_key");

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_duplicate_x_api_key_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);
    let mut request = Request::builder()
        .method("POST")
        .uri("/auth/exchange")
        .header("content-type", "application/json")
        .header("x-request-id", "req-duplicate-key")
        .body(Body::from(r#"{"apis":["projects"]}"#))?;
    request
        .headers_mut()
        .append("x-api-key", HeaderValue::from_static("default-client-key"));
    request
        .headers_mut()
        .append("x-api-key", HeaderValue::from_static("default-client-key"));

    let response = app.oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "req-duplicate-key"
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "invalid_api_key");
    assert_eq!(payload["error"]["request_id"], "req-duplicate-key");

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_blank_x_api_key_header() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "   ")
                .body(Body::from(r#"{"apis":["projects"]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "invalid_api_key");

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_api_slug_with_slash_as_bad_request()
-> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["projects/api"]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "bad_request");

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_api_slug_with_trailing_space_as_bad_request()
-> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["projects "]}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "bad_request");

    Ok(())
}

#[tokio::test]
async fn auth_exchange_rejects_oversized_body_as_bad_request()
-> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(VALID_SECRETS)?;
    let app = build_router(AppState::from_config(&config)?);
    let oversized_api = "a".repeat(20_000);
    let payload = serde_json::json!({ "apis": [oversized_api] }).to_string();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(payload))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "bad_request");

    Ok(())
}
