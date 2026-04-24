use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

mod support;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode, header::HeaderValue},
    routing::any,
};
use gate_agent::{
    app::AppState,
    commands::config::{
        ConfigApiArgs, ConfigApiAuthSelection, ConfigGroupArgs, apply_api, apply_group,
    },
    config::{
        ConfigSource,
        app_config::AppConfig,
        secrets::{AccessLevel, SecretsConfig},
        write,
    },
    proxy::router::build_router,
};
use http_body_util::BodyExt;
use support::{
    bearer_token, bearer_token_for_client, bearer_token_with_access, capture_channel,
    capture_request, expired_bearer_token, load_multi_api_test_config,
    load_multi_api_test_config_without_projects_auth_header, load_test_config,
    load_test_config_with_billing_basic_auth, load_test_config_with_billing_timeout,
    spawn_chunked_upstream, spawn_upstream,
};
use tempfile::tempdir;
use tower::ServiceExt;

async fn assert_upstream_redirect_is_followed(
    redirect_status: StatusCode,
) -> Result<(), Box<dyn std::error::Error>> {
    let redirect_target_hits = Arc::new(AtomicUsize::new(0));
    let upstream = Router::new()
        .route(
            "/api/redirect",
            any(move || async move {
                let mut response = Response::new(Body::from("redirect response"));
                *response.status_mut() = redirect_status;
                response
                    .headers_mut()
                    .insert("location", HeaderValue::from_static("/api/redirect-target"));
                response
            }),
        )
        .route(
            "/api/redirect-target",
            any(
                |State(redirect_target_hits): State<Arc<AtomicUsize>>| async move {
                    redirect_target_hits.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK
                },
            ),
        )
        .with_state(redirect_target_hits.clone());
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/redirect")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(body, bytes::Bytes::from_static(b""));
    assert_eq!(redirect_target_hits.load(Ordering::SeqCst), 1);

    Ok(())
}

#[tokio::test]
async fn proxy_route_forwards_only_suffix_after_api_segment_and_injects_request_id()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route(
            "/api/{*path}",
            any(
                |State(sender): State<support::CaptureSender>, request: Request<Body>| async move {
                    capture_request(State(sender), request).await;

                    let mut response = Response::new(Body::from("upstream ok"));
                    *response.status_mut() = StatusCode::CREATED;
                    response
                        .headers_mut()
                        .insert("x-upstream", HeaderValue::from_static("present"));
                    response
                },
            ),
        )
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token_for_client("default", "billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/proxy/billing/v1/projects/1/tasks?expand=1")
                .header("authorization", format!("Bearer {token}"))
                .header("x-custom", "preserved")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"New task"}"#))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers().get("x-upstream").unwrap(), "present");
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("response request id")
        .to_str()?
        .to_owned();
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(body, bytes::Bytes::from_static(b"upstream ok"));

    let captured = rx.await?;
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path_and_query, "/api/v1/projects/1/tasks?expand=1");
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        "Bearer billing-secret-token"
    );
    assert_eq!(captured.headers.get("x-custom").unwrap(), "preserved");
    assert_eq!(
        captured.headers.get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(
        captured.headers.get("x-request-id").unwrap(),
        request_id.as_str()
    );
    assert_eq!(
        captured.body,
        bytes::Bytes::from_static(br#"{"name":"New task"}"#)
    );

    Ok(())
}

#[tokio::test]
async fn proxy_route_uses_api_segment_for_billing_multi_api_token()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_multi_api_test_config(&base_url)?;
    let token = bearer_token_for_client("default", "billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let billing_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/path")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(billing_response.status(), StatusCode::OK);

    let billing_request = rx.await?;
    assert_eq!(billing_request.path_and_query, "/api/path");
    assert_eq!(
        billing_request.headers.get("authorization").unwrap(),
        "Bearer billing-secret-token"
    );
    assert!(billing_request.headers.get("x-api-key").is_none());

    Ok(())
}

#[tokio::test]
async fn proxy_route_forwards_configured_basic_auth() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/api/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config_with_billing_basic_auth(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/v1/projects/1/tasks")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.path_and_query, "/api/v1/projects/1/tasks");
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        "Basic YmlsbGluZy11c2VyOmJpbGxpbmctcGFzcw=="
    );

    Ok(())
}

#[tokio::test]
async fn proxy_route_forwards_basic_auth_written_by_config_api()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/api/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("gate-agent.toml");
    let token = write::init_config_with_default_bearer_token(&config_path, false, None)?;

    apply_api(ConfigApiArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: "debug".to_owned(),
        name: "billing".to_owned(),
        delete: false,
        base_url: Some(format!("{base_url}/api")),
        headers: None,
        auth: ConfigApiAuthSelection::Basic {
            username: "billing-user".to_owned(),
            password: Some("billing-pass".to_owned()),
        },
        timeout_ms: Some(5_000),
    })?;

    apply_group(ConfigGroupArgs {
        config: Some(config_path.clone()),
        password: None,
        log_level: "debug".to_owned(),
        name: "local-default".to_owned(),
        delete: false,
        api_access: vec!["billing=write".to_owned()],
    })?;

    let config = AppConfig::new(
        "127.0.0.1:0".parse()?,
        "debug",
        ConfigSource::Path(config_path.clone()),
        SecretsConfig::load_from_file(&config_path)?,
    );
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/v1/invoices")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.path_and_query, "/api/v1/invoices");
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        "Basic YmlsbGluZy11c2VyOmJpbGxpbmctcGFzcw=="
    );

    Ok(())
}

#[tokio::test]
async fn proxy_route_strips_client_forwarding_headers_before_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/api/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/v1/projects/1/tasks")
                .header("authorization", format!("Bearer {token}"))
                .header("forwarded", "for=203.0.113.9;proto=https;host=evil.example")
                .header("x-forwarded-for", "203.0.113.10")
                .header("x-forwarded-host", "evil.example")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-port", "443")
                .header("x-forwarded-prefix", "/spoofed")
                .header("x-real-ip", "203.0.113.11")
                .header("via", "1.1 attacker-proxy")
                .header("x-custom", "preserved")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.path_and_query, "/api/v1/projects/1/tasks");
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        "Bearer billing-secret-token"
    );
    assert_eq!(captured.headers.get("x-custom").unwrap(), "preserved");
    assert!(captured.headers.get("forwarded").is_none());
    assert!(captured.headers.get("x-forwarded-for").is_none());
    assert!(captured.headers.get("x-forwarded-host").is_none());
    assert!(captured.headers.get("x-forwarded-proto").is_none());
    assert!(captured.headers.get("x-forwarded-port").is_none());
    assert!(captured.headers.get("x-forwarded-prefix").is_none());
    assert!(captured.headers.get("x-real-ip").is_none());
    assert!(captured.headers.get("via").is_none());

    Ok(())
}

#[tokio::test]
async fn proxy_route_uses_api_segment_for_projects_multi_api_token()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_multi_api_test_config(&base_url)?;
    let token = bearer_token_for_client("default", "projects", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let projects_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proxy/projects/path?expand=1")
                .header("authorization", format!("Bearer {token}"))
                .header("x-api-key", "client-collision-value")
                .header("x-custom", "preserved")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(projects_response.status(), StatusCode::OK);

    let projects_request = rx.await?;
    assert_eq!(projects_request.path_and_query, "/path?expand=1");
    assert_eq!(
        projects_request.headers.get("x-api-key").unwrap(),
        "projects-secret-value"
    );
    assert_eq!(
        projects_request.headers.get("x-custom").unwrap(),
        "preserved"
    );
    assert!(projects_request.headers.get("authorization").is_none());

    Ok(())
}

#[tokio::test]
async fn proxy_route_does_not_inject_upstream_auth_when_api_has_no_auth_header()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_multi_api_test_config_without_projects_auth_header(&base_url)?;
    let token = bearer_token_for_client("default", "projects", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/projects/path?expand=1")
                .header("authorization", format!("Bearer {token}"))
                .header("x-custom", "preserved")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.path_and_query, "/path?expand=1");
    assert_eq!(captured.headers.get("x-custom").unwrap(), "preserved");
    assert!(captured.headers.get("authorization").is_none());
    assert!(captured.headers.get("x-api-key").is_none());

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_multi_api_client_without_configured_billing_access()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_multi_api_test_config(&base_url)?;
    let token = bearer_token_for_client("partner", "projects", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/path")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "forbidden_api");

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_selected_api_not_present_in_token()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token_for_client("default", "billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/projects/v1/projects/1/tasks")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "forbidden_api");

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_unknown_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/v1/projects/1/tasks")
                .header("authorization", "Bearer unknown-client.not-a-real-secret")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "invalid_token");

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_expired_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = expired_bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/v1/projects/1/tasks")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(
        payload["error"]["code"],
        serde_json::Value::String("invalid_token".to_owned())
    );

    Ok(())
}

#[tokio::test]
async fn proxy_route_returns_consistent_invalid_token_error_with_request_id_for_malformed_bearer_token()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/projects/v1/projects")
                .header("x-request-id", "req-test-123")
                .header("authorization", "Bearer not-a-valid-token")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "req-test-123"
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(
        payload,
        serde_json::json!({
            "error": {
                "code": "invalid_token",
                "message": "authentication failed",
                "request_id": "req-test-123"
            }
        })
    );

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_duplicate_authorization_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);
    let mut request = Request::builder()
        .uri("/proxy/billing/v1/projects")
        .header("x-request-id", "req-duplicate-auth")
        .body(Body::empty())?;
    request.headers_mut().append(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    request.headers_mut().append(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );

    let response = app.oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "req-duplicate-auth"
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "invalid_token");
    assert_eq!(payload["error"]["request_id"], "req-duplicate-auth");

    Ok(())
}

#[tokio::test]
async fn proxy_route_maps_upstream_timeout_to_gateway_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route(
        "/api/{*path}",
        any(|| async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            StatusCode::OK
        }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config_with_billing_timeout(&base_url, 50)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/slow")
                .header("x-request-id", "req-timeout")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(
        payload,
        serde_json::json!({
            "error": {
                "code": "upstream_timeout",
                "message": "upstream request timed out",
                "request_id": "req-timeout"
            }
        })
    );

    Ok(())
}

#[tokio::test]
async fn proxy_route_follows_upstream_redirects() -> Result<(), Box<dyn std::error::Error>> {
    assert_upstream_redirect_is_followed(StatusCode::FOUND).await?;
    assert_upstream_redirect_is_followed(StatusCode::TEMPORARY_REDIRECT).await?;

    Ok(())
}

#[tokio::test]
async fn proxy_route_preserves_raw_encoded_path_and_query() -> Result<(), Box<dyn std::error::Error>>
{
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/api/", any(capture_request))
        .route("/api/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/v1/files/a%2Fb?expand=%2F&literal=%252F")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(
        captured.path_and_query,
        "/api/v1/files/a%2Fb?expand=%2F&literal=%252F"
    );
    assert_eq!(captured.body, bytes::Bytes::new());

    Ok(())
}

#[tokio::test]
async fn proxy_route_forwards_empty_suffix_to_upstream_base_path_without_using_wildcard_route()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let wildcard_hits = Arc::new(AtomicUsize::new(0));
    let exact_sender = sender.clone();
    let wildcard_hits_for_route = wildcard_hits.clone();
    let upstream = Router::new()
        .route(
            "/api",
            any(move |request: Request<Body>| {
                let sender = exact_sender.clone();
                async move { capture_request(State(sender), request).await }
            }),
        )
        .route(
            "/api/{*path}",
            any(move |_request: Request<Body>| {
                let wildcard_hits = wildcard_hits_for_route.clone();
                async move {
                    wildcard_hits.fetch_add(1, Ordering::SeqCst);
                    StatusCode::CREATED
                }
            }),
        );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.path_and_query, "/api");
    assert_eq!(captured.body, bytes::Bytes::new());
    assert_eq!(wildcard_hits.load(Ordering::SeqCst), 0);

    Ok(())
}

#[tokio::test]
async fn proxy_route_preserves_trailing_api_route_slash() -> Result<(), Box<dyn std::error::Error>>
{
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/api/", any(capture_request))
        .route("/api/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.path_and_query, "/api/");
    assert_eq!(captured.body, bytes::Bytes::new());

    Ok(())
}

#[tokio::test]
async fn proxy_route_preserves_double_slash_segments() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/api/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing//double")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.path_and_query, "/api//double");
    assert_eq!(captured.body, bytes::Bytes::new());

    Ok(())
}

#[tokio::test]
async fn proxy_route_allows_get_with_read_token() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/api/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token_with_access("billing", AccessLevel::Read, config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/proxy/billing/v1/projects/1/tasks")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.path_and_query, "/api/v1/projects/1/tasks");

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_post_with_read_token() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token_with_access("billing", AccessLevel::Read, config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/proxy/billing/v1/projects/1/tasks")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "forbidden_api");

    Ok(())
}

#[tokio::test]
async fn proxy_route_allows_delete_with_write_token() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/api/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/proxy/billing/v1/projects/1/tasks")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let captured = rx.await?;
    assert_eq!(captured.method, "DELETE");
    assert_eq!(captured.path_and_query, "/api/v1/projects/1/tasks");

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_custom_method_with_read_token()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token_with_access("billing", AccessLevel::Read, config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("TRACE")
                .uri("/proxy/billing/v1/projects/1/tasks")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "forbidden_api");

    Ok(())
}

#[tokio::test]
async fn proxy_route_authorizes_multi_api_token_by_route_api_and_method_required_access()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_multi_api_test_config(&base_url)?;
    let token = bearer_token_with_access("projects", AccessLevel::Read, config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/proxy/projects/path?expand=1")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(get_response.status(), StatusCode::OK);

    let projects_request = rx.await?;
    assert_eq!(projects_request.path_and_query, "/path?expand=1");
    assert_eq!(projects_request.method, "GET");

    let denied_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/proxy/projects/path")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);

    let payload: serde_json::Value =
        serde_json::from_slice(&denied_response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "forbidden_api");

    Ok(())
}

#[tokio::test]
async fn proxy_route_streams_upstream_response_body_and_preserves_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = spawn_chunked_upstream(
        "206 Partial Content",
        &[
            ("content-type", "application/json"),
            ("x-upstream", "streamed"),
        ],
        &[br#"{"items":["# as &[u8], br#""alpha","#, br#""beta"]}"#],
    )
    .await?;
    let config = load_test_config(&upstream.base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/stream?expand=1")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(response.headers().get("x-upstream").unwrap(), "streamed");
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("response request id")
        .to_str()?
        .to_owned();
    let body = response.into_body().collect().await?.to_bytes();

    assert_eq!(
        body,
        bytes::Bytes::from_static(br#"{"items":["alpha","beta"]}"#)
    );

    let captured_request = upstream.captured_request.await?;
    let captured_request = captured_request.to_ascii_lowercase();

    assert!(captured_request.starts_with("get /api/stream?expand=1 http/1.1\r\n"));
    assert!(captured_request.contains("authorization: bearer billing-secret-token\r\n"));
    assert!(captured_request.contains(&format!("x-request-id: {request_id}\r\n")));

    Ok(())
}
