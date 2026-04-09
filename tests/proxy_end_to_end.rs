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
use gate_agent::{app::AppState, proxy::router::build_router};
use http_body_util::BodyExt;
use secrecy::ExposeSecret;
use support::{
    capture_channel, capture_request, load_multi_api_test_config, load_test_config,
    load_test_config_with_billing_timeout, signed_token, signed_token_for_client,
    signed_token_with_subject_and_secret, spawn_chunked_upstream, spawn_upstream,
};
use tower::ServiceExt;

async fn assert_upstream_redirect_is_not_followed(
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
    let token = signed_token("billing", &config.secrets)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/redirect")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), redirect_status);
    assert_eq!(
        response.headers().get("location").unwrap(),
        "/api/redirect-target"
    );
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(body, bytes::Bytes::from_static(b"redirect response"));
    assert_eq!(redirect_target_hits.load(Ordering::SeqCst), 0);

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
    let token = signed_token_for_client("default", "billing", &config.secrets)?;
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
    let app = build_router(AppState::from_config(&config)?);

    let exchange_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["projects","billing"]}"#))?,
        )
        .await?;

    assert_eq!(exchange_response.status(), StatusCode::OK);

    let exchange: gate_agent::auth::exchange::ExchangeResponse =
        serde_json::from_slice(&exchange_response.into_body().collect().await?.to_bytes())?;

    let billing_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/path")
                .header("authorization", format!("Bearer {}", exchange.access_token))
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
async fn proxy_route_uses_api_segment_for_projects_multi_api_token()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route("/{*path}", any(capture_request))
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_multi_api_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let exchange_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["projects","billing"]}"#))?,
        )
        .await?;

    assert_eq!(exchange_response.status(), StatusCode::OK);

    let exchange: gate_agent::auth::exchange::ExchangeResponse =
        serde_json::from_slice(&exchange_response.into_body().collect().await?.to_bytes())?;

    let projects_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proxy/projects/path?expand=1")
                .header("authorization", format!("Bearer {}", exchange.access_token))
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
    assert!(projects_request.headers.get("authorization").is_none());

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_multi_api_token_for_route_api_not_present_in_token()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_multi_api_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let exchange_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["projects","billing"]}"#))?,
        )
        .await?;

    assert_eq!(exchange_response.status(), StatusCode::OK);

    let exchange: gate_agent::auth::exchange::ExchangeResponse =
        serde_json::from_slice(&exchange_response.into_body().collect().await?.to_bytes())?;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/reports")
                .header("authorization", format!("Bearer {}", exchange.access_token))
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
    let token = signed_token_for_client("default", "billing", &config.secrets)?;
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
async fn proxy_route_rejects_disallowed_api_for_valid_client_token()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = signed_token_with_subject_and_secret(
        "default",
        "projects",
        config.secrets.auth.signing_secret.expose_secret(),
        &config.secrets,
    )?;
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

    assert_eq!(
        payload["error"]["code"],
        serde_json::Value::String("forbidden_api".to_owned())
    );

    Ok(())
}

#[tokio::test]
async fn proxy_route_rejects_token_signed_with_wrong_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = signed_token_with_subject_and_secret(
        "default",
        "billing",
        "wrong-secret",
        &config.secrets,
    )?;
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
async fn proxy_route_returns_consistent_invalid_token_error_with_request_id()
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
    let token = signed_token("billing", &config.secrets)?;
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
async fn proxy_route_maps_upstream_timeout_to_gateway_timeout_for_exchanged_token()
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
    let app = build_router(AppState::from_config(&config)?);

    let exchange_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/exchange")
                .header("content-type", "application/json")
                .header("x-api-key", "default-client-key")
                .body(Body::from(r#"{"apis":["billing"]}"#))?,
        )
        .await?;

    assert_eq!(exchange_response.status(), StatusCode::OK);

    let exchange: gate_agent::auth::exchange::ExchangeResponse =
        serde_json::from_slice(&exchange_response.into_body().collect().await?.to_bytes())?;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/proxy/billing/slow")
                .header("x-request-id", "req-timeout-exchange")
                .header("authorization", format!("Bearer {}", exchange.access_token))
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
                "request_id": "req-timeout-exchange"
            }
        })
    );

    Ok(())
}

#[tokio::test]
async fn proxy_route_returns_upstream_redirects_without_following_them()
-> Result<(), Box<dyn std::error::Error>> {
    assert_upstream_redirect_is_not_followed(StatusCode::FOUND).await?;
    assert_upstream_redirect_is_not_followed(StatusCode::TEMPORARY_REDIRECT).await?;

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
    let token = signed_token("billing", &config.secrets)?;
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
    let token = signed_token("billing", &config.secrets)?;
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
    let token = signed_token("billing", &config.secrets)?;
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
    let token = signed_token("billing", &config.secrets)?;
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
    let token = signed_token("billing", &config.secrets)?;
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
