use std::{
    future::Future,
    io,
    io::Write,
    sync::{Arc, Mutex},
};

mod support;

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode},
    routing::any,
};
use gate_agent::{app::AppState, proxy::router::build_router, telemetry::build_env_filter};
use http_body_util::BodyExt;
use support::{load_test_config, signed_token, signed_token_for_client, spawn_upstream};
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct SharedBuffer {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl SharedBuffer {
    fn contents(&self) -> String {
        String::from_utf8(self.bytes.lock().expect("shared log buffer lock").clone())
            .expect("log output should be valid utf-8")
    }
}

struct SharedBufferWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for SharedBufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes
            .lock()
            .expect("shared log buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedBufferWriter {
            bytes: self.bytes.clone(),
        }
    }
}

async fn captured_dispatch<F, Fut>(
    log_level: &str,
    run: F,
) -> Result<String, Box<dyn std::error::Error>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_writer(buffer.clone())
        .with_env_filter(build_env_filter(log_level)?)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    run().await?;

    Ok(buffer.contents())
}

#[tokio::test(flavor = "current_thread")]
async fn debug_logging_stays_crate_scoped() -> Result<(), Box<dyn std::error::Error>> {
    let logs = captured_dispatch("debug", || async {
        tracing::debug!(target: "gate_agent::proxy::router", "crate scoped debug");
        tracing::debug!(target: "hyper::proto::h1", "hyper debug hidden");
        tracing::warn!(target: "hyper::proto::h1", "hyper warn visible");

        Ok(())
    })
    .await?;

    assert!(logs.contains("crate scoped debug"));
    assert!(logs.contains("hyper warn visible"));
    assert!(!logs.contains("hyper debug hidden"));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn successful_proxy_requests_include_safe_upstream_fields_in_completion_log()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route(
        "/api/{*path}",
        any(|| async {
            let mut response = Response::new(Body::from("upstream ok"));
            *response.status_mut() = StatusCode::CREATED;
            response
        }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = signed_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let logs = captured_dispatch("debug", || async {
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/proxy/billing/v1/projects/1/tasks?expand=1&jwt=query-secret")
                    .header("x-request-id", "req-success")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get("x-request-id").unwrap(),
            "req-success"
        );
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "upstream ok"
        );

        Ok(())
    })
    .await?;

    assert!(logs.contains("status=201 Created"), "logs were: {logs}");
    assert!(logs.contains("client_id=default"), "logs were: {logs}");
    assert!(logs.contains("latency_ms="), "logs were: {logs}");
    assert!(logs.contains("api=billing"), "logs were: {logs}");
    assert!(logs.contains("upstream_method=GET"), "logs were: {logs}");
    assert!(logs.contains("upstream_url="), "logs were: {logs}");
    assert!(
        logs.contains("upstream_status=201 Created"),
        "logs were: {logs}"
    );
    assert!(logs.contains("timeout_ms=5000"), "logs were: {logs}");
    assert!(!logs.contains("error_code="), "logs were: {logs}");
    assert!(
        logs.contains("uri=/proxy/billing/v1/projects/1/tasks"),
        "logs were: {logs}"
    );
    assert!(
        logs.contains("/api/v1/projects/1/tasks"),
        "logs were: {logs}"
    );
    assert!(!logs.contains("expand=1"), "logs were: {logs}");
    assert!(!logs.contains("jwt=query-secret"), "logs were: {logs}");
    assert!(!logs.contains(&token), "logs were: {logs}");
    assert!(
        !logs.contains("proxy upstream call finished"),
        "logs were: {logs}"
    );

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn auth_exchange_logs_do_not_leak_api_key_or_query_values()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let logs = captured_dispatch("debug", || async {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/exchange?token=query-secret")
                    .header("x-request-id", "req-auth-log")
                    .header("content-type", "application/json")
                    .header("x-api-key", "default-client-key")
                    .body(Body::from(r#"{"apis":["billing"]}"#))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        Ok(())
    })
    .await?;

    assert!(logs.contains("uri=/auth/exchange"), "logs were: {logs}");
    assert!(!logs.contains("token=query-secret"), "logs were: {logs}");
    assert!(!logs.contains("default-client-key"), "logs were: {logs}");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn completion_logs_add_error_code_only_for_application_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = signed_token_for_client("default", "billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let logs = captured_dispatch("debug", || async {
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/proxy/projects/v1/projects/1/tasks")
                    .header("x-request-id", "req-forbidden")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        Ok(())
    })
    .await?;

    assert!(logs.contains("status=403 Forbidden"), "logs were: {logs}");
    assert!(logs.contains("client_id=default"), "logs were: {logs}");
    assert!(
        logs.contains("error_code=\"forbidden_api\""),
        "logs were: {logs}"
    );
    assert!(!logs.contains("upstream_method="), "logs were: {logs}");
    assert!(!logs.contains("upstream_status="), "logs were: {logs}");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_token_completion_logs_keep_default_client_id()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let logs = captured_dispatch("debug", || async {
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/proxy/billing/v1/projects/1/tasks")
                    .header("x-request-id", "req-invalid-token")
                    .header("authorization", "Bearer not-a-real-token")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    })
    .await?;

    assert!(
        logs.contains("status=401 Unauthorized"),
        "logs were: {logs}"
    );
    assert!(logs.contains("client_id=<unknown>"), "logs were: {logs}");
    assert!(
        logs.contains("error_code=\"invalid_token\""),
        "logs were: {logs}"
    );

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn successful_auth_exchange_completion_logs_include_client_id()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let logs = captured_dispatch("debug", || async {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/exchange")
                    .header("x-request-id", "req-exchange")
                    .header("x-api-key", "default-client-key")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"apis":["billing"]}"#))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        Ok(())
    })
    .await?;

    assert!(logs.contains("status=200 OK"), "logs were: {logs}");
    assert!(logs.contains("client_id=default"), "logs were: {logs}");
    assert!(!logs.contains("error_code="), "logs were: {logs}");

    Ok(())
}
