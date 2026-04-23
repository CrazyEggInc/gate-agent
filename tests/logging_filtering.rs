use std::{
    future::Future,
    io,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode},
    routing::any,
};
use gate_agent::{
    app::AppState,
    config::{ConfigSource, app_config::AppConfig, secrets::SecretsConfig},
    proxy::router::build_router,
    telemetry::build_env_filter,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;

const DEFAULT_TOKEN: &str = "default.s3cr3t";

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

struct CapturedLogs {
    raw: String,
    entries: Vec<Value>,
}

impl CapturedLogs {
    fn parse(raw: String) -> Self {
        let entries = raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("each log line should be valid json"))
            .collect();

        Self { raw, entries }
    }
}

fn nested_values_for_key<'a>(value: &'a Value, key: &str, matches: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(key) {
                matches.push(found);
            }

            for nested in map.values() {
                nested_values_for_key(nested, key, matches);
            }
        }
        Value::Array(values) => {
            for nested in values {
                nested_values_for_key(nested, key, matches);
            }
        }
        _ => {}
    }
}

fn contains_key(value: &Value, key: &str) -> bool {
    let mut matches = Vec::new();
    nested_values_for_key(value, key, &mut matches);
    !matches.is_empty()
}

fn find_event_with_keys<'a>(entries: &'a [Value], keys: &[&str]) -> &'a Value {
    entries
        .iter()
        .find(|entry| keys.iter().all(|key| contains_key(entry, key)))
        .unwrap_or_else(|| panic!("missing log entry with keys {keys:?}: {entries:#?}"))
}

fn find_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        let mut matches = Vec::new();
        nested_values_for_key(value, key, &mut matches);

        for found in matches {
            match found {
                Value::String(text) => return Some(text.clone()),
                Value::Number(number) => return Some(number.to_string()),
                Value::Bool(boolean) => return Some(boolean.to_string()),
                _ => {}
            }
        }
    }

    None
}

fn find_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let mut matches = Vec::new();
        nested_values_for_key(value, key, &mut matches);

        for found in matches {
            match found {
                Value::Number(number) => {
                    if let Some(parsed) = number.as_u64() {
                        return Some(parsed);
                    }
                }
                Value::String(text) => {
                    if let Ok(parsed) = text.parse() {
                        return Some(parsed);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

fn find_status_code(value: &Value, keys: &[&str]) -> Option<u16> {
    for key in keys {
        let mut matches = Vec::new();
        nested_values_for_key(value, key, &mut matches);

        for found in matches {
            match found {
                Value::Number(number) => {
                    if let Some(parsed) =
                        number.as_u64().and_then(|value| u16::try_from(value).ok())
                    {
                        return Some(parsed);
                    }
                }
                Value::String(text) => {
                    if let Some(token) = text.split_whitespace().next()
                        && let Ok(parsed) = token.parse()
                    {
                        return Some(parsed);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

fn assert_message_present(entries: &[Value], expected: &str) {
    let found = entries.iter().any(|entry| {
        find_string(entry, &["message"])
            .as_deref()
            .is_some_and(|message| message == expected)
    });

    assert!(found, "missing log message `{expected}`: {entries:#?}");
}

fn assert_message_absent(entries: &[Value], unexpected: &str) {
    let found = entries.iter().any(|entry| {
        find_string(entry, &["message"])
            .as_deref()
            .is_some_and(|message| message == unexpected)
    });

    assert!(
        !found,
        "unexpected log message `{unexpected}`: {entries:#?}"
    );
}

fn write_secrets_file(
    contents: &str,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    std::fs::write(&secrets_file, contents)?;
    Ok((temp_dir, secrets_file))
}

fn load_test_config(base_url: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_secrets_file(&format!(
        r#"
[clients.default]
bearer_token_id = "default"
bearer_token_hash = "2db0c3448853c76dd5d546e11bc41a309a283a7726b034705dcd65e433c9744d"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ billing = "write" }}

[clients.partner]
bearer_token_id = "partner"
bearer_token_hash = "5773afbb04744f0a04a8534d53d0ab41546e9f6ca1e5c6b32a58cf6fc2f6fb77"
bearer_token_expires_at = "2030-01-03T03:04:05Z"
api_access = {{ projects = "write" }}

[apis.projects]
base_url = "{base_url}"
headers = {{ x-api-key = "projects-secret-value" }}
timeout_ms = 5000

[apis.billing]
base_url = "{base_url}/api"
headers = {{ authorization = "Bearer billing-secret-token" }}
timeout_ms = 5000
"#,
    ))?;

    Ok(AppConfig::new(
        "127.0.0.1:0".parse()?,
        "debug",
        ConfigSource::Path(config_file.clone()),
        SecretsConfig::load_from_file(&config_file)?,
    ))
}

async fn spawn_upstream(app: Router) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("upstream server should run");
    });

    Ok(format!("http://{address}"))
}

async fn captured_dispatch<F, Fut>(
    log_level: &str,
    run: F,
) -> Result<CapturedLogs, Box<dyn std::error::Error>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_ansi(false)
        .without_time()
        .with_current_span(false)
        .with_span_list(false)
        .with_target(true)
        .with_writer(buffer.clone())
        .with_env_filter(build_env_filter(log_level)?)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    run().await?;

    Ok(CapturedLogs::parse(buffer.contents()))
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

    assert_message_present(&logs.entries, "crate scoped debug");
    assert_message_present(&logs.entries, "hyper warn visible");
    assert_message_absent(&logs.entries, "hyper debug hidden");

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
    let app = build_router(AppState::from_config(&config)?);

    let logs = captured_dispatch("debug", || async {
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/proxy/billing/v1/projects/1/tasks?expand=1&jwt=query-secret")
                    .header("x-request-id", "req-success")
                    .header("authorization", format!("Bearer {DEFAULT_TOKEN}"))
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

    let completion = find_event_with_keys(
        &logs.entries,
        &[
            "client",
            "request_id",
            "method",
            "uri",
            "status",
            "latency_ms",
            "api",
            "upstream_method",
            "upstream_url",
            "upstream_status",
            "timeout_ms",
        ],
    );

    assert_eq!(
        find_string(completion, &["client"]).as_deref(),
        Some("default")
    );
    assert_eq!(
        find_string(completion, &["request_id"]).as_deref(),
        Some("req-success")
    );
    assert_eq!(find_string(completion, &["method"]).as_deref(), Some("GET"));
    assert_eq!(
        find_string(completion, &["uri"]).as_deref(),
        Some("/proxy/billing/v1/projects/1/tasks")
    );
    assert_eq!(
        find_status_code(completion, &["status", "status_code"]),
        Some(201)
    );
    assert!(
        find_u64(completion, &["latency_ms"]).is_some(),
        "logs were: {}",
        logs.raw
    );
    assert_eq!(
        find_string(completion, &["api"]).as_deref(),
        Some("billing")
    );
    assert_eq!(
        find_string(completion, &["upstream_method"]).as_deref(),
        Some("GET")
    );
    let expected_upstream_url = format!("{base_url}/api/v1/projects/1/tasks");
    assert_eq!(
        find_string(completion, &["upstream_url"]).as_deref(),
        Some(expected_upstream_url.as_str())
    );
    assert_eq!(
        find_status_code(completion, &["upstream_status", "upstream_status_code"]),
        Some(201)
    );
    assert_eq!(find_u64(completion, &["timeout_ms"]), Some(5_000));
    assert!(
        !contains_key(completion, "error_code"),
        "logs were: {}",
        logs.raw
    );
    assert!(!logs.raw.contains("expand=1"), "logs were: {}", logs.raw);
    assert!(
        !logs.raw.contains("jwt=query-secret"),
        "logs were: {}",
        logs.raw
    );
    assert!(!logs.raw.contains(DEFAULT_TOKEN), "logs were: {}", logs.raw);
    assert!(
        !logs.raw.contains(&format!("Bearer {DEFAULT_TOKEN}")),
        "logs were: {}",
        logs.raw
    );
    assert!(
        !logs.raw.contains("billing-secret-token"),
        "logs were: {}",
        logs.raw
    );
    assert!(
        !logs.raw.contains("proxy upstream call finished"),
        "logs were: {}",
        logs.raw
    );
    assert!(!contains_key(completion, "span"), "logs were: {}", logs.raw);
    assert!(
        !contains_key(completion, "spans"),
        "logs were: {}",
        logs.raw
    );

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn completion_logs_add_error_code_only_for_application_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let logs = captured_dispatch("debug", || async {
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/proxy/projects/v1/projects/1/tasks")
                    .header("x-request-id", "req-forbidden")
                    .header("authorization", format!("Bearer {DEFAULT_TOKEN}"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        Ok(())
    })
    .await?;

    let completion = find_event_with_keys(
        &logs.entries,
        &[
            "client",
            "request_id",
            "method",
            "uri",
            "status",
            "latency_ms",
            "error_code",
        ],
    );

    assert_eq!(
        find_string(completion, &["client"]).as_deref(),
        Some("default")
    );
    assert_eq!(
        find_string(completion, &["request_id"]).as_deref(),
        Some("req-forbidden")
    );
    assert_eq!(find_string(completion, &["method"]).as_deref(), Some("GET"));
    assert_eq!(
        find_string(completion, &["uri"]).as_deref(),
        Some("/proxy/projects/v1/projects/1/tasks")
    );
    assert_eq!(
        find_status_code(completion, &["status", "status_code"]),
        Some(403)
    );
    assert!(
        find_u64(completion, &["latency_ms"]).is_some(),
        "logs were: {}",
        logs.raw
    );
    assert_eq!(
        find_string(completion, &["error_code"]).as_deref(),
        Some("forbidden_api")
    );
    assert!(!logs.raw.contains(DEFAULT_TOKEN), "logs were: {}", logs.raw);
    assert!(
        !logs.raw.contains(&format!("Bearer {DEFAULT_TOKEN}")),
        "logs were: {}",
        logs.raw
    );
    assert!(
        !contains_key(completion, "upstream_method"),
        "logs were: {}",
        logs.raw
    );
    assert!(
        !contains_key(completion, "upstream_status"),
        "logs were: {}",
        logs.raw
    );

    Ok(())
}
