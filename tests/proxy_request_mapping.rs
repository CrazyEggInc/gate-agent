use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode, header::HeaderValue},
    routing::{any, get},
};
use gate_agent::{
    config::secrets::SecretsConfig,
    proxy::{request::map_request, response::map_response},
};
use http_body_util::BodyExt;
use tokio::{
    net::TcpListener,
    sync::{Mutex, oneshot},
};

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path_and_query: String,
    headers: http::HeaderMap,
    body: bytes::Bytes,
}

fn write_secrets_file(
    contents: &str,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    std::fs::write(&secrets_file, contents)?;
    Ok((temp_dir, secrets_file))
}

fn load_test_secrets(base_url: &str) -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let (_temp_dir, secrets_file) = write_secrets_file(&format!(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "replace-me"

[clients.default]
api_key = "default-client-api-key"
api_key_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ projects = "read", billing = "write" }}

[apis.projects]
base_url = "{base_url}"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000

[apis.billing]
base_url = "{base_url}/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#
    ))?;

    Ok(SecretsConfig::load_from_file(&secrets_file)?)
}

async fn spawn_server(app: Router) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test server should run");
    });

    Ok(format!("http://{address}"))
}

#[tokio::test]
async fn request_mapping_builds_upstream_request_filters_headers_and_keeps_streaming()
-> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = oneshot::channel();
    let sender = Arc::new(Mutex::new(Some(tx)));
    let app = Router::new()
        .route(
            "/api/{*path}",
            any(
                |State(sender): State<Arc<Mutex<Option<oneshot::Sender<CapturedRequest>>>>>,
                 request: Request<Body>| async move {
                    let (parts, body) = request.into_parts();
                    let body = body
                        .collect()
                        .await
                        .expect("collect request body")
                        .to_bytes();

                    if let Some(tx) = sender.lock().await.take() {
                        tx.send(CapturedRequest {
                            method: parts.method.to_string(),
                            path_and_query: parts
                                .uri
                                .path_and_query()
                                .map(|value| value.as_str().to_owned())
                                .unwrap_or_else(|| parts.uri.path().to_owned()),
                            headers: parts.headers,
                            body,
                        })
                        .expect("send captured request");
                    }

                    StatusCode::ACCEPTED
                },
            ),
        )
        .with_state(sender);
    let base_url = spawn_server(app).await?;
    let secrets = load_test_secrets(&base_url)?;
    let api = secrets.apis.get("billing").expect("billing api config");

    let request = Request::builder()
        .method("POST")
        .uri("/proxy/billing/v1/projects/1/tasks?expand=1")
        .header("authorization", "Bearer client-jwt")
        .header("connection", "keep-alive, x-remove-me")
        .header("host", "localhost:8787")
        .header("te", "trailers")
        .header("x-custom", "preserved")
        .header("x-remove-me", "remove this too")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"New task"}"#))?;

    let outbound = map_request(request, "billing", api)?;

    assert_eq!(outbound.method().as_str(), "POST");
    assert_eq!(
        outbound.url().as_str(),
        format!("{base_url}/api/v1/projects/1/tasks?expand=1")
    );
    assert_eq!(
        outbound
            .headers()
            .get("authorization")
            .expect("upstream auth header"),
        "Bearer billing-secret-token"
    );
    assert_eq!(
        outbound.headers().get("x-custom").expect("custom header"),
        "preserved"
    );
    assert!(outbound.headers().get("connection").is_none());
    assert!(outbound.headers().get("te").is_none());
    assert!(outbound.headers().get("x-remove-me").is_none());
    assert!(outbound.headers().get("host").is_none());
    assert_eq!(
        outbound.body().and_then(reqwest::Body::as_bytes),
        None,
        "request body should remain stream-backed"
    );

    let client = reqwest::Client::new();
    let response = client.execute(outbound).await?;

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let captured = rx.await?;
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path_and_query, "/api/v1/projects/1/tasks?expand=1");
    assert_eq!(
        captured
            .headers
            .get("authorization")
            .expect("forwarded upstream auth header"),
        "Bearer billing-secret-token"
    );
    assert_eq!(
        captured.headers.get("x-custom").expect("custom header"),
        "preserved"
    );
    assert_eq!(
        captured
            .headers
            .get("content-type")
            .expect("content-type header"),
        "application/json"
    );
    assert!(captured.headers.get("connection").is_none());
    assert!(captured.headers.get("te").is_none());
    assert!(captured.headers.get("x-remove-me").is_none());
    assert_eq!(
        captured.body,
        bytes::Bytes::from_static(br#"{"name":"New task"}"#)
    );

    Ok(())
}

#[tokio::test]
async fn request_mapping_preserves_encoded_path_and_query_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_server(app).await?;
    let secrets = load_test_secrets(&base_url)?;
    let api = secrets.apis.get("billing").expect("billing api config");

    let request = Request::builder()
        .method("GET")
        .uri("/proxy/billing/files/a%2Fb?expand=%2F")
        .body(Body::empty())?;

    let outbound = map_request(request, "billing", api)?;

    assert_eq!(
        outbound.url().as_str(),
        format!("{base_url}/api/files/a%2Fb?expand=%2F")
    );

    Ok(())
}

#[tokio::test]
async fn request_mapping_strips_client_forwarding_headers() -> Result<(), Box<dyn std::error::Error>>
{
    let app = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_server(app).await?;
    let secrets = load_test_secrets(&base_url)?;
    let api = secrets.apis.get("billing").expect("billing api config");

    let request = Request::builder()
        .method("GET")
        .uri("/proxy/billing/v1/projects")
        .header("forwarded", "for=203.0.113.9;proto=https;host=evil.example")
        .header("x-forwarded-for", "203.0.113.10")
        .header("x-forwarded-host", "evil.example")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-port", "443")
        .header("x-forwarded-prefix", "/spoofed")
        .header("x-real-ip", "203.0.113.11")
        .header("via", "1.1 attacker-proxy")
        .header("x-custom", "preserved")
        .body(Body::empty())?;

    let outbound = map_request(request, "billing", api)?;

    assert!(outbound.headers().get("forwarded").is_none());
    assert!(outbound.headers().get("x-forwarded-for").is_none());
    assert!(outbound.headers().get("x-forwarded-host").is_none());
    assert!(outbound.headers().get("x-forwarded-proto").is_none());
    assert!(outbound.headers().get("x-forwarded-port").is_none());
    assert!(outbound.headers().get("x-forwarded-prefix").is_none());
    assert!(outbound.headers().get("x-real-ip").is_none());
    assert!(outbound.headers().get("via").is_none());
    assert_eq!(outbound.headers().get("x-custom").unwrap(), "preserved");
    assert_eq!(
        outbound.headers().get("authorization").unwrap(),
        "Bearer billing-secret-token"
    );

    Ok(())
}

#[tokio::test]
async fn request_mapping_sets_raw_upstream_auth_header_when_scheme_is_not_configured()
-> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_server(app).await?;
    let secrets = load_test_secrets(&base_url)?;
    let api = secrets.apis.get("projects").expect("projects api config");

    let request = Request::builder()
        .method("GET")
        .uri("/proxy/projects")
        .header("authorization", "Bearer client-jwt")
        .body(Body::empty())?;

    let outbound = map_request(request, "projects", api)?;

    assert_eq!(
        outbound
            .headers()
            .get("x-api-key")
            .expect("x-api-key header"),
        "projects-secret-value"
    );
    assert!(outbound.headers().get("authorization").is_none());

    Ok(())
}

#[tokio::test]
async fn request_mapping_preserves_trailing_proxy_slash() -> Result<(), Box<dyn std::error::Error>>
{
    let app = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_server(app).await?;
    let secrets = load_test_secrets(&base_url)?;
    let api = secrets.apis.get("billing").expect("billing api config");

    let request = Request::builder()
        .method("GET")
        .uri("/proxy/billing/")
        .body(Body::empty())?;

    let outbound = map_request(request, "billing", api)?;

    assert_eq!(outbound.url().as_str(), format!("{base_url}/api/"));

    Ok(())
}

#[tokio::test]
async fn request_mapping_preserves_double_slash_segments() -> Result<(), Box<dyn std::error::Error>>
{
    let app = Router::new().route("/{*path}", any(|| async { StatusCode::NO_CONTENT }));
    let base_url = spawn_server(app).await?;
    let secrets = load_test_secrets(&base_url)?;
    let api = secrets.apis.get("billing").expect("billing api config");

    let request = Request::builder()
        .method("GET")
        .uri("/proxy/billing//double")
        .body(Body::empty())?;

    let outbound = map_request(request, "billing", api)?;

    assert_eq!(outbound.url().as_str(), format!("{base_url}/api//double"));

    Ok(())
}

#[test]
fn request_mapping_rejects_missing_proxy_suffix() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Runtime::new()?;
    let base_url = runtime.block_on(async {
        let app = Router::new().route("/{*path}", any(|| async { StatusCode::OK }));
        spawn_server(app).await
    })?;
    let secrets = load_test_secrets(&base_url)?;
    let api = secrets.apis.get("projects").expect("projects api config");

    let request = Request::builder()
        .method("GET")
        .uri("/proxy")
        .body(Body::empty())?;

    let error = map_request(request, "projects", api).unwrap_err();

    assert!(matches!(
        error,
        gate_agent::error::AppError::BadProxyPath(_)
    ));

    Ok(())
}

#[tokio::test]
async fn response_mapping_filters_hop_by_hop_headers_and_keeps_body_readable()
-> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().route(
        "/upstream",
        get(|| async move {
            let mut response = Response::new(Body::from("upstream-body"));
            *response.status_mut() = StatusCode::CREATED;
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("text/plain"));
            response
                .headers_mut()
                .insert("x-upstream", HeaderValue::from_static("present"));
            response.headers_mut().insert(
                "connection",
                HeaderValue::from_static("keep-alive, x-remove-me"),
            );
            response
                .headers_mut()
                .insert("keep-alive", HeaderValue::from_static("timeout=5"));
            response
                .headers_mut()
                .insert("x-remove-me", HeaderValue::from_static("remove me"));
            response
        }),
    );
    let base_url = spawn_server(app).await?;
    let upstream = reqwest::Client::new()
        .get(format!("{base_url}/upstream"))
        .send()
        .await?;

    let response = map_response(upstream)?;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("content-type header"),
        "text/plain"
    );
    assert_eq!(
        response
            .headers()
            .get("x-upstream")
            .expect("x-upstream header"),
        "present"
    );
    assert!(response.headers().get("connection").is_none());
    assert!(response.headers().get("keep-alive").is_none());
    assert!(response.headers().get("x-remove-me").is_none());

    let body = response.into_body().collect().await?.to_bytes();

    assert_eq!(body, bytes::Bytes::from_static(b"upstream-body"));

    Ok(())
}
