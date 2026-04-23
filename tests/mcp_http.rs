mod support;

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode, header::HeaderValue},
    routing::any,
};
use gate_agent::{app::AppState, proxy::router::build_router};
use http_body_util::BodyExt;
use support::{
    bearer_token, bearer_token_for_client, capture_channel, capture_request,
    load_multi_api_test_config, load_test_config, spawn_upstream,
};
use tower::ServiceExt;

async fn json_body(
    response: Response<Body>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &response.into_body().collect().await?.to_bytes(),
    )?)
}

fn tool_content_json(payload: &serde_json::Value) -> serde_json::Value {
    serde_json::from_str(
        payload["result"]["content"][0]["text"]
            .as_str()
            .expect("tool content text should exist"),
    )
    .expect("tool content should be valid JSON")
}

#[tokio::test]
async fn mcp_route_rejects_malformed_bearer_token_before_json_rpc_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("x-request-id", "req-mcp-invalid")
                .header("authorization", "Bearer not-a-valid-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "req-mcp-invalid"
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(
        payload,
        serde_json::json!({
            "error": {
                "code": "invalid_token",
                "message": "authentication failed",
                "request_id": "req-mcp-invalid"
            }
        })
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_rejects_duplicate_authorization_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("x-request-id", "req-mcp-duplicate-auth")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        ))?;
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
        "req-mcp-duplicate-auth"
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["error"]["code"], "invalid_token");

    Ok(())
}

#[tokio::test]
async fn mcp_route_accepts_valid_bearer_token_for_initialize()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("x-request-id", "req-mcp-init")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("www-authenticate").is_none());
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "req-mcp-init"
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], 1);
    assert_eq!(payload["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(payload["result"]["serverInfo"]["name"], "gate-agent");
    assert_eq!(
        payload["result"]["capabilities"],
        serde_json::json!({"tools": {}})
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_rejects_oversized_request_body_before_json_rpc_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);
    let oversized_padding = "a".repeat((1024 * 1024) + 1);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"padding":"{oversized_padding}"}}}}"#
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("x-request-id", "req-mcp-too-large")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "req-mcp-too-large"
    );

    let payload = json_body(response).await?;

    assert_eq!(payload["error"]["code"], "bad_request");
    assert_eq!(payload["error"]["message"], "request is invalid");
    assert_eq!(payload["error"]["request_id"], "req-mcp-too-large");

    Ok(())
}

#[tokio::test]
async fn mcp_route_returns_json_rpc_parse_error_after_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize""#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], serde_json::Value::Null);
    assert_eq!(payload["error"]["code"], -32700);
    assert_eq!(payload["error"]["message"], "parse error");
    assert!(payload.get("result").is_none());
    assert!(payload.get("error").is_some());

    Ok(())
}

#[tokio::test]
async fn mcp_route_returns_json_rpc_invalid_params_for_bad_tools_call_params()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":123}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], 8);
    assert_eq!(payload["error"]["code"], -32602);
    assert_eq!(payload["error"]["message"], "invalid params");

    Ok(())
}

#[tokio::test]
async fn mcp_route_returns_json_rpc_invalid_request_after_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"1.0","id":10,"method":"initialize","params":{}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], 10);
    assert_eq!(payload["error"]["code"], -32600);
    assert_eq!(payload["error"]["message"], "invalid request");

    Ok(())
}

#[tokio::test]
async fn mcp_route_rejects_boolean_json_rpc_id_as_invalid_request()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":true,"method":"initialize","params":{}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], serde_json::Value::Null);
    assert_eq!(payload["error"]["code"], -32600);
    assert_eq!(payload["error"]["message"], "invalid request");

    Ok(())
}

#[tokio::test]
async fn mcp_route_emits_null_id_for_parse_errors() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize""#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], serde_json::Value::Null);
    assert_eq!(payload["error"]["code"], -32700);

    Ok(())
}

#[tokio::test]
async fn mcp_route_lists_only_supported_mcp_tools() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], 1);
    assert_eq!(payload["result"]["tools"].as_array().unwrap().len(), 2);
    assert_eq!(payload["result"]["tools"][0]["name"], "call_api");
    assert_eq!(payload["result"]["tools"][1]["name"], "list_apis");
    assert!(payload["result"]["tools"][0]["inputSchema"].is_object());
    assert_eq!(
        payload["result"]["tools"][0]["inputSchema"]["properties"]["path"]["pattern"],
        "^/"
    );
    assert_eq!(
        payload["result"]["tools"][0]["inputSchema"]["properties"]["response_headers"],
        serde_json::json!({
            "type": "string",
            "enum": ["essential", "all"]
        })
    );
    assert_eq!(
        payload["result"]["tools"][1]["inputSchema"],
        serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_list_apis_returns_sorted_effective_api_access_with_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_multi_api_test_config(&base_url)?;
    let token = bearer_token_for_client("default", "billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_apis","arguments":{}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], 2);
    assert_eq!(payload["result"]["isError"], false);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    assert_eq!(
        tool_content_json(&payload),
        serde_json::json!({
            "apis": [
                {
                    "slug": "billing",
                    "access_level": "write",
                    "description": "Billing API",
                    "docs_url": "https://docs.internal.example/billing",
                    "usage_hint": "Call this API with the call_api tool.",
                    "example_arguments": {
                        "api": "billing",
                        "method": "GET",
                        "path": "/<endpoint>"
                    }
                },
                {
                    "slug": "projects",
                    "access_level": "write",
                    "description": "Projects API",
                    "docs_url": "https://docs.internal.example/projects",
                    "usage_hint": "Call this API with the call_api tool.",
                    "example_arguments": {
                        "api": "projects",
                        "method": "GET",
                        "path": "/<endpoint>"
                    }
                }
            ]
        })
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_call_api_uses_shared_forwarding_logic_for_json_requests()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, rx) = capture_channel();
    let upstream = Router::new()
        .route(
            "/api/{*path}",
            any(
                |axum::extract::State(sender): axum::extract::State<support::CaptureSender>,
                 request: Request<Body>| async move {
                    capture_request(axum::extract::State(sender), request).await;

                    let mut response = Response::new(Body::from(r#"{"ok":true,"source":"mcp"}"#));
                    *response.status_mut() = StatusCode::CREATED;
                    response
                        .headers_mut()
                        .insert("content-type", HeaderValue::from_static("application/json"));
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
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"call_api","arguments":{"api":"billing","method":"POST","path":"/v1/projects/1/tasks","query":{"expand":"1"},"headers":{"authorization":"Bearer client-token","forwarded":"for=203.0.113.9;proto=https","x-custom":"preserved"},"body":{"name":"New task"}}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["result"]["isError"], false);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    let content = tool_content_json(&payload);
    assert_eq!(content["status"], 201);
    assert_eq!(content["content_type"], "application/json");
    assert_eq!(
        content["headers"]["content-type"],
        serde_json::json!(["application/json"])
    );
    assert!(content["headers"]["date"].is_string() || content["headers"]["date"].is_array());
    assert!(content["headers"].get("x-upstream").is_none());
    assert_eq!(
        content["body_json"],
        serde_json::json!({"ok": true, "source": "mcp"})
    );

    let captured = rx.await?;
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path_and_query, "/api/v1/projects/1/tasks?expand=1");
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        "Bearer billing-secret-token"
    );
    assert_eq!(captured.headers.get("x-custom").unwrap(), "preserved");
    assert!(captured.headers.get("forwarded").is_none());
    assert_eq!(
        captured.headers.get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(
        captured.body,
        bytes::Bytes::from_static(br#"{"name":"New task"}"#)
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_call_api_can_return_all_response_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/api/{*path}",
        axum::routing::any(|| async {
            let mut response = Response::new(Body::from(r#"{"ok":true}"#));
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
            response
                .headers_mut()
                .insert("x-upstream", HeaderValue::from_static("present"));
            response
        }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"call_api","arguments":{"api":"billing","method":"GET","path":"/headers","response_headers":"all"}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["result"]["isError"], false);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    let content = tool_content_json(&payload);
    assert_eq!(
        content["headers"]["content-type"],
        serde_json::json!(["application/json"])
    );
    assert_eq!(
        content["headers"]["x-upstream"],
        serde_json::json!(["present"])
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_call_api_returns_text_responses() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/api/{*path}",
        axum::routing::any(|| async {
            let mut response = Response::new(Body::from("hello from upstream"));
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response
        }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"call_api","arguments":{"api":"billing","method":"GET","path":"/message"}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["result"]["isError"], false);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    let content = tool_content_json(&payload);
    assert_eq!(content["status"], 200);
    assert_eq!(content["body_text"], "hello from upstream");

    Ok(())
}

#[tokio::test]
async fn mcp_route_call_api_rejects_unsupported_request_content_type()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"call_api","arguments":{"api":"billing","method":"POST","path":"/upload","content_type":"multipart/form-data","body":"ignored"}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["result"]["isError"], true);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    let content = tool_content_json(&payload);
    assert_eq!(content["code"], "bad_request");
    assert_eq!(content["message"], "unsupported MCP request content type");

    Ok(())
}

#[tokio::test]
async fn mcp_route_call_api_rejects_unsupported_request_content_type_without_body()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, mut rx) = capture_channel();
    let upstream = Router::new()
        .route(
            "/api/{*path}",
            any(
                |axum::extract::State(sender): axum::extract::State<support::CaptureSender>,
                 request: Request<Body>| async move {
                    capture_request(axum::extract::State(sender), request).await
                },
            ),
        )
        .with_state(sender);
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"call_api","arguments":{"api":"billing","method":"POST","path":"/upload","content_type":"multipart/form-data"}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["result"]["isError"], true);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    let content = tool_content_json(&payload);
    assert_eq!(content["code"], "bad_request");
    assert_eq!(content["message"], "unsupported MCP request content type");

    assert!(rx.try_recv().is_err());

    Ok(())
}

#[tokio::test]
async fn mcp_route_call_api_rejects_path_with_embedded_query_or_fragment()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"call_api","arguments":{"api":"billing","method":"GET","path":"/message?expand=1#frag"}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["result"]["isError"], true);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    let content = tool_content_json(&payload);
    assert_eq!(content["code"], "bad_request");
    assert_eq!(
        content["message"],
        "path must not include query or fragment components"
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_call_api_rejects_unsupported_binary_upstream_response()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/api/{*path}",
        axum::routing::any(|| async {
            let mut response = Response::new(Body::from(vec![0_u8, 159, 146, 150]));
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/octet-stream"),
            );
            response
        }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"call_api","arguments":{"api":"billing","method":"GET","path":"/binary"}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["result"]["isError"], true);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    let content = tool_content_json(&payload);
    assert_eq!(content["code"], "response_mapping");
    assert_eq!(
        content["message"],
        "unsupported MCP upstream response content type"
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_call_api_rejects_oversized_upstream_response_body()
-> Result<(), Box<dyn std::error::Error>> {
    let oversized_body = "a".repeat((1024 * 1024) + 1);
    let upstream = axum::Router::new().route(
        "/api/{*path}",
        axum::routing::any(move || {
            let oversized_body = oversized_body.clone();
            async move {
                let mut response = Response::new(Body::from(oversized_body));
                response.headers_mut().insert(
                    "content-type",
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                response
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
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"call_api","arguments":{"api":"billing","method":"GET","path":"/too-large"}}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["result"]["isError"], true);
    assert_eq!(
        payload["result"]["structuredContent"],
        serde_json::json!({})
    );
    let content = tool_content_json(&payload);
    assert_eq!(content["code"], "response_mapping");
    assert_eq!(
        content["message"],
        "MCP upstream response body exceeds 1048576 bytes"
    );

    Ok(())
}

#[tokio::test]
async fn mcp_route_returns_method_not_found_for_unknown_method()
-> Result<(), Box<dyn std::error::Error>> {
    let upstream = axum::Router::new().route(
        "/{*path}",
        axum::routing::any(|| async { StatusCode::NO_CONTENT }),
    );
    let base_url = spawn_upstream(upstream).await?;
    let config = load_test_config(&base_url)?;
    let token = bearer_token("billing", config.secrets())?;
    let app = build_router(AppState::from_config(&config)?);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":7,"method":"resources/list","params":{}}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let payload = json_body(response).await?;

    assert_eq!(payload["jsonrpc"], "2.0");
    assert_eq!(payload["id"], 7);
    assert_eq!(payload["error"]["code"], -32601);
    assert_eq!(payload["error"]["message"], "method not found");

    Ok(())
}
