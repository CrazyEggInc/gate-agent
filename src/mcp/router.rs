use axum::{
    body::{Body, to_bytes},
    extract::State,
    http::Request,
    response::Response,
};
use serde_json::Value;

use crate::{
    app::AppState,
    auth::bearer::{
        AuthorizedRequest, extract_authorization_header, validate_bearer_authorized_request,
    },
    error::AppError,
    telemetry::{
        GATE_AGENT_REQUEST_ID_HEADER, LoggedClient, LoggedRequestContext,
        generate_internal_request_id, sanitize_request_uri_for_logs,
    },
};

use super::{
    protocol::{
        JsonRpcId, JsonRpcRequest, JsonRpcResponse, ToolResult, ToolsListResult, initialize_result,
    },
    tools::{ToolsCallParams, call_tool, supported_tools},
};

const MCP_MAX_BODY_BYTES: usize = 1024 * 1024;

pub async fn mcp_handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    let request_id = generate_internal_request_id();
    let request_context = LoggedRequestContext {
        request_id: request_id.clone(),
        method: request.method().to_string(),
        uri: sanitize_request_uri_for_logs(request.uri()),
    };

    let mut response = match handle_mcp_request(state, request, &request_id).await {
        Ok((client_slug, response)) => {
            let mut response = response;
            response.extensions_mut().insert(LoggedClient(client_slug));
            response
        }
        Err((client_slug, response)) => {
            let mut response = response;
            if let Some(client_slug) = client_slug {
                response.extensions_mut().insert(LoggedClient(client_slug));
            }
            response
        }
    };

    response.headers_mut().insert(
        GATE_AGENT_REQUEST_ID_HEADER,
        http::HeaderValue::from_str(&request_id)
            .expect("request id should always be a valid header value"),
    );

    response.extensions_mut().insert(request_context);

    response
}

async fn handle_mcp_request(
    state: AppState,
    request: Request<Body>,
    request_id: &str,
) -> Result<(String, Response), (Option<String>, Response)> {
    let authorization_header = extract_authorization_header(request.headers())
        .map_err(|error| (None, error.response(Some(request_id))))?;
    let authorized = validate_bearer_authorized_request(authorization_header, state.secrets())
        .map_err(|error| (None, error.response(Some(request_id))))?;
    let client_slug = authorized.client_slug.clone();

    let (_parts, body) = request.into_parts();
    let body = to_bytes(body, MCP_MAX_BODY_BYTES).await.map_err(|error| {
        (
            Some(client_slug.clone()),
            AppError::BadRequest(format!("failed to read request body: {error}"))
                .response(Some(request_id)),
        )
    })?;
    let raw_request: Value = serde_json::from_slice(&body).map_err(|_| {
        (
            Some(client_slug.clone()),
            json_rpc_error_response(None, -32700, "parse error"),
        )
    })?;
    let rpc_id = json_rpc_id(&raw_request);
    let JsonRpcRequest {
        jsonrpc,
        id,
        method,
        params,
    } = serde_json::from_value(raw_request).map_err(|_| {
        (
            Some(client_slug.clone()),
            json_rpc_error_response(rpc_id, -32600, "invalid request"),
        )
    })?;
    if jsonrpc != "2.0" {
        return Err((
            Some(client_slug),
            json_rpc_error_response(id, -32600, "invalid request"),
        ));
    }

    let response = match method.as_str() {
        "initialize" => JsonRpcResponse::success(id, initialize_result()).into_response(),
        "tools/list" => JsonRpcResponse::success(
            id,
            ToolsListResult {
                tools: supported_tools(),
            },
        )
        .into_response(),
        "tools/call" => handle_tools_call(&state, &authorized, id, params).await,
        _ => JsonRpcResponse::<serde_json::Value>::error(id, -32601, "method not found")
            .into_response(),
    };

    Ok((client_slug, response))
}

fn json_rpc_error_response(id: Option<JsonRpcId>, code: i32, message: &'static str) -> Response {
    JsonRpcResponse::<Value>::error(id, code, message).into_response()
}

fn json_rpc_id(value: &Value) -> Option<JsonRpcId> {
    let value = value.as_object()?.get("id")?;

    match value {
        Value::String(value) => Some(JsonRpcId::String(value.clone())),
        Value::Number(value) => Some(JsonRpcId::Number(value.clone())),
        Value::Null => Some(JsonRpcId::Null),
        _ => None,
    }
}

async fn handle_tools_call(
    state: &AppState,
    authorized: &AuthorizedRequest,
    id: Option<JsonRpcId>,
    params: Option<serde_json::Value>,
) -> Response {
    let params_value = params.unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    let result = match serde_json::from_value::<ToolsCallParams>(params_value) {
        Ok(params) => match call_tool(state, authorized, params).await {
            Ok(result) => result,
            Err(error) => ToolResult::app_error(&error),
        },
        Err(_) => {
            return JsonRpcResponse::<serde_json::Value>::error(id, -32602, "invalid params")
                .into_response();
        }
    };

    let upstream_request = result.upstream_request.clone();
    let mut response = JsonRpcResponse::success(id, result).into_response();
    if let Some(upstream_request) = upstream_request {
        response.extensions_mut().insert(upstream_request);
    }

    response
}
