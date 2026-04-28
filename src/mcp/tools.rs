use std::collections::BTreeMap;

use axum::body::Body;
use bytes::BytesMut;
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::form_urlencoded;

use crate::{
    app::AppState,
    auth::bearer::AuthorizedRequest,
    config::secrets::{ApiAccessMethod, ApiAccessRule},
    error::AppError,
    proxy::{
        forward::{forward_prepared_request, prepare_authorized_forward_request},
        request::ForwardRequest,
    },
};

use super::protocol::{ToolDefinition, ToolResult};

const JSON_CONTENT_TYPE: &str = "application/json";
const TEXT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const CALL_API_QUERY_GUIDANCE: &str = "Pass query parameters in call_api.query, not in call_api.path. Keep path path-only, for example path /users with query {\"active\":true}.";
const LIST_APIS_USAGE_HINT: &str = "Call this API with the call_api tool. Put query parameters in call_api.query and keep call_api.path path-only.";
const MCP_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct ToolsCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallApiArguments {
    api: String,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<Map<String, Value>>,
    #[serde(default)]
    headers: Option<Map<String, Value>>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    response_headers: ResponseHeadersMode,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseHeadersMode {
    #[default]
    Essential,
    All,
}

#[derive(Debug, Serialize)]
struct ListApisPayload {
    call_api_query_guidance: &'static str,
    apis: Vec<ApiDescriptor>,
}

#[derive(Debug, Serialize)]
struct ApiDescriptor {
    slug: String,
    rules: Vec<ApiRuleDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    docs_url: Option<String>,
    usage_hint: &'static str,
    example_arguments: CallApiExampleArguments,
}

#[derive(Debug, Serialize)]
struct ApiRuleDescriptor {
    method: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct CallApiExampleArguments {
    api: String,
    method: &'static str,
    path: &'static str,
    query: Value,
}

#[derive(Debug, Serialize)]
struct CallApiPayload {
    status: u16,
    headers: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_json: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_text: Option<String>,
}

pub fn supported_tools() -> Vec<ToolDefinition> {
    vec![call_api_tool_definition(), list_apis_tool_definition()]
}

pub async fn call_tool(
    state: &AppState,
    authorized: &AuthorizedRequest,
    params: ToolsCallParams,
) -> Result<ToolResult, AppError> {
    match params.name.as_str() {
        "list_apis" => list_apis(state, authorized),
        "call_api" => call_api(state, authorized, params.arguments).await,
        _ => Err(AppError::BadRequest(format!(
            "unsupported MCP tool '{}'",
            params.name
        ))),
    }
}

fn list_apis(state: &AppState, authorized: &AuthorizedRequest) -> Result<ToolResult, AppError> {
    let mut apis = Vec::new();

    for (slug, rules) in &authorized.access.apis {
        if rules.is_empty() {
            continue;
        }

        let api_config = state.api_config(slug)?;
        apis.push(ApiDescriptor {
            slug: slug.clone(),
            rules: rules.iter().map(api_rule_descriptor).collect(),
            description: api_config.description.clone(),
            docs_url: api_config.docs_url.as_ref().map(|url| url.to_string()),
            usage_hint: LIST_APIS_USAGE_HINT,
            example_arguments: CallApiExampleArguments {
                api: slug.clone(),
                method: "GET",
                path: "/<endpoint>",
                query: serde_json::json!({ "example": "value" }),
            },
        });
    }

    let payload = ListApisPayload {
        call_api_query_guidance: CALL_API_QUERY_GUIDANCE,
        apis,
    };
    let content_json = serde_json::to_value(&payload).map_err(|error| {
        AppError::Internal(format!("failed to serialize MCP list_apis result: {error}"))
    })?;

    Ok(ToolResult::success(content_json))
}

fn api_rule_descriptor(rule: &ApiAccessRule) -> ApiRuleDescriptor {
    let method = match &rule.method {
        ApiAccessMethod::Any => "*".to_owned(),
        ApiAccessMethod::Exact(method) => method.as_str().to_ascii_lowercase(),
    };

    ApiRuleDescriptor {
        method,
        path: rule.path.clone(),
    }
}

async fn call_api(
    state: &AppState,
    authorized: &AuthorizedRequest,
    arguments: Option<Value>,
) -> Result<ToolResult, AppError> {
    let arguments = arguments.unwrap_or(Value::Object(Map::new()));
    let arguments: CallApiArguments = serde_json::from_value(arguments)
        .map_err(|error| AppError::BadRequest(format!("invalid call_api arguments: {error}")))?;
    let response_headers = arguments.response_headers;
    let forward_request = build_forward_request(arguments)?;
    let prepared = prepare_authorized_forward_request(forward_request, authorized)?;
    let forward = forward_prepared_request(state, prepared).await?;
    let payload = map_call_api_response(forward.response, response_headers).await?;
    let content_json = serde_json::to_value(&payload).map_err(|error| {
        AppError::Internal(format!("failed to serialize MCP call_api result: {error}"))
    })?;

    Ok(ToolResult::success(content_json))
}

fn call_api_tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: "call_api",
        description: "Call an allowed upstream API through gate-agent.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "api": { "type": "string" },
                "method": { "type": "string" },
                "path": {
                    "type": "string",
                    "pattern": "^/",
                    "description": "Path to call on the selected API. Do not include query strings or fragments; pass query parameters with the query argument."
                },
                "query": {
                    "type": "object",
                    "description": "Optional query parameters to append to the upstream request URL. Use this instead of embedding a query string in path.",
                    "additionalProperties": {
                        "anyOf": [
                            { "type": "string" },
                            { "type": "number" },
                            { "type": "boolean" },
                            { "type": "null" },
                            {
                                "type": "array",
                                "items": {
                                    "anyOf": [
                                        { "type": "string" },
                                        { "type": "number" },
                                        { "type": "boolean" },
                                        { "type": "null" }
                                    ]
                                }
                            }
                        ]
                    }
                },
                "headers": { "type": "object", "additionalProperties": { "type": "string" } },
                "body": {},
                "content_type": { "type": "string" },
                "response_headers": {
                    "type": "string",
                    "enum": ["essential", "all"]
                }
            },
            "required": ["api", "method", "path"],
            "additionalProperties": false
        }),
    }
}

fn list_apis_tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: "list_apis",
        description: "List APIs allowed for the authenticated client.",
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
    }
}

fn build_forward_request(arguments: CallApiArguments) -> Result<ForwardRequest, AppError> {
    let method = Method::from_bytes(arguments.method.as_bytes())
        .map_err(|error| AppError::BadRequest(format!("method is invalid: {error}")))?;

    if !arguments.path.starts_with('/') {
        return Err(AppError::BadRequest("path must start with '/'".to_owned()));
    }

    if arguments.path.contains('?') || arguments.path.contains('#') {
        return Err(AppError::BadRequest(
            "path must not include query or fragment components".to_owned(),
        ));
    }

    let path_and_query = build_path_and_query(&arguments.path, arguments.query.as_ref())?;
    let body_and_content_type = build_body(arguments.body, arguments.content_type.as_deref())?;
    let mut headers = build_headers(arguments.headers.as_ref())?;

    if let Some(content_type) = body_and_content_type.content_type {
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&content_type).map_err(|error| {
                AppError::BadRequest(format!("content_type is invalid: {error}"))
            })?,
        );
    }

    Ok(ForwardRequest {
        api_slug: arguments.api,
        method,
        path_and_query,
        headers,
        body: Body::from(body_and_content_type.body),
    })
}

fn build_path_and_query(
    path: &str,
    query: Option<&Map<String, Value>>,
) -> Result<String, AppError> {
    let Some(query) = query else {
        return Ok(path.to_owned());
    };

    let mut serializer = form_urlencoded::Serializer::new(String::new());

    for (key, value) in query {
        append_query_value(&mut serializer, key, value)?;
    }

    let query = serializer.finish();
    if query.is_empty() {
        Ok(path.to_owned())
    } else {
        Ok(format!("{path}?{query}"))
    }
}

fn append_query_value(
    serializer: &mut form_urlencoded::Serializer<'_, String>,
    key: &str,
    value: &Value,
) -> Result<(), AppError> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(value) => {
            serializer.append_pair(key, if *value { "true" } else { "false" });
            Ok(())
        }
        Value::Number(value) => {
            serializer.append_pair(key, &value.to_string());
            Ok(())
        }
        Value::String(value) => {
            serializer.append_pair(key, value);
            Ok(())
        }
        Value::Array(values) => {
            for value in values {
                append_query_value(serializer, key, value)?;
            }
            Ok(())
        }
        Value::Object(_) => Err(AppError::BadRequest(
            "query values must be strings, numbers, booleans, null, or arrays of those values"
                .to_owned(),
        )),
    }
}

fn build_headers(headers: Option<&Map<String, Value>>) -> Result<HeaderMap, AppError> {
    let mut header_map = HeaderMap::new();

    let Some(headers) = headers else {
        return Ok(header_map);
    };

    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            AppError::BadRequest(format!("header name '{name}' is invalid: {error}"))
        })?;
        let value = value
            .as_str()
            .ok_or_else(|| AppError::BadRequest(format!("header '{name}' must be a string")))?;
        let value = HeaderValue::from_str(value).map_err(|error| {
            AppError::BadRequest(format!("header '{name}' is invalid: {error}"))
        })?;
        header_map.append(name, value);
    }

    Ok(header_map)
}

struct EncodedBody {
    body: Vec<u8>,
    content_type: Option<String>,
}

fn build_body(body: Option<Value>, content_type: Option<&str>) -> Result<EncodedBody, AppError> {
    let normalized_content_type = content_type.map(normalize_content_type).transpose()?;

    if let Some(content_type) = normalized_content_type.as_deref()
        && !is_json_content_type(content_type)
        && !is_text_content_type(content_type)
    {
        return Err(AppError::BadRequest(
            "unsupported MCP request content type".to_owned(),
        ));
    }

    let body = match body {
        None => {
            return Ok(EncodedBody {
                body: Vec::new(),
                content_type: normalized_content_type,
            });
        }
        Some(body) => body,
    };

    let content_type = match normalized_content_type {
        Some(content_type) => content_type,
        None => infer_content_type(&body),
    };

    if is_json_content_type(&content_type) {
        let body = serde_json::to_vec(&body)
            .map_err(|error| AppError::BadRequest(format!("body is invalid JSON: {error}")))?;

        return Ok(EncodedBody {
            body,
            content_type: Some(content_type),
        });
    }

    if is_text_content_type(&content_type) {
        let Value::String(body) = body else {
            return Err(AppError::BadRequest(
                "text content_type requires a string body".to_owned(),
            ));
        };

        return Ok(EncodedBody {
            body: body.into_bytes(),
            content_type: Some(content_type),
        });
    }

    Err(AppError::BadRequest(
        "unsupported MCP request content type".to_owned(),
    ))
}

fn normalize_content_type(content_type: &str) -> Result<String, AppError> {
    let content_type = content_type.trim();

    if content_type.is_empty() {
        return Err(AppError::BadRequest(
            "content_type cannot be empty".to_owned(),
        ));
    }

    Ok(content_type.to_owned())
}

fn infer_content_type(body: &Value) -> String {
    match body {
        Value::String(_) => TEXT_CONTENT_TYPE.to_owned(),
        _ => JSON_CONTENT_TYPE.to_owned(),
    }
}

async fn map_call_api_response(
    response: crate::proxy::response::ForwardedResponse,
    response_headers: ResponseHeadersMode,
) -> Result<CallApiPayload, AppError> {
    let status = response.status.as_u16();
    let headers = serialize_headers(&response.headers, response_headers);
    let content_type = response
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = collect_bounded_response_body(response).await?;

    if body.is_empty() {
        return Ok(CallApiPayload {
            status,
            headers,
            content_type,
            body_json: None,
            body_text: None,
        });
    }

    let Some(content_type_value) = content_type.clone() else {
        let body_text = String::from_utf8(body.to_vec()).map_err(|_| {
            AppError::ResponseMapping("unsupported MCP upstream response content type".to_owned())
        })?;

        return Ok(CallApiPayload {
            status,
            headers,
            content_type,
            body_json: None,
            body_text: Some(body_text),
        });
    };

    if is_json_content_type(&content_type_value) {
        let body_json = serde_json::from_slice(&body).map_err(|error| {
            AppError::ResponseMapping(format!("failed to parse upstream JSON response: {error}"))
        })?;

        return Ok(CallApiPayload {
            status,
            headers,
            content_type,
            body_json: Some(body_json),
            body_text: None,
        });
    }

    if is_text_content_type(&content_type_value) {
        let body_text = String::from_utf8(body.to_vec()).map_err(|_| {
            AppError::ResponseMapping("unsupported MCP upstream response content type".to_owned())
        })?;

        return Ok(CallApiPayload {
            status,
            headers,
            content_type,
            body_json: None,
            body_text: Some(body_text),
        });
    }

    Err(AppError::ResponseMapping(
        "unsupported MCP upstream response content type".to_owned(),
    ))
}

async fn collect_bounded_response_body(
    response: crate::proxy::response::ForwardedResponse,
) -> Result<bytes::Bytes, AppError> {
    let mut stream = response.into_body_stream();
    let mut body = BytesMut::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            AppError::ResponseMapping(format!("failed to read upstream response body: {error}"))
        })?;

        if body.len().saturating_add(chunk.len()) > MCP_MAX_PAYLOAD_BYTES {
            return Err(AppError::ResponseMapping(format!(
                "MCP upstream response body exceeds {} bytes",
                MCP_MAX_PAYLOAD_BYTES
            )));
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}

fn serialize_headers(
    headers: &HeaderMap,
    response_headers: ResponseHeadersMode,
) -> BTreeMap<String, Vec<String>> {
    let mut grouped = BTreeMap::<String, Vec<String>>::new();

    for (name, value) in headers {
        if !include_response_header(name.as_str(), response_headers) {
            continue;
        }

        if let Ok(value) = value.to_str() {
            grouped
                .entry(name.as_str().to_owned())
                .or_default()
                .push(value.to_owned());
        }
    }

    grouped
}

fn include_response_header(name: &str, response_headers: ResponseHeadersMode) -> bool {
    if is_sensitive_response_header(name) {
        return false;
    }

    match response_headers {
        ResponseHeadersMode::All => true,
        ResponseHeadersMode::Essential => {
            name.eq_ignore_ascii_case("content-type") || name.eq_ignore_ascii_case("date")
        }
    }
}

fn is_sensitive_response_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();

    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "set-cookie"
            | "www-authenticate"
    ) || name.contains("token")
        || name.contains("secret")
        || name.contains("api-key")
}

fn is_json_content_type(content_type: &str) -> bool {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();

    mime == JSON_CONTENT_TYPE || mime.ends_with("+json")
}

fn is_text_content_type(content_type: &str) -> bool {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();

    mime.starts_with("text/")
}
