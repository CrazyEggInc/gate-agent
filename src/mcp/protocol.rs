use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value, json};

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    String(String),
    Number(Number),
    Null,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<JsonRpcId>,
    pub method: String,
    #[allow(dead_code)]
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: &'static str,
    pub id: JsonRpcId,
    #[serde(flatten)]
    pub payload: JsonRpcPayload<T>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum JsonRpcPayload<T> {
    Result { result: T },
    Error { error: JsonRpcError },
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: &'static str,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

#[derive(Debug, Serialize)]
pub struct ServerCapabilities {
    pub tools: ToolsCapability,
}

#[derive(Debug, Serialize)]
pub struct ToolsCapability {}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ToolsListResult {
    pub tools: Vec<ToolDefinition>,
}

#[derive(Debug, Serialize)]
pub struct ToolDefinition {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Debug, Serialize)]
pub struct ToolResult {
    pub content: Vec<ToolTextContent>,
    #[serde(rename = "structuredContent")]
    pub structured_content: Value,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

#[derive(Debug, Serialize)]
pub struct ToolTextContent {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub text: String,
}

impl<T> JsonRpcResponse<T>
where
    T: Serialize,
{
    pub fn success(id: Option<JsonRpcId>, result: T) -> Self {
        Self {
            jsonrpc: "2.0",
            id: id.unwrap_or(JsonRpcId::Null),
            payload: JsonRpcPayload::Result { result },
        }
    }

    pub fn error(id: Option<JsonRpcId>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id: id.unwrap_or(JsonRpcId::Null),
            payload: JsonRpcPayload::Error {
                error: JsonRpcError {
                    code,
                    message: message.into(),
                },
            },
        }
    }

    pub fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

impl ToolResult {
    pub fn success(content_json: Value) -> Self {
        let text = serde_json::to_string_pretty(&content_json).unwrap_or_else(|_| "{}".to_owned());
        Self {
            content: vec![ToolTextContent::text(text)],
            structured_content: json!({}),
            is_error: false,
        }
    }

    pub fn app_error(error: &crate::error::AppError) -> Self {
        let content_json = json!({
            "code": error.code(),
            "message": match error {
                crate::error::AppError::BadRequest(message)
                | crate::error::AppError::ResponseMapping(message) => message,
                _ => error.safe_message(),
            }
        });
        let text = serde_json::to_string_pretty(&content_json).unwrap_or_else(|_| "{}".to_owned());
        Self {
            content: vec![ToolTextContent::text(text)],
            structured_content: json!({}),
            is_error: true,
        }
    }
}

impl ToolTextContent {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            kind: "text",
            text: text.into(),
        }
    }
}

pub fn initialize_result() -> InitializeResult {
    InitializeResult {
        protocol_version: "2025-03-26",
        capabilities: ServerCapabilities {
            tools: ToolsCapability {},
        },
        server_info: ServerInfo {
            name: "gate-agent",
            version: env!("CARGO_PKG_VERSION"),
        },
    }
}
