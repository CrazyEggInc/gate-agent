use std::{fmt::Display, io, sync::OnceLock};

use axum::http::Uri;
use reqwest::Url;
use serde::Serialize;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter, prelude::*};

use crate::error::AppError;

pub(crate) const GATE_AGENT_REQUEST_ID_HEADER: &str = "x-gate-agent-request-id";

static TRACING_INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct LoggedClient(pub String);

#[derive(Clone, Debug)]
pub(crate) struct LoggedRequestContext {
    pub request_id: String,
    pub method: String,
    pub uri: String,
}

#[derive(Serialize)]
struct FatalErrorLogRecord {
    level: &'static str,
    event: &'static str,
    error_code: &'static str,
    error_message: String,
}

impl From<&AppError> for FatalErrorLogRecord {
    fn from(error: &AppError) -> Self {
        Self {
            level: "ERROR",
            event: "fatal_error",
            error_code: error.code(),
            error_message: error.to_string(),
        }
    }
}

fn fatal_error_log_record(
    error_code: &'static str,
    error_message: impl Display,
) -> FatalErrorLogRecord {
    FatalErrorLogRecord {
        level: "ERROR",
        event: "fatal_error",
        error_code,
        error_message: error_message.to_string(),
    }
}

pub fn sanitize_request_uri_for_logs(uri: &Uri) -> String {
    uri.path().to_owned()
}

pub fn sanitize_url_for_logs(raw_url: &str) -> String {
    if let Ok(url) = Url::parse(raw_url) {
        return format_url_without_sensitive_parts(&url);
    }

    raw_url
        .split(['?', '#'])
        .next()
        .unwrap_or(raw_url)
        .to_owned()
}

pub(crate) fn generate_internal_request_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

pub fn init_tracing(log_filter: &str) -> Result<(), AppError> {
    init_tracing_with_state(&TRACING_INIT_RESULT, log_filter)
}

pub fn emit_fatal_error_json(error: &AppError) -> io::Result<()> {
    write_fatal_error_json(std::io::stderr(), error)
}

pub fn emit_fatal_json_message(
    error_code: &'static str,
    error_message: impl Display,
) -> io::Result<()> {
    write_fatal_json_message(std::io::stderr(), error_code, error_message)
}

pub fn write_fatal_error_json<W>(mut writer: W, error: &AppError) -> io::Result<()>
where
    W: io::Write,
{
    write_fatal_json_message(&mut writer, error.code(), error)
}

pub fn write_fatal_json_message<W>(
    mut writer: W,
    error_code: &'static str,
    error_message: impl Display,
) -> io::Result<()>
where
    W: io::Write,
{
    serde_json::to_writer(
        &mut writer,
        &fatal_error_log_record(error_code, error_message),
    )
    .map_err(io::Error::other)?;
    writer.write_all(b"\n")
}

pub fn build_json_subscriber<W>(
    log_level: &str,
    writer: W,
) -> Result<impl tracing::Subscriber + Send + Sync, AppError>
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let env_filter = build_env_filter(log_level)?;

    Ok(tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_env_filter(env_filter)
        .with_writer(writer)
        .finish())
}

pub fn build_env_filter(log_level: &str) -> Result<EnvFilter, AppError> {
    let log_level = log_level.trim();

    if log_level.is_empty() {
        return Err(AppError::Internal(
            "invalid log level: value cannot be empty".to_owned(),
        ));
    }

    if !matches!(log_level, "warn" | "info" | "debug") {
        return Err(AppError::Internal(format!(
            "invalid log level '{log_level}': expected one of warn, info, debug"
        )));
    }

    let policy = format!("warn,gate_agent={log_level}");

    EnvFilter::try_new(policy)
        .map_err(|error| AppError::Internal(format!("invalid log filter policy: {error}")))
}

fn init_tracing_with_state(
    init_result: &OnceLock<Result<(), String>>,
    log_filter: &str,
) -> Result<(), AppError> {
    if let Some(existing_result) = init_result.get() {
        return map_init_result(existing_result);
    }

    let init_result = init_result.get_or_init(|| {
        build_json_subscriber(log_filter, std::io::stderr)
            .map_err(|error| error.to_string())?
            .try_init()
            .map_err(|error| error.to_string())
    });

    map_init_result(init_result)
}

fn map_init_result(init_result: &Result<(), String>) -> Result<(), AppError> {
    match init_result {
        Ok(()) => Ok(()),
        Err(message) => Err(AppError::Internal(format!(
            "tracing subscriber setup failed: {message}"
        ))),
    }
}

fn format_url_without_sensitive_parts(url: &Url) -> String {
    let Some(host) = url.host_str() else {
        return url.path().to_owned();
    };

    let mut sanitized = format!("{}://{host}", url.scheme());

    if let Some(port) = url.port() {
        sanitized.push(':');
        sanitized.push_str(&port.to_string());
    }

    sanitized.push_str(url.path());

    sanitized
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        io::Write,
        sync::{Arc, Mutex, OnceLock},
    };

    use axum::http::Uri;
    use serde_json::{Value, json};

    use crate::error::AppError;

    use super::{
        build_env_filter, build_json_subscriber, init_tracing_with_state,
        sanitize_request_uri_for_logs, sanitize_url_for_logs, write_fatal_error_json,
        write_fatal_json_message,
    };

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

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedBufferWriter {
                bytes: self.bytes.clone(),
            }
        }
    }

    #[test]
    fn debug_filter_is_scoped_to_the_crate() {
        let env_filter = build_env_filter("debug").expect("debug filter should build");
        let directives = env_filter.to_string();

        assert!(directives.contains("warn"));
        assert!(directives.contains("gate_agent=debug"));
    }

    #[test]
    fn info_filter_is_scoped_to_the_crate() {
        let env_filter = build_env_filter("info").expect("info filter should build");
        let directives = env_filter.to_string();

        assert!(directives.contains("warn"));
        assert!(directives.contains("gate_agent=info"));
    }

    #[test]
    fn invalid_log_level_returns_error() {
        let error = build_env_filter("trace").expect_err("invalid level should fail");

        assert_eq!(error.code(), "internal");
        assert_eq!(
            error.to_string(),
            "internal error: invalid log level 'trace': expected one of warn, info, debug"
        );
    }

    #[test]
    fn second_call_after_successful_init_is_a_no_op() {
        let init_result = OnceLock::new();

        init_result
            .set(Ok(()))
            .expect("test tracing state should initialize");

        let result = init_tracing_with_state(&init_result, "debug");

        assert!(result.is_ok(), "repeat init should be a no-op");
    }

    #[test]
    fn fatal_error_json_writer_emits_one_newline_delimited_record() {
        let mut buffer = Vec::new();

        write_fatal_error_json(
            &mut buffer,
            &AppError::BadRequest("missing token".to_owned()),
        )
        .expect("fatal error json should write");

        let output = String::from_utf8(buffer).expect("fatal error log should be valid utf-8");
        let payload: Value =
            serde_json::from_str(output.trim_end()).expect("fatal error log should be json");

        assert!(output.ends_with('\n'), "output was: {output:?}");
        assert_eq!(output.lines().count(), 1, "output was: {output}");
        assert_eq!(
            payload,
            json!({
                "level": "ERROR",
                "event": "fatal_error",
                "error_code": "bad_request",
                "error_message": "bad request: missing token"
            })
        );
    }

    #[test]
    fn fatal_json_message_writer_uses_rendered_message_without_app_error_prefix() {
        let mut buffer = Vec::new();

        write_fatal_json_message(
            &mut buffer,
            "internal",
            "failed to bind server listener: boom",
        )
        .expect("fatal error json should write");

        let output = String::from_utf8(buffer).expect("fatal error log should be valid utf-8");
        let payload: Value =
            serde_json::from_str(output.trim_end()).expect("fatal error log should be json");

        assert!(output.ends_with('\n'), "output was: {output:?}");
        assert_eq!(output.lines().count(), 1, "output was: {output}");
        assert_eq!(
            payload,
            json!({
                "level": "ERROR",
                "event": "fatal_error",
                "error_code": "internal",
                "error_message": "failed to bind server listener: boom"
            })
        );
    }

    #[test]
    fn json_subscriber_emits_newline_delimited_json_without_span_metadata() {
        let buffer = SharedBuffer::default();
        let subscriber =
            build_json_subscriber("debug", buffer.clone()).expect("json subscriber should build");
        let _guard = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!(
            "http_request",
            request_id = "req-123",
            method = "GET",
            uri = "/proxy/billing/v1/projects/1/tasks"
        );
        let _enter = span.enter();

        tracing::info!(
            status = "201 Created",
            latency_ms = 12,
            api = "billing",
            upstream_method = "GET",
            upstream_url = "https://example.com/api/v1/projects/1/tasks",
            upstream_status = "201 Created",
            timeout_ms = 5000
        );

        let logs = buffer.contents();
        let line = logs.trim();

        assert_eq!(logs.lines().count(), 1, "logs were: {logs}");

        let payload: Value = serde_json::from_str(line).expect("log line should be valid json");
        assert_eq!(payload.get("level").and_then(Value::as_str), Some("INFO"));
        assert_eq!(
            payload.get("status").and_then(Value::as_str),
            Some("201 Created")
        );
        assert_eq!(payload.get("api").and_then(Value::as_str), Some("billing"));
        assert_eq!(
            payload.get("timeout_ms").and_then(Value::as_u64),
            Some(5000)
        );
        assert!(payload.get("fields").is_none(), "payload was: {payload}");
        assert!(payload.get("span").is_none(), "payload was: {payload}");
        assert!(payload.get("spans").is_none(), "payload was: {payload}");
    }

    #[test]
    fn request_uri_sanitizer_removes_query_string() {
        let uri: Uri = "/proxy/projects/items?token=secret&expand=1"
            .parse()
            .expect("uri should parse");

        assert_eq!(sanitize_request_uri_for_logs(&uri), "/proxy/projects/items");
    }

    #[test]
    fn url_sanitizer_removes_userinfo_query_and_fragment() {
        let sanitized =
            sanitize_url_for_logs("https://user:pass@example.com:8443/api/tasks?token=secret#frag");

        assert_eq!(sanitized, "https://example.com:8443/api/tasks");
    }
}
