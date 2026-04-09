use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;

use crate::error::AppError;

static TRACING_INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

pub fn init_tracing(log_filter: &str) -> Result<(), AppError> {
    init_tracing_with_state(&TRACING_INIT_RESULT, log_filter)
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

    let env_filter = build_env_filter(log_filter)?;

    let init_result = init_result.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
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

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::{build_env_filter, init_tracing_with_state};

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
}
