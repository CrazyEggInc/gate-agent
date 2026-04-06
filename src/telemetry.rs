use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;

use crate::error::AppError;

static TRACING_INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

pub fn init_tracing(log_filter: &str) -> Result<(), AppError> {
    init_tracing_with_state(&TRACING_INIT_RESULT, log_filter)
}

fn init_tracing_with_state(
    init_result: &OnceLock<Result<(), String>>,
    log_filter: &str,
) -> Result<(), AppError> {
    if let Some(existing_result) = init_result.get() {
        return map_init_result(existing_result);
    }

    let env_filter = EnvFilter::try_new(log_filter)
        .map_err(|error| AppError::Internal(format!("invalid log filter: {error}")))?;

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

    use super::init_tracing_with_state;

    #[test]
    fn invalid_log_filter_returns_error() {
        let error =
            init_tracing_with_state(&OnceLock::new(), "[").expect_err("invalid filter should fail");

        assert_eq!(error.code(), "internal");
    }

    #[test]
    fn second_call_after_successful_init_is_a_no_op() {
        let init_result = OnceLock::new();

        init_result
            .set(Ok(()))
            .expect("test tracing state should initialize");

        let result = init_tracing_with_state(&init_result, "[");

        assert!(result.is_ok(), "repeat init should be a no-op");
    }
}
