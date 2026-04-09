use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;

pub fn unix_timestamp_secs() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| AppError::Internal(format!("system clock is invalid: {error}")))
}

pub fn unix_timestamp_secs_i64() -> Result<i64, AppError> {
    i64::try_from(unix_timestamp_secs()?).map_err(|error| {
        AppError::Internal(format!("system clock timestamp overflowed i64: {error}"))
    })
}
