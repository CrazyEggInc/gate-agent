use std::time::Duration;

use crate::config::secrets::ApiConfig;
use crate::error::AppError;

pub async fn execute_request(
    client: &reqwest::Client,
    request: reqwest::Request,
    api_config: &ApiConfig,
) -> Result<reqwest::Response, AppError> {
    let timeout = Duration::from_millis(api_config.timeout_ms);
    let response = tokio::time::timeout(timeout, client.execute(request))
        .await
        .map_err(|_| AppError::UpstreamTimeout)?;

    response.map_err(|error| {
        if error.is_timeout() {
            AppError::UpstreamTimeout
        } else {
            AppError::UpstreamRequest(error.to_string())
        }
    })
}
