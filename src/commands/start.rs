use axum::Router;
use tokio::net::TcpListener;

use crate::app::AppState;
use crate::cli::StartArgs;
use crate::config::app_config::AppConfig;
use crate::error::AppError;
use crate::proxy::router::build_router;
use crate::telemetry::init_tracing;

use super::CommandError;

#[derive(Clone)]
pub struct PreparedStart {
    pub config: AppConfig,
    pub state: AppState,
    pub app: Router,
}

pub fn prepare(args: &StartArgs) -> Result<PreparedStart, AppError> {
    let config = AppConfig::from_start_args(args)
        .map_err(|error| AppError::ConfigLoad(error.to_string()))?;

    init_tracing(&config.log_level)?;

    let state = AppState::from_config(&config)?;
    let app = build_router(state.clone());

    Ok(PreparedStart { config, state, app })
}

pub async fn bind_listener(bind: std::net::SocketAddr) -> Result<TcpListener, AppError> {
    TcpListener::bind(bind)
        .await
        .map_err(|error| AppError::Internal(format!("failed to bind server listener: {error}")))
}

pub async fn serve(listener: TcpListener, app: Router) -> Result<(), AppError> {
    axum::serve(listener, app)
        .await
        .map_err(|error| AppError::Internal(format!("server failed: {error}")))
}

pub fn run(args: StartArgs) -> Result<(), CommandError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| CommandError::new(format!("failed to start tokio runtime: {error}")))?;

    runtime.block_on(async move {
        let prepared = prepare(&args)?;
        let listener = bind_listener(prepared.config.bind).await?;

        serve(listener, prepared.app).await
    })?;

    Ok(())
}
