use std::net::SocketAddr;

use crate::{
    auth::jwt::sign_local_test_token,
    cli::{CurlPayloadArgs, StartArgs},
    config::app_config::{AppConfig, DEFAULT_LOG_LEVEL},
};

use super::CommandError;

pub fn run(args: CurlPayloadArgs) -> Result<(), CommandError> {
    if !args.path.starts_with('/') {
        return Err(CommandError::new("path must start with '/'"));
    }

    let config = load_local_config(&args)?;
    let api = config.secrets.apis.get(&args.api).ok_or_else(|| {
        CommandError::from(crate::error::AppError::ForbiddenApi {
            api: args.api.clone(),
        })
    })?;
    let token = sign_local_test_token(&api.slug, &config.secrets)?;

    println!("url = \"{}\"", local_proxy_url(config.bind, &args.path));
    println!("header = \"Authorization: Bearer {token}\"");

    Ok(())
}

fn load_local_config(args: &CurlPayloadArgs) -> Result<AppConfig, CommandError> {
    let start_args = StartArgs {
        bind: args.bind,
        secrets_file: args.secrets_file.clone(),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    };

    AppConfig::from_start_args(&start_args).map_err(CommandError::from)
}

fn local_proxy_url(bind: SocketAddr, path: &str) -> String {
    format!("http://{bind}/proxy{path}")
}
