use secrecy::ExposeSecret;
use serde_json::json;

use crate::{
    cli::{CurlArgs, StartArgs},
    config::{
        app_config::{AppConfig, DEFAULT_LOG_LEVEL},
        secrets::ClientConfig,
    },
};

use super::CommandError;

pub fn run(args: CurlArgs) -> Result<(), CommandError> {
    let payload = render(args)?;
    print!("{payload}");
    Ok(())
}

pub fn render(args: CurlArgs) -> Result<String, CommandError> {
    let config = load_local_config(&args)?;

    if args.auth {
        return render_auth_payload(&args, &config);
    }

    render_proxy_payload(&args, &config)
}

fn load_local_config(args: &CurlArgs) -> Result<AppConfig, CommandError> {
    let start_args = StartArgs {
        bind: args.bind,
        config: args.config.clone(),
        password: args.password.clone(),
        log_level: DEFAULT_LOG_LEVEL.to_owned(),
    };

    AppConfig::from_start_args(&start_args).map_err(CommandError::from)
}

fn render_auth_payload(args: &CurlArgs, config: &AppConfig) -> Result<String, CommandError> {
    if args.proxy || args.jwt.is_some() || args.api.is_some() || args.path.is_some() {
        return Err(CommandError::new(
            "--auth cannot be combined with --proxy, --jwt, --api, or --path",
        ));
    }

    let client = config
        .secrets()
        .clients
        .get(&args.client)
        .ok_or_else(|| CommandError::new(format!("unknown client '{}'", args.client)))?;
    let apis = client.allowed_apis.iter().cloned().collect::<Vec<_>>();

    if apis.is_empty() {
        return Err(CommandError::new(format!(
            "client '{}' has no allowed_apis configured",
            client.slug
        )));
    }

    let body = json!({ "apis": apis }).to_string();

    Ok(format!(
        concat!(
            "url = \"{url}\"\n",
            "request = \"POST\"\n",
            "header = \"x-api-key: {api_key}\"\n",
            "header = \"content-type: application/json\"\n",
            "data = \"{body}\"\n"
        ),
        url = local_auth_url(config),
        api_key = client.api_key.expose_secret(),
        body = escape_for_curl_config(&body),
    ))
}

fn render_proxy_payload(args: &CurlArgs, config: &AppConfig) -> Result<String, CommandError> {
    if args.proxy && args.auth {
        return Err(CommandError::new("--auth cannot be combined with --proxy"));
    }

    let jwt = args
        .jwt
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CommandError::new("--jwt is required in proxy mode"))?;

    let api = args
        .api
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CommandError::new("--api is required when using --jwt"))?;

    let path = args
        .path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CommandError::new("--path is required when using --jwt"))?;

    if !path.starts_with('/') {
        return Err(CommandError::new("path must start with '/'"));
    }

    if !config.secrets().apis.contains_key(api) {
        return Err(CommandError::new(format!("unknown api '{}'", api)));
    }

    Ok(format!(
        concat!(
            "url = \"{url}\"\n",
            "header = \"Authorization: Bearer {jwt}\"\n"
        ),
        url = local_proxy_url(config, api, path),
        jwt = jwt,
    ))
}

fn local_auth_url(config: &AppConfig) -> String {
    format!("http://{}/auth/exchange", config.bind())
}

fn local_proxy_url(config: &AppConfig, api: &str, path: &str) -> String {
    format!("http://{}/proxy/{api}{path}", config.bind())
}

fn escape_for_curl_config(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[allow(dead_code)]
fn _client_slug(client: &ClientConfig) -> &str {
    &client.slug
}
