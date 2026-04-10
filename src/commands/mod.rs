use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::cli::{
    Command, ConfigAddApiArgs, ConfigAddClientArgs, ConfigArgs, ConfigCommand, ConfigEditArgs,
    ConfigInitArgs, ConfigShowArgs, ConfigValidateArgs, StartArgs,
};
use crate::config::ConfigError;
use crate::config::app_config::AppConfig;
use crate::error::AppError;
use crate::telemetry::init_tracing;

pub mod config;
pub mod start;

#[derive(Debug)]
pub struct CommandError {
    message: String,
}

impl CommandError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for CommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CommandError {}

impl From<ConfigError> for CommandError {
    fn from(error: ConfigError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<AppError> for CommandError {
    fn from(error: AppError) -> Self {
        Self::new(error.to_string())
    }
}

pub fn run(command: Command) -> Result<(), CommandError> {
    init_tracing(command.log_level())?;

    match command {
        Command::Start(args) => run_start(args),
        Command::Config(args) => run_config(args),
    }
}

fn run_config(args: ConfigArgs) -> Result<(), CommandError> {
    match args.command {
        ConfigCommand::Init(args) => {
            config::init(map_config_init_args(args))
                .map_err(|error| CommandError::new(error.to_string()))?;
        }
        ConfigCommand::Show(args) => {
            let contents = config::show(map_config_show_args(args))
                .map_err(|error| CommandError::new(error.to_string()))?;
            print!("{contents}");
        }
        ConfigCommand::Edit(args) => {
            config::edit(map_config_edit_args(args))
                .map_err(|error| CommandError::new(error.to_string()))?;
        }
        ConfigCommand::Validate(args) => {
            let message = config::validate(map_config_validate_args(args))
                .map_err(|error| CommandError::new(error.to_string()))?;
            println!("{message}");
        }
        ConfigCommand::AddApi(args) => {
            config::add_api(map_config_add_api_args(args))
                .map_err(|error| CommandError::new(error.to_string()))?;
        }
        ConfigCommand::AddClient(args) => {
            config::add_client(map_config_add_client_args(args))
                .map_err(|error| CommandError::new(error.to_string()))?;
        }
    }

    Ok(())
}

fn run_start(args: StartArgs) -> Result<(), CommandError> {
    let config = AppConfig::from_start_args(&args)?;
    start::run_with_config(config)
}

fn map_config_init_args(args: ConfigInitArgs) -> config::ConfigInitArgs {
    config::ConfigInitArgs {
        config: args.config,
        encrypted: args.encrypted,
        password: args.password,
        log_level: args.log_level,
    }
}

fn map_config_show_args(args: ConfigShowArgs) -> config::ConfigShowArgs {
    config::ConfigShowArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
    }
}

fn map_config_edit_args(args: ConfigEditArgs) -> config::ConfigEditArgs {
    config::ConfigEditArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
    }
}

fn map_config_validate_args(args: ConfigValidateArgs) -> config::ConfigValidateArgs {
    config::ConfigValidateArgs {
        config: args.config,
        log_level: args.log_level,
    }
}

fn map_config_add_api_args(args: ConfigAddApiArgs) -> config::ConfigAddApiArgs {
    config::ConfigAddApiArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        name: args.name,
        base_url: args.base_url,
        auth_header: args.auth_header,
        auth_scheme: args.auth_scheme,
        auth_value: args.auth_value,
        timeout_ms: args.timeout_ms,
    }
}

fn map_config_add_client_args(args: ConfigAddClientArgs) -> config::ConfigAddClientArgs {
    config::ConfigAddClientArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        name: args.name,
        bearer_token_expires_at: args.bearer_token_expires_at,
        group: args.group,
        api_access: args.api_access,
    }
}
