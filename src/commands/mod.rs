use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::IsTerminal;

use crate::cli::{
    Command, ConfigAddApiArgs, ConfigAddClientArgs, ConfigAddGroupArgs, ConfigArgs, ConfigCommand,
    ConfigEditArgs, ConfigInitArgs, ConfigShowArgs, ConfigValidateArgs, StartArgs,
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
    config::reset_test_prompt_state_if_exhausted()
        .map_err(|error| CommandError::new(error.to_string()))?;

    match args.command {
        ConfigCommand::Init(args) => {
            let resolved = resolve_config_init_args(args)?;
            config::init(resolved).map_err(|error| CommandError::new(error.to_string()))?;
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
            let resolved = resolve_config_add_api_args(args)?;
            config::add_api(resolved).map_err(|error| CommandError::new(error.to_string()))?;
        }
        ConfigCommand::AddGroup(args) => {
            let resolved = resolve_config_add_group_args(args)?;
            config::add_group(resolved).map_err(|error| CommandError::new(error.to_string()))?;
        }
        ConfigCommand::AddClient(args) => {
            let resolved = resolve_config_add_client_args(args)?;
            config::add_client(resolved).map_err(|error| CommandError::new(error.to_string()))?;
        }
    }

    Ok(())
}

fn run_start(args: StartArgs) -> Result<(), CommandError> {
    let config = AppConfig::from_start_args(&args)?;
    start::run_with_config(config)
}

fn resolve_config_init_args(args: ConfigInitArgs) -> Result<config::ConfigInitArgs, CommandError> {
    let encrypted = if args.encrypted_was_explicitly_set() {
        args.encrypted
    } else if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        config::prompt_yes_no(
            &config::prompt_message("Write encrypted config?", None, None, None, None, None),
            true,
            "config init requires --encrypted to be decided in non-interactive sessions",
        )
        .map_err(|error| CommandError::new(error.to_string()))?
    } else {
        args.encrypted
    };

    let default_path =
        config::default_init_config_path().map_err(|error| CommandError::new(error.to_string()))?;
    let default_path_display = default_path.display().to_string();
    let config = if let Some(path) = args.config {
        Some(path)
    } else if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        Some(
            config::prompt_required_text(
                &config::prompt_message(
                    "Config path",
                    None,
                    Some(&default_path_display),
                    Some("~/.config/gate-agent/secrets"),
                    None,
                    None,
                ),
                Some(&default_path_display),
                "config init requires a config path",
            )
            .map(std::path::PathBuf::from)
            .map_err(|error| CommandError::new(error.to_string()))?,
        )
    } else {
        Some(default_path)
    };

    Ok(config::ConfigInitArgs {
        config,
        encrypted,
        password: args.password,
        log_level: args.log_level,
    })
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

fn resolve_config_add_api_args(
    args: ConfigAddApiArgs,
) -> Result<config::ConfigAddApiArgs, CommandError> {
    let invoked_name = "add-api";
    let name_error = format!("config {invoked_name} requires --name in non-interactive sessions");
    let base_url_error =
        format!("config {invoked_name} requires --base-url in non-interactive sessions");

    let name = resolve_required_arg(
        args.name,
        &config::prompt_message("API name", None, None, None, None, None),
        &name_error,
    )?;
    let base_url = resolve_required_arg(
        args.base_url,
        &config::prompt_message(
            "Base URL",
            None,
            None,
            Some("https://projects.internal.example/api"),
            None,
            None,
        ),
        &base_url_error,
    )?;

    let mut auth_header = optional_non_empty(args.auth_header);
    let mut auth_value = optional_non_empty(args.auth_value);

    if auth_header.is_none() && auth_value.is_none() && interactive_questionnaire_available() {
        auth_header = config::prompt_optional_text(
            &config::prompt_message(
                "Auth header",
                None,
                Some("authorization"),
                None,
                None,
                Some("use 'none' for no auth"),
            ),
            Some("authorization"),
            "config add-api accepts optional --auth-header",
        )
        .map_err(|error| CommandError::new(error.to_string()))?;

        if auth_header.as_deref() == Some("none") {
            auth_header = None;
        }

        if auth_header.is_some() {
            auth_value = Some(
                config::prompt_required_text(
                    &config::prompt_message(
                        "Auth value",
                        None,
                        None,
                        Some("Bearer my-token"),
                        None,
                        None,
                    ),
                    None,
                    "config add-api requires --auth-value when auth_header is configured",
                )
                .map_err(|error| CommandError::new(error.to_string()))?,
            );
        }
    }

    if auth_header.is_none() && auth_value.is_some() {
        return Err(CommandError::new(
            "auth_value cannot be set without auth_header",
        ));
    }

    if auth_header.is_some() && auth_value.is_none() {
        return Err(CommandError::new(
            "auth_value is required when auth_header is configured",
        ));
    }

    Ok(config::ConfigAddApiArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        name,
        base_url,
        auth_header,
        auth_value,
        timeout_ms: args.timeout_ms,
    })
}

fn resolve_config_add_client_args(
    args: ConfigAddClientArgs,
) -> Result<config::ConfigAddClientArgs, CommandError> {
    let name = resolve_required_arg(
        args.name,
        &config::prompt_message("Client name", None, None, None, None, None),
        "config add-client requires --name in non-interactive sessions",
    )?;

    let group = if args.group.is_some() || !args.api_access.is_empty() {
        args.group
    } else {
        let existing_groups =
            config::list_group_slugs(args.config.as_deref(), args.password.clone())
                .map_err(|error| CommandError::new(error.to_string()))?;
        let options = if existing_groups.is_empty() {
            "blank = inline api_access".to_owned()
        } else {
            format!("{}, blank = inline api_access", existing_groups.join(", "))
        };

        config::prompt_optional_text(
            &config::prompt_message("Group name", None, None, None, Some(&options), None),
            None,
            "config add-client requires --group or --api-access in non-interactive sessions",
        )
        .map_err(|error| CommandError::new(error.to_string()))?
    };

    let api_access =
        if group.is_some() || !args.api_access.is_empty() {
            args.api_access
        } else {
            vec![config::prompt_required_text(
            &config::prompt_message(
                "Inline api_access entry",
                None,
                None,
                Some("projects=read,reports=write"),
                Some("levels: read, write"),
                None,
            ),
            None,
            "config add-client requires --group or --api-access in non-interactive sessions",
        )
        .map_err(|error| CommandError::new(error.to_string()))?]
        };

    Ok(config::ConfigAddClientArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        name,
        bearer_token_expires_at: args.bearer_token_expires_at,
        group,
        api_access,
    })
}

fn resolve_config_add_group_args(
    args: ConfigAddGroupArgs,
) -> Result<config::ConfigAddGroupArgs, CommandError> {
    let name = resolve_required_arg(
        args.name,
        &config::prompt_message("Group name", None, None, None, None, None),
        "config add-group requires --name in non-interactive sessions",
    )?;

    let api_access = if args.api_access.is_empty() {
        vec![
            config::prompt_required_text(
                &config::prompt_message(
                    "Inline api_access entry",
                    None,
                    None,
                    Some("projects=read,reports=write"),
                    Some("levels: read, write"),
                    None,
                ),
                None,
                "config add-group requires --api-access in non-interactive sessions",
            )
            .map_err(|error| CommandError::new(error.to_string()))?,
        ]
    } else {
        args.api_access
    };

    Ok(config::ConfigAddGroupArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        name,
        api_access,
    })
}

fn resolve_required_arg(
    value: String,
    prompt: &str,
    non_interactive_message: &str,
) -> Result<String, CommandError> {
    if !value.trim().is_empty() {
        return Ok(value);
    }

    config::prompt_required_text(prompt, None, non_interactive_message)
        .map_err(|error| CommandError::new(error.to_string()))
}

fn optional_non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn interactive_questionnaire_available() -> bool {
    std::env::var_os("GATE_AGENT_TEST_PROMPT_INPUTS").is_some()
        || (std::io::stdin().is_terminal() && std::io::stderr().is_terminal())
}
