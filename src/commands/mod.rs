use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::IsTerminal;

use crate::cli::{
    Command, ConfigApiArgs, ConfigArgs, ConfigClientArgs, ConfigClientSubcommand, ConfigCommand,
    ConfigEditArgs, ConfigGroupArgs, ConfigInitArgs, ConfigRotateSecretArgs, ConfigShowArgs,
    ConfigValidateArgs, StartArgs,
};
use crate::config::ConfigError;
use crate::config::app_config::AppConfig;
use crate::config::app_config::DEFAULT_LOG_LEVEL;
use crate::config::secrets::{AccessLevel, DEFAULT_SERVER_BIND, DEFAULT_SERVER_PORT};
use crate::error::AppError;
use crate::telemetry::init_tracing;

pub mod config;
pub mod start;
pub mod version;

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
    if matches!(command, Command::Version) {
        return version::run();
    }

    init_tracing(command.log_level().unwrap_or(DEFAULT_LOG_LEVEL))?;

    match command {
        Command::Start(args) => run_start(args),
        Command::Config(args) => run_config(args),
        Command::Version => version::run(),
    }
}

fn run_config(args: ConfigArgs) -> Result<(), CommandError> {
    config::reset_test_prompt_state_if_exhausted()
        .map_err(|error| CommandError::new(error.to_string()))?;

    match args.command {
        ConfigCommand::Init(args) => {
            let resolved = resolve_config_init_args(args)?;
            config::init_with_server(resolved.args, &resolved.server_bind, resolved.server_port)
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
        ConfigCommand::Api(args) => {
            let outcome = config::apply_api(resolve_config_api_args(args)?)
                .map_err(|error| CommandError::new(error.to_string()))?;
            print_resource_success(&outcome);
        }
        ConfigCommand::Group(args) => {
            let outcome = config::apply_group(resolve_config_group_args(args)?)
                .map_err(|error| CommandError::new(error.to_string()))?;
            print_resource_success(&outcome);
        }
        ConfigCommand::Client(args) => {
            if let Some(ConfigClientSubcommand::RotateSecret(subcommand)) = args.command.clone() {
                reject_rotate_secret_parent_client_flags(&args)?;
                let resolved_args = merge_rotate_secret_args(args, subcommand);
                config::rotate_client_secret(resolve_rotate_secret_args(resolved_args)?)
                    .map_err(|error| CommandError::new(error.to_string()))?;
                return Ok(());
            }

            let outcome = config::apply_client(resolve_config_client_args(args)?)
                .map_err(|error| CommandError::new(error.to_string()))?;
            print_resource_success(&outcome.resource);
        }
    }

    Ok(())
}

fn reject_rotate_secret_parent_client_flags(args: &ConfigClientArgs) -> Result<(), CommandError> {
    let mut forbidden_flags = Vec::new();

    if args.delete {
        forbidden_flags.push("--delete");
    }

    if args.group.is_some() {
        forbidden_flags.push("--group");
    }

    if !args.api_access.is_empty() {
        forbidden_flags.push("--api-access");
    }

    if forbidden_flags.is_empty() {
        return Ok(());
    }

    Err(CommandError::new(format!(
        "config client rotate-secret does not accept parent flags: {}",
        forbidden_flags.join(", ")
    )))
}

fn merge_rotate_secret_args(
    parent: ConfigClientArgs,
    nested: ConfigRotateSecretArgs,
) -> ConfigRotateSecretArgs {
    let nested_log_level_was_explicitly_set = nested.log_level_was_explicitly_set();

    ConfigRotateSecretArgs {
        config: nested.config.or(parent.config),
        password: nested.password.or(parent.password),
        log_level: if nested_log_level_was_explicitly_set {
            nested.log_level
        } else {
            parent.log_level
        },
        log_level_explicitly_set: nested_log_level_was_explicitly_set,
        name: if nested.name.trim().is_empty() {
            parent.name.unwrap_or_default()
        } else {
            nested.name
        },
        bearer_token_expires_at: nested
            .bearer_token_expires_at
            .or(parent.bearer_token_expires_at),
    }
}

fn print_resource_success(outcome: &config::ResourceMutationOutcome) {
    println!(
        "{} {} '{}'",
        outcome.kind.label(),
        outcome.resource_kind.label(),
        outcome.name
    );
}

fn run_start(args: StartArgs) -> Result<(), CommandError> {
    let config = AppConfig::from_start_args(&args)?;
    start::run_with_config(config)
}

struct ResolvedConfigInitArgs {
    args: config::ConfigInitArgs,
    server_bind: String,
    server_port: u16,
}

fn resolve_config_init_args(args: ConfigInitArgs) -> Result<ResolvedConfigInitArgs, CommandError> {
    let interactive = interactive_questionnaire_available();

    let encrypted = if args.encrypted_was_explicitly_set() {
        args.encrypted
    } else if interactive {
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
    } else if interactive {
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

    let server_bind = if interactive {
        config::prompt_required_text(
            &config::prompt_message(
                "Server bind",
                None,
                Some(DEFAULT_SERVER_BIND),
                None,
                None,
                Some("remote setups should use 0.0.0.0"),
            ),
            Some(DEFAULT_SERVER_BIND),
            "config init requires --server-bind in non-interactive sessions",
        )
        .map_err(|error| CommandError::new(error.to_string()))?
    } else {
        DEFAULT_SERVER_BIND.to_owned()
    };

    let default_server_port = DEFAULT_SERVER_PORT.to_string();
    let server_port = if interactive {
        parse_server_port(
            &config::prompt_required_text(
                &config::prompt_message(
                    "Server port",
                    None,
                    Some(&default_server_port),
                    None,
                    None,
                    None,
                ),
                Some(&default_server_port),
                "config init requires --server-port in non-interactive sessions",
            )
            .map_err(|error| CommandError::new(error.to_string()))?,
        )?
    } else {
        DEFAULT_SERVER_PORT
    };

    Ok(ResolvedConfigInitArgs {
        args: config::ConfigInitArgs {
            config,
            encrypted,
            password: args.password,
            log_level: args.log_level,
        },
        server_bind,
        server_port,
    })
}

fn parse_server_port(value: &str) -> Result<u16, CommandError> {
    let port: u16 = value
        .parse()
        .map_err(|_| CommandError::new("Server port must be a number between 1 and 65535"))?;

    if port == 0 {
        return Err(CommandError::new(
            "Server port must be a number between 1 and 65535",
        ));
    }

    Ok(port)
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

fn resolve_config_api_args(args: ConfigApiArgs) -> Result<config::ConfigApiArgs, CommandError> {
    let names = config::list_api_slugs(args.config.as_deref(), args.password.clone())
        .map_err(|error| CommandError::new(error.to_string()))?;
    let detail = config::format_existing_name_hint(config::ResourceKind::Api, &names, args.delete);
    let name = resolve_name(
        args.name,
        "API name",
        detail.as_deref(),
        "config api requires --name in non-interactive sessions",
    )?;

    if args.delete {
        confirm_delete(config::ResourceKind::Api, &name)?;
        return Ok(config::ConfigApiArgs {
            config: args.config,
            password: args.password,
            log_level: args.log_level,
            delete: true,
            name,
            base_url: None,
            auth_header: None,
            auth_value: None,
            timeout_ms: None,
        });
    }

    let existing =
        config::load_existing_api_state(args.config.as_deref(), args.password.clone(), &name)
            .map_err(|error| CommandError::new(error.to_string()))?;

    let base_url = if args.base_url.is_some() {
        args.base_url
    } else if interactive_questionnaire_available() {
        Some(prompt_required(
            "Base URL",
            existing.as_ref().map(|state| state.base_url.as_str()),
            Some("https://projects.internal.example/api"),
            "config api requires --base-url in non-interactive sessions",
        )?)
    } else {
        None
    };

    let existing_auth_header = existing
        .as_ref()
        .and_then(|state| state.auth_header.as_deref());
    let auth_header = if args.auth_header.is_some() || args.auth_value.is_some() {
        args.auth_header
    } else if interactive_questionnaire_available() {
        config::prompt_optional_text(
            &config::prompt_message(
                "Auth header",
                None,
                existing_auth_header,
                Some("authorization"),
                None,
                Some("use 'none' for no auth"),
            ),
            existing_auth_header,
            "config api accepts optional --auth-header",
        )
        .map_err(|error| CommandError::new(error.to_string()))?
    } else {
        None
    };

    let auth_value = if args.auth_value.is_some() {
        args.auth_value
    } else if interactive_questionnaire_available() && auth_header.as_deref() != Some("none") {
        match auth_header.as_deref() {
            Some(header) if !header.trim().is_empty() => Some(prompt_required(
                "Auth value",
                existing
                    .as_ref()
                    .and_then(|state| state.auth_value.as_deref()),
                Some("Bearer my-token"),
                "config api requires --auth-value when auth_header is configured",
            )?),
            _ => None,
        }
    } else {
        None
    };

    let timeout_ms = if args.timeout_ms.is_some() {
        args.timeout_ms
    } else {
        existing.as_ref().map(|state| state.timeout_ms)
    };

    Ok(config::ConfigApiArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        delete: false,
        name,
        base_url,
        auth_header,
        auth_value,
        timeout_ms,
    })
}

fn resolve_config_group_args(
    args: ConfigGroupArgs,
) -> Result<config::ConfigGroupArgs, CommandError> {
    let names = config::list_group_slugs(args.config.as_deref(), args.password.clone())
        .map_err(|error| CommandError::new(error.to_string()))?;
    let detail =
        config::format_existing_name_hint(config::ResourceKind::Group, &names, args.delete);
    let name = resolve_name(
        args.name,
        "Group name",
        detail.as_deref(),
        "config group requires --name in non-interactive sessions",
    )?;

    if args.delete {
        confirm_delete(config::ResourceKind::Group, &name)?;
        return Ok(config::ConfigGroupArgs {
            config: args.config,
            password: args.password,
            log_level: args.log_level,
            delete: true,
            name,
            api_access: vec![],
        });
    }

    let existing =
        config::load_existing_group_state(args.config.as_deref(), args.password.clone(), &name)
            .map_err(|error| CommandError::new(error.to_string()))?;
    let api_access = if !args.api_access.is_empty() {
        args.api_access
    } else if interactive_questionnaire_available() {
        vec![prompt_required(
            "Inline api_access entry",
            existing.as_ref().map(render_api_access_map).as_deref(),
            Some("projects=read,reports=write"),
            "config group requires --api-access in non-interactive sessions",
        )?]
    } else {
        vec![]
    };

    Ok(config::ConfigGroupArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        delete: false,
        name,
        api_access,
    })
}

fn resolve_config_client_args(
    args: ConfigClientArgs,
) -> Result<config::ConfigClientArgs, CommandError> {
    let names = config::list_client_slugs(args.config.as_deref(), args.password.clone())
        .map_err(|error| CommandError::new(error.to_string()))?;
    let detail =
        config::format_existing_name_hint(config::ResourceKind::Client, &names, args.delete);
    let name = resolve_name(
        args.name,
        "Client name",
        detail.as_deref(),
        "config client requires --name in non-interactive sessions",
    )?;

    if args.delete {
        confirm_delete(config::ResourceKind::Client, &name)?;
        return Ok(config::ConfigClientArgs {
            config: args.config,
            password: args.password,
            log_level: args.log_level,
            delete: true,
            name,
            bearer_token_expires_at: None,
            group: None,
            api_access: vec![],
        });
    }

    let existing =
        config::load_existing_client_state(args.config.as_deref(), args.password.clone(), &name)
            .map_err(|error| CommandError::new(error.to_string()))?;

    let bearer_token_expires_at = if args.bearer_token_expires_at.is_some() {
        args.bearer_token_expires_at
    } else if interactive_questionnaire_available() {
        Some(prompt_required(
            "Bearer token expires at",
            existing
                .as_ref()
                .map(|state| state.bearer_token_expires_at.as_str()),
            None,
            "config client requires --bearer-token-expires-at in non-interactive sessions",
        )?)
    } else {
        None
    };

    let has_access = args.group.is_some() || !args.api_access.is_empty();
    if has_access {
        return Ok(config::ConfigClientArgs {
            config: args.config,
            password: args.password,
            log_level: args.log_level,
            delete: false,
            name,
            bearer_token_expires_at,
            group: args.group,
            api_access: args.api_access,
        });
    }

    if interactive_questionnaire_available() {
        let default_mode = if existing
            .as_ref()
            .and_then(|state| state.group.as_ref())
            .is_some()
        {
            "group"
        } else {
            "inline"
        };
        let chosen_mode = config::prompt_required_text(
            &config::prompt_message(
                "Access mode",
                None,
                Some(default_mode),
                None,
                Some("group, inline"),
                None,
            ),
            Some(default_mode),
            "config client requires --group or --api-access in non-interactive sessions",
        )
        .map_err(|error| CommandError::new(error.to_string()))?;

        let (group, api_access) = match chosen_mode.as_str() {
            "group" => {
                let groups =
                    config::list_group_slugs(args.config.as_deref(), args.password.clone())
                        .map_err(|error| CommandError::new(error.to_string()))?;
                let detail = if groups.is_empty() {
                    None
                } else {
                    Some(format!("existing groups: {}", groups.join(", ")))
                };
                let group = config::prompt_required_text(
                    &config::prompt_message(
                        "Group name",
                        detail.as_deref(),
                        existing.as_ref().and_then(|state| state.group.as_deref()),
                        None,
                        None,
                        None,
                    ),
                    existing.as_ref().and_then(|state| state.group.as_deref()),
                    "config client requires --group or --api-access in non-interactive sessions",
                )
                .map_err(|error| CommandError::new(error.to_string()))?;
                (Some(group), vec![])
            }
            "inline" => (
                None,
                vec![prompt_required(
                    "Inline api_access entry",
                    existing
                        .as_ref()
                        .map(render_client_api_access_map)
                        .as_deref(),
                    Some("projects=read,reports=write"),
                    "config client requires --group or --api-access in non-interactive sessions",
                )?],
            ),
            _ => {
                return Err(CommandError::new(
                    "Access mode must be one of: group, inline",
                ));
            }
        };

        return Ok(config::ConfigClientArgs {
            config: args.config,
            password: args.password,
            log_level: args.log_level,
            delete: false,
            name,
            bearer_token_expires_at,
            group,
            api_access,
        });
    }

    Ok(config::ConfigClientArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        delete: false,
        name,
        bearer_token_expires_at,
        group: None,
        api_access: vec![],
    })
}

fn resolve_rotate_secret_args(
    args: ConfigRotateSecretArgs,
) -> Result<config::ConfigRotateSecretArgs, CommandError> {
    let names = config::list_client_slugs(args.config.as_deref(), args.password.clone())
        .map_err(|error| CommandError::new(error.to_string()))?;
    let detail = config::format_existing_name_hint(config::ResourceKind::Client, &names, false);
    let name = resolve_name(
        Some(args.name),
        "Client name",
        detail.as_deref(),
        "config client rotate-secret requires --name in non-interactive sessions",
    )?;

    let existing =
        config::load_existing_client_state(args.config.as_deref(), args.password.clone(), &name)
            .map_err(|error| CommandError::new(error.to_string()))?;
    let bearer_token_expires_at = if args.bearer_token_expires_at.is_some() {
        args.bearer_token_expires_at
    } else if interactive_questionnaire_available() {
        Some(prompt_required(
            "Bearer token expires at",
            existing
                .as_ref()
                .map(|state| state.bearer_token_expires_at.as_str()),
            None,
            "config client rotate-secret requires --bearer-token-expires-at in non-interactive sessions",
        )?)
    } else {
        None
    };

    Ok(config::ConfigRotateSecretArgs {
        config: args.config,
        password: args.password,
        log_level: args.log_level,
        name,
        bearer_token_expires_at,
    })
}

fn resolve_name(
    value: Option<String>,
    label: &str,
    detail: Option<&str>,
    non_interactive_message: &str,
) -> Result<String, CommandError> {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        return Ok(value);
    }

    config::prompt_required_text(
        &config::prompt_message(label, detail, None, None, None, None),
        None,
        non_interactive_message,
    )
    .map_err(|error| CommandError::new(error.to_string()))
}

fn prompt_required(
    label: &str,
    default: Option<&str>,
    example: Option<&str>,
    non_interactive_message: &str,
) -> Result<String, CommandError> {
    config::prompt_required_text(
        &config::prompt_message(label, None, default, example, None, None),
        default,
        non_interactive_message,
    )
    .map_err(|error| CommandError::new(error.to_string()))
}

fn confirm_delete(resource_kind: config::ResourceKind, name: &str) -> Result<(), CommandError> {
    if !interactive_questionnaire_available() {
        return Ok(());
    }

    let confirmed = config::prompt_yes_no(
        &format!(
            "Delete {} '{}'? This cannot be undone",
            resource_kind.label(),
            name
        ),
        false,
        &format!(
            "config {} --delete requires explicit --name in non-interactive sessions",
            resource_kind.label()
        ),
    )
    .map_err(|error| CommandError::new(error.to_string()))?;

    if !confirmed {
        return Err(CommandError::new("Delete cancelled"));
    }

    Ok(())
}

fn render_api_access_map(map: &config::ExistingGroupState) -> String {
    render_access_map(&map.api_access)
}

fn render_client_api_access_map(map: &config::ExistingClientPromptState) -> String {
    render_access_map(&map.api_access)
}

fn render_access_map(map: &std::collections::BTreeMap<String, AccessLevel>) -> String {
    map.iter()
        .map(|(api, level)| {
            format!(
                "{api}={}",
                match level {
                    AccessLevel::Read => "read",
                    AccessLevel::Write => "write",
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn interactive_questionnaire_available() -> bool {
    std::env::var_os("GATE_AGENT_TEST_PROMPT_INPUTS").is_some()
        || (!config::interactive_prompts_disabled()
            && std::io::stdin().is_terminal()
            && std::io::stderr().is_terminal())
}
