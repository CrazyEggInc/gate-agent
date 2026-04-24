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
            headers: None,
            auth: config::ConfigApiAuthSelection::Preserve,
            timeout_ms: None,
        });
    }

    let existing =
        config::load_existing_api_state(args.config.as_deref(), args.password.clone(), &name)
            .map_err(|error| CommandError::new(error.to_string()))?;
    let interactive = interactive_questionnaire_available();

    let base_url = if args.base_url.is_some() {
        args.base_url
    } else if interactive {
        Some(prompt_required(
            "Base URL",
            existing.as_ref().map(|state| state.base_url.as_str()),
            Some("https://projects.internal.example/api"),
            "config api requires --base-url in non-interactive sessions",
        )?)
    } else {
        None
    };

    let header_default_auth = if args.basic_auth {
        config::ConfigApiAuthSelection::None
    } else {
        config::ConfigApiAuthSelection::Preserve
    };
    let header_default = existing
        .as_ref()
        .map(|state| render_api_headers_for_prompt(state, &header_default_auth))
        .filter(|value| !value.is_empty());

    let headers_from_cli = !args.header.is_empty();
    let mut headers = if headers_from_cli {
        Some(
            args.header
                .into_iter()
                .filter_map(optional_non_empty)
                .collect::<Vec<_>>(),
        )
    } else if interactive {
        match config::prompt_optional_text(
            &header_prompt_message(header_default.as_deref()),
            header_default.as_deref(),
            "config api accepts optional --header",
        )
        .map_err(|error| CommandError::new(error.to_string()))?
        {
            Some(prompted_headers) if prompted_headers.eq_ignore_ascii_case("none") => Some(vec![]),
            Some(prompted_headers) => Some(split_optional_header_segments(&prompted_headers)),
            None => None,
        }
    } else {
        None
    };

    let resolved_auth = if args.basic_auth {
        prompt_basic_auth(existing.as_ref())?
    } else if interactive {
        resolve_prompted_api_auth(existing.as_ref(), headers.as_ref())?
    } else {
        config::ConfigApiAuthSelection::Preserve
    };

    if matches!(resolved_auth, config::ConfigApiAuthSelection::Basic { .. }) && !headers_from_cli {
        strip_authorization_header_entries(&mut headers);
    }

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
        headers,
        auth: resolved_auth,
        timeout_ms,
    })
}

fn resolve_prompted_api_auth(
    existing: Option<&config::ExistingApiState>,
    headers: Option<&Vec<String>>,
) -> Result<config::ConfigApiAuthSelection, CommandError> {
    let configure_basic_auth = config::prompt_yes_no(
        &config::prompt_message(
            "Configure basic auth?",
            None,
            None,
            None,
            None,
            existing
                .and_then(|state| state.basic_auth.as_ref())
                .map(|_| "blank keeps current basic auth")
                .or(Some("blank skips basic auth")),
        ),
        existing.is_some_and(|state| state.basic_auth.is_some()),
        "config api requires interactive prompts to resolve basic auth",
    )
    .map_err(|error| CommandError::new(error.to_string()))?;

    if configure_basic_auth {
        return prompt_basic_auth(existing);
    }

    if headers_contain_authorization(headers) {
        return Ok(config::ConfigApiAuthSelection::Header);
    }

    if existing.is_some_and(|state| state.basic_auth.is_some()) {
        return Ok(config::ConfigApiAuthSelection::None);
    }

    Ok(config::ConfigApiAuthSelection::Preserve)
}

fn prompt_basic_auth(
    existing: Option<&config::ExistingApiState>,
) -> Result<config::ConfigApiAuthSelection, CommandError> {
    let existing_basic_auth = existing.and_then(|state| state.basic_auth.as_ref());
    let username = config::prompt_required_text(
        &config::prompt_message(
            "Basic auth username",
            None,
            existing_basic_auth.map(|state| state.username.as_str()),
            None,
            None,
            None,
        ),
        existing_basic_auth.map(|state| state.username.as_str()),
        "config api --basic-auth requires interactive username prompt",
    )
    .map_err(|error| CommandError::new(error.to_string()))?;
    let password = config::prompt_optional_text(
        &config::prompt_message(
            "Basic auth password",
            None,
            None,
            None,
            None,
            existing_basic_auth
                .map(|_| "blank clears existing password; enter password to keep or change")
                .or(Some(
                    "blank stores empty password; enter 'none' for username-only basic auth",
                )),
        ),
        None,
        "config api --basic-auth requires interactive password prompt",
    )
    .map_err(|error| CommandError::new(error.to_string()))?;

    let password = match (password, existing_basic_auth) {
        (Some(password), _) if password.eq_ignore_ascii_case("none") => None,
        (Some(password), _) => Some(password),
        (None, Some(_)) => None,
        (None, None) => Some(String::new()),
    };

    Ok(config::ConfigApiAuthSelection::Basic { username, password })
}

fn headers_contain_authorization(headers: Option<&Vec<String>>) -> bool {
    headers.is_some_and(|headers| {
        headers.iter().any(|header| {
            header
                .split_once('=')
                .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("authorization"))
        })
    })
}

fn strip_authorization_header_entries(headers: &mut Option<Vec<String>>) {
    if let Some(headers) = headers {
        headers.retain(|header| {
            header
                .split_once('=')
                .is_none_or(|(name, _)| !name.trim().eq_ignore_ascii_case("authorization"))
        });
    }
}

fn header_prompt_message(default: Option<&str>) -> String {
    config::prompt_message(
        "Headers",
        None,
        default,
        Some("x-api-key=secret"),
        None,
        Some(match default {
            Some(_) => "leave empty to keep current headers; enter 'none' to clear",
            None => "leave empty for no headers",
        }),
    )
}

fn render_api_headers_for_prompt(
    state: &config::ExistingApiState,
    auth: &config::ConfigApiAuthSelection,
) -> String {
    let mut headers = state.headers.clone();

    match auth {
        config::ConfigApiAuthSelection::None | config::ConfigApiAuthSelection::Basic { .. } => {
            headers.retain(|name, _| !name.eq_ignore_ascii_case("authorization"));
        }
        config::ConfigApiAuthSelection::Preserve | config::ConfigApiAuthSelection::Header => {}
    }

    render_headers_map(&headers)
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

fn render_headers_map(map: &std::collections::BTreeMap<String, String>) -> String {
    map.iter()
        .map(|(name, value)| format!("{name}={}", escape_header_prompt_value(value)))
        .collect::<Vec<_>>()
        .join(",")
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

fn split_optional_header_segments(value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut escape = false;

    for character in value.chars() {
        if escape {
            match character {
                ',' | '\\' => current.push(character),
                _ => {
                    current.push('\\');
                    current.push(character);
                }
            }
            escape = false;
            continue;
        }

        match character {
            '\\' => escape = true,
            ',' => {
                segments.push(std::mem::take(&mut current));
            }
            _ => current.push(character),
        }
    }

    if escape {
        current.push('\\');
    }

    segments.push(current);

    segments
        .into_iter()
        .filter_map(optional_non_empty)
        .collect()
}

fn escape_header_prompt_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace(',', "\\,")
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
        || (!config::interactive_prompts_disabled()
            && std::io::stdin().is_terminal()
            && std::io::stderr().is_terminal())
}
