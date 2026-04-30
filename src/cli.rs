use std::cell::Cell;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{
    ArgGroup, Args, Command as ClapCommand, FromArgMatches, Parser, Subcommand, parser::ValueSource,
};

use crate::commands;
use crate::config::app_config::DEFAULT_LOG_LEVEL;

#[derive(Debug, Parser)]
#[command(name = "gate-agent")]
#[command(about = "Local proxy for authenticated upstream API access")]
#[command(disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

thread_local! {
    static CONFIG_INIT_ENCRYPTED_EXPLICIT: Cell<bool> = const { Cell::new(false) };
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Start the local proxy server")]
    Start(StartArgs),
    #[command(name = "config")]
    #[command(about = "Create or update config entries")]
    Config(ConfigArgs),
    #[command(about = "Print build version")]
    Version,
}

#[derive(Clone, Debug, Args)]
pub struct StartArgs {
    #[arg(
        long,
        help = "Bind address for the local listener as host:port (example: 0.0.0.0:8787)"
    )]
    pub bind: Option<SocketAddr>,

    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(
        long,
        default_value = DEFAULT_LOG_LEVEL,
        help = "Log level for server output: warn, info, or debug"
    )]
    pub log_level: String,
}

#[derive(Clone, Debug, Args)]
#[command(disable_help_subcommand = true)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum ConfigCommand {
    #[command(about = "Create a new config file")]
    Init(ConfigInitArgs),
    #[command(about = "Validate config from stdin or file")]
    Validate(ConfigValidateArgs),
    #[command(about = "Print the current config contents")]
    Show(ConfigShowArgs),
    #[command(about = "Open the config in your editor")]
    Edit(ConfigEditArgs),
    #[command(about = "Add, update, or delete an upstream API entry")]
    Api(ConfigApiArgs),
    #[command(about = "Add, update, or delete a group entry")]
    Group(ConfigGroupArgs),
    #[command(about = "Add, update, or delete a client entry")]
    Client(ConfigClientArgs),
}

#[derive(Clone, Debug)]
pub struct ConfigInitArgs {
    pub config: Option<PathBuf>,

    pub encrypted: bool,

    pub password: Option<String>,

    pub log_level: String,
}

#[derive(Clone, Debug, Args)]
struct ConfigInitArgsRaw {
    #[arg(long, help = "Path to the config file")]
    config: Option<PathBuf>,

    #[arg(long, help = "Write the new config encrypted at rest")]
    encrypted: bool,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    log_level: String,
}

impl From<ConfigInitArgsRaw> for ConfigInitArgs {
    fn from(value: ConfigInitArgsRaw) -> Self {
        Self {
            config: value.config,
            encrypted: value.encrypted,
            password: value.password,
            log_level: value.log_level,
        }
    }
}

impl FromArgMatches for ConfigInitArgs {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        CONFIG_INIT_ENCRYPTED_EXPLICIT.with(|flag| {
            flag.set(matches.value_source("encrypted") == Some(ValueSource::CommandLine))
        });

        ConfigInitArgsRaw::from_arg_matches(matches).map(Into::into)
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        CONFIG_INIT_ENCRYPTED_EXPLICIT.with(|flag| {
            flag.set(matches.value_source("encrypted") == Some(ValueSource::CommandLine))
        });

        let updated = ConfigInitArgsRaw::from_arg_matches(matches)?;
        *self = updated.into();

        Ok(())
    }
}

impl Args for ConfigInitArgs {
    fn augment_args(cmd: ClapCommand) -> ClapCommand {
        ConfigInitArgsRaw::augment_args(cmd)
    }

    fn augment_args_for_update(cmd: ClapCommand) -> ClapCommand {
        ConfigInitArgsRaw::augment_args_for_update(cmd)
    }
}

impl ConfigInitArgs {
    pub fn encrypted_was_explicitly_set(&self) -> bool {
        CONFIG_INIT_ENCRYPTED_EXPLICIT.with(Cell::get)
    }
}

#[derive(Clone, Debug, Args)]
pub struct ConfigShowArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,
}

#[derive(Clone, Debug, Args)]
pub struct ConfigEditArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,
}

#[derive(Clone, Debug, Args)]
pub struct ConfigValidateArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,
}

#[derive(Clone, Debug, Args)]
pub struct ConfigApiArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(
        short = 'd',
        long,
        help = "Delete existing api instead of add-or-update"
    )]
    pub delete: bool,

    #[arg(long, help = "API slug to add, update, or delete")]
    pub name: Option<String>,

    #[arg(long, help = "Base URL for the upstream API")]
    pub base_url: Option<String>,

    #[arg(long, help = "Configure upstream HTTP Basic auth interactively")]
    pub basic_auth: bool,

    #[arg(
        long,
        help = "Upstream headers as name=value pairs (example: x-api-key=secret). Repeat flag to add multiple upstream headers"
    )]
    pub header: Vec<String>,

    #[arg(long, help = "Upstream timeout in milliseconds")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Args)]
#[command(group(
    ArgGroup::new("client_access")
        .multiple(false)
        .args(["group", "api_access"])
))]
pub struct ConfigClientArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(
        short = 'd',
        long,
        help = "Delete existing client instead of add-or-update"
    )]
    pub delete: bool,

    #[arg(long, help = "Client name to add, update, or delete")]
    pub name: Option<String>,

    #[arg(
        long = "bearer-token-expires-at",
        help = "Bearer token expiry date-only as YYYY-MM-DD (example: 2026-01-01)"
    )]
    pub bearer_token_expires_at: Option<String>,

    #[arg(long, help = "Group slug to assign to the client")]
    pub group: Option<String>,

    #[arg(
        long = "api-access",
        help = "API route rule as api:method:path (example: projects:get:*); method is HTTP verb or *; path supports * wildcards. Repeat flag or comma-separate rules"
    )]
    pub api_access: Vec<String>,

    #[command(subcommand)]
    pub command: Option<ConfigClientSubcommand>,
}

#[derive(Clone, Debug)]
pub struct ConfigRotateSecretArgs {
    pub config: Option<PathBuf>,

    pub password: Option<String>,

    pub log_level: String,

    #[doc(hidden)]
    pub log_level_explicitly_set: bool,

    pub name: String,

    pub bearer_token_expires_at: Option<String>,
}

#[derive(Clone, Debug, Args)]
struct ConfigRotateSecretArgsRaw {
    #[arg(long, help = "Path to the config file")]
    config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    log_level: String,

    #[arg(
        long,
        default_value = "",
        hide_default_value = true,
        help = "Client name to rotate"
    )]
    name: String,

    #[arg(
        long = "bearer-token-expires-at",
        help = "Replacement bearer token expiry date-only as YYYY-MM-DD (example: 2026-01-01)"
    )]
    bearer_token_expires_at: Option<String>,
}

impl From<ConfigRotateSecretArgsRaw> for ConfigRotateSecretArgs {
    fn from(value: ConfigRotateSecretArgsRaw) -> Self {
        Self {
            config: value.config,
            password: value.password,
            log_level: value.log_level,
            log_level_explicitly_set: false,
            name: value.name,
            bearer_token_expires_at: value.bearer_token_expires_at,
        }
    }
}

impl FromArgMatches for ConfigRotateSecretArgs {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let log_level_explicitly_set =
            matches.value_source("log_level") == Some(ValueSource::CommandLine);
        let mut args: Self = ConfigRotateSecretArgsRaw::from_arg_matches(matches)?.into();
        args.log_level_explicitly_set = log_level_explicitly_set;

        Ok(args)
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        let updated = ConfigRotateSecretArgsRaw::from_arg_matches(matches)?;
        *self = updated.into();
        self.log_level_explicitly_set =
            matches.value_source("log_level") == Some(ValueSource::CommandLine);

        Ok(())
    }
}

impl Args for ConfigRotateSecretArgs {
    fn augment_args(cmd: ClapCommand) -> ClapCommand {
        ConfigRotateSecretArgsRaw::augment_args(cmd)
    }

    fn augment_args_for_update(cmd: ClapCommand) -> ClapCommand {
        ConfigRotateSecretArgsRaw::augment_args_for_update(cmd)
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum ConfigClientSubcommand {
    #[command(
        name = "rotate-secret",
        about = "Rotate an existing client bearer token"
    )]
    RotateSecret(ConfigRotateSecretArgs),
}

#[derive(Clone, Debug, Args)]
pub struct ConfigGroupArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(
        short = 'd',
        long,
        help = "Delete existing group instead of add-or-update"
    )]
    pub delete: bool,

    #[arg(long, help = "Group name to add, update, or delete")]
    pub name: Option<String>,

    #[arg(
        long = "api-access",
        help = "API route rule as api:method:path (example: projects:get:*); method is HTTP verb or *; path supports * wildcards. Repeat flag or comma-separate rules"
    )]
    pub api_access: Vec<String>,
}

pub fn run() -> Result<(), commands::CommandError> {
    let cli = Cli::parse();
    commands::run(cli.command)
}

impl Cli {
    pub fn command(&self) -> &Command {
        &self.command
    }
}

impl ConfigRotateSecretArgs {
    pub fn log_level_was_explicitly_set(&self) -> bool {
        self.log_level_explicitly_set
    }
}

impl ConfigClientArgs {
    pub fn effective_log_level(&self) -> &str {
        match &self.command {
            Some(ConfigClientSubcommand::RotateSecret(args))
                if args.log_level_was_explicitly_set() =>
            {
                &args.log_level
            }
            _ => &self.log_level,
        }
    }
}

impl Command {
    pub fn log_level(&self) -> Option<&str> {
        match self {
            Self::Start(args) => Some(&args.log_level),
            Self::Config(args) => match &args.command {
                ConfigCommand::Init(args) => Some(&args.log_level),
                ConfigCommand::Validate(args) => Some(&args.log_level),
                ConfigCommand::Show(args) => Some(&args.log_level),
                ConfigCommand::Edit(args) => Some(&args.log_level),
                ConfigCommand::Api(args) => Some(&args.log_level),
                ConfigCommand::Group(args) => Some(&args.log_level),
                ConfigCommand::Client(args) => Some(args.effective_log_level()),
            },
            Self::Version => None,
        }
    }
}
