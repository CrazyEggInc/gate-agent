use std::cell::Cell;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{
    ArgGroup, Args, Command as ClapCommand, FromArgMatches, Parser, Subcommand, parser::ValueSource,
};

use crate::commands;
use crate::config::app_config::DEFAULT_LOG_LEVEL;
use crate::config::secrets::DEFAULT_API_TIMEOUT_MS;

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
    #[arg(long, help = "Bind address for the local listener")]
    pub bind: Option<SocketAddr>,

    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for server output")]
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
    #[command(name = "add-api")]
    #[command(about = "Add an upstream API entry")]
    AddApi(ConfigAddApiArgs),
    #[command(name = "add-group")]
    #[command(about = "Add a group entry")]
    AddGroup(ConfigAddGroupArgs),
    #[command(name = "add-client")]
    #[command(about = "Add a client entry")]
    AddClient(ConfigAddClientArgs),
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
pub struct ConfigAddApiArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(
        long,
        default_value = "",
        hide_default_value = true,
        help = "API slug to create"
    )]
    pub name: String,

    #[arg(
        long,
        default_value = "",
        hide_default_value = true,
        help = "Base URL for the upstream API"
    )]
    pub base_url: String,

    #[arg(
        long,
        default_value = "",
        hide_default_value = true,
        help = "Header name sent upstream"
    )]
    pub auth_header: String,

    #[arg(
        long,
        default_value = "",
        hide_default_value = true,
        help = "Secret or token sent upstream"
    )]
    pub auth_value: String,

    #[arg(long, default_value_t = DEFAULT_API_TIMEOUT_MS, help = "Upstream timeout in milliseconds")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Args)]
#[command(group(
    ArgGroup::new("client_access")
        .multiple(false)
        .args(["group", "api_access"])
))]
pub struct ConfigAddClientArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(
        long,
        default_value = "",
        hide_default_value = true,
        help = "Client name to create"
    )]
    pub name: String,

    #[arg(
        long = "bearer-token-expires-at",
        help = "Bearer token expiry timestamp"
    )]
    pub bearer_token_expires_at: Option<String>,

    #[arg(long, help = "Group slug to assign to the client")]
    pub group: Option<String>,

    #[arg(
        long = "api-access",
        help = "Inline API access entries as api=level pairs; levels: read, write. Repeat the flag or comma-separate pairs"
    )]
    pub api_access: Vec<String>,
}

#[derive(Clone, Debug, Args)]
pub struct ConfigAddGroupArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(short = 'p', long, help = "Password for encrypted config files")]
    pub password: Option<String>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(
        long,
        default_value = "",
        hide_default_value = true,
        help = "Group name to create"
    )]
    pub name: String,

    #[arg(
        long = "api-access",
        help = "Inline API access entries as api=level pairs; levels: read, write. Repeat the flag or comma-separate pairs"
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

impl Command {
    pub fn log_level(&self) -> Option<&str> {
        match self {
            Self::Start(args) => Some(&args.log_level),
            Self::Config(args) => match &args.command {
                ConfigCommand::Init(args) => Some(&args.log_level),
                ConfigCommand::Validate(args) => Some(&args.log_level),
                ConfigCommand::Show(args) => Some(&args.log_level),
                ConfigCommand::Edit(args) => Some(&args.log_level),
                ConfigCommand::AddApi(args) => Some(&args.log_level),
                ConfigCommand::AddGroup(args) => Some(&args.log_level),
                ConfigCommand::AddClient(args) => Some(&args.log_level),
            },
            Self::Version => None,
        }
    }
}
