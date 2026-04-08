use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::config::app_config::{DEFAULT_BIND, DEFAULT_LOG_LEVEL};

#[derive(Debug, Parser)]
#[command(name = "gate-agent")]
#[command(about = "Local proxy for authenticated upstream API access")]
#[command(disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Start the local proxy server")]
    Start(StartArgs),
    #[command(name = "curl")]
    #[command(about = "Print a curl command for the proxy")]
    Curl(CurlArgs),
    #[command(name = "config")]
    #[command(about = "Create or update config entries")]
    Config(ConfigArgs),
}

#[derive(Clone, Debug, Args)]
pub struct StartArgs {
    #[arg(long, default_value = DEFAULT_BIND, help = "Bind address for the local listener")]
    pub bind: SocketAddr,

    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for server output")]
    pub log_level: String,
}

#[derive(Clone, Debug, Args)]
pub struct CurlArgs {
    #[arg(long, default_value = DEFAULT_BIND, help = "Bind address of the local proxy")]
    pub bind: SocketAddr,

    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(
        long,
        default_value = "default",
        help = "Client slug to use for auth exchange; defaults to 'default'"
    )]
    pub client: String,

    #[arg(
        long,
        conflicts_with = "proxy",
        help = "Call the auth endpoint instead of /proxy"
    )]
    pub auth: bool,

    #[arg(long, conflicts_with = "auth", help = "Call the /proxy route")]
    pub proxy: bool,

    #[arg(long, help = "Use this JWT instead of generating one")]
    pub jwt: Option<String>,

    #[arg(long, help = "API slug to target")]
    pub api: Option<String>,

    #[arg(long, help = "Request path to append")]
    pub path: Option<String>,
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
    #[command(name = "add-api")]
    #[command(about = "Add an upstream API entry")]
    AddApi(ConfigAddApiArgs),
    #[command(name = "add-client")]
    #[command(about = "Add a client entry")]
    AddClient(ConfigAddClientArgs),
}

#[derive(Clone, Debug, Args)]
pub struct ConfigInitArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,
}

#[derive(Clone, Debug, Args)]
pub struct ConfigAddApiArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(long, help = "API slug to create")]
    pub name: String,

    #[arg(long, help = "Base URL for the upstream API")]
    pub base_url: String,

    #[arg(long, help = "Header name sent upstream")]
    pub auth_header: String,

    #[arg(long, help = "Optional auth scheme prefix")]
    pub auth_scheme: Option<String>,

    #[arg(long, help = "Secret or token sent upstream")]
    pub auth_value: String,

    #[arg(long, help = "Upstream timeout in milliseconds")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Args)]
pub struct ConfigAddClientArgs {
    #[arg(long, help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL, help = "Log level for command output")]
    pub log_level: String,

    #[arg(long, help = "Client name to create")]
    pub name: String,

    #[arg(long, help = "Shared API key for the client")]
    pub api_key: Option<String>,

    #[arg(long, help = "API key expiry timestamp")]
    pub api_key_expires_at: Option<String>,

    #[arg(long, help = "Allowed API slug; repeat for more")]
    pub allowed_api: Vec<String>,
}

pub fn run() -> Result<(), commands::CommandError> {
    let cli = Cli::parse();
    commands::run(cli.command)
}

impl Command {
    pub fn log_level(&self) -> &str {
        match self {
            Self::Start(args) => &args.log_level,
            Self::Curl(args) => &args.log_level,
            Self::Config(args) => match &args.command {
                ConfigCommand::Init(args) => &args.log_level,
                ConfigCommand::AddApi(args) => &args.log_level,
                ConfigCommand::AddClient(args) => &args.log_level,
            },
        }
    }
}
