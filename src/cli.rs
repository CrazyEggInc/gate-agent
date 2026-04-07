use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands;
use crate::config::app_config::{DEFAULT_BIND, DEFAULT_LOG_LEVEL, DEFAULT_SECRETS_FILE};

#[derive(Debug, Parser)]
#[command(name = "gate-agent")]
#[command(about = "Local Rust CLI for the gate-agent MVP")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Start(StartArgs),
    #[command(name = "curl-payload")]
    CurlPayload(CurlPayloadArgs),
}

#[derive(Clone, Debug, clap::Args)]
pub struct StartArgs {
    #[arg(long, default_value = DEFAULT_BIND)]
    pub bind: SocketAddr,

    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    pub secrets_file: PathBuf,

    #[arg(long, default_value = DEFAULT_LOG_LEVEL)]
    pub log_level: String,
}

#[derive(Clone, Debug, clap::Args)]
pub struct CurlPayloadArgs {
    #[arg(long, default_value = DEFAULT_BIND)]
    pub bind: SocketAddr,

    #[arg(long, default_value = DEFAULT_SECRETS_FILE)]
    pub secrets_file: PathBuf,

    #[arg(long)]
    pub api: String,

    #[arg(long)]
    pub path: String,
}

pub fn run() -> Result<(), commands::CommandError> {
    let cli = Cli::parse();
    commands::run(cli.command)
}
