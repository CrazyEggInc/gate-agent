use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::cli::{Command, StartArgs};
use crate::config::ConfigError;
use crate::config::app_config::AppConfig;
use crate::error::AppError;

pub mod curl_payload;
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
    match command {
        Command::Start(args) => run_start(args),
        Command::CurlPayload(args) => curl_payload::run(args),
    }
}

fn run_start(args: StartArgs) -> Result<(), CommandError> {
    let _ = AppConfig::from_start_args(&args)?;
    start::run(args)
}
