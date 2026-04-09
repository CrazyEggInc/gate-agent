use std::error::Error;
use std::fmt::{Display, Formatter};

pub mod app_config;
pub mod path;
pub mod secrets;
pub mod write;

#[derive(Debug)]
pub struct ConfigError {
    message: String,
}

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ConfigError {}
