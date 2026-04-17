use std::io::Write;

use super::CommandError;

pub fn write_version(mut writer: impl Write) -> Result<(), CommandError> {
    writeln!(writer, "{}", env!("CARGO_PKG_VERSION"))
        .map_err(|error| CommandError::new(format!("failed to write version: {error}")))
}

pub fn run() -> Result<(), CommandError> {
    let mut stdout = std::io::stdout().lock();
    write_version(&mut stdout)
}
