use std::io::{self, IsTerminal, Read};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

use crate::cli::StartArgs;

use super::password::PasswordArgs;
use super::path::{LOCAL_CONFIG_FILE, resolve_config_path};
use super::secrets::SecretsConfig;
use super::{ConfigError, ConfigSource};

pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
pub const DEFAULT_CONFIG_FILE: &str = LOCAL_CONFIG_FILE;
pub const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(Clone, Debug)]
pub struct AppConfig {
    bind: SocketAddr,
    log_level: String,
    config_source: ConfigSource,
    secrets: SecretsConfig,
}

#[derive(Clone, Debug)]
pub struct StartConfigStdin {
    is_terminal: bool,
    bytes: Vec<u8>,
}

impl StartConfigStdin {
    pub fn terminal() -> Self {
        Self {
            is_terminal: true,
            bytes: Vec::new(),
        }
    }

    pub fn piped(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            is_terminal: false,
            bytes: bytes.into(),
        }
    }

    fn from_process() -> Result<Self, ConfigError> {
        let mut stdin = io::stdin();

        if stdin.is_terminal() {
            return Ok(Self::terminal());
        }

        let bytes = read_available_stdin(&mut stdin)?;

        Ok(Self::piped(bytes))
    }

    fn into_non_empty_text(self) -> Result<Option<String>, ConfigError> {
        if self.is_terminal {
            return Ok(None);
        }

        if !self.bytes.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Ok(None);
        }

        String::from_utf8(self.bytes)
            .map(Some)
            .map_err(|error| ConfigError::new(format!("failed to read config from stdin: {error}")))
    }
}

fn stdin_read_error(error: impl std::fmt::Display) -> ConfigError {
    ConfigError::new(format!("failed to read config from stdin: {error}"))
}

#[cfg(unix)]
fn read_available_stdin<R>(reader: &mut R) -> Result<Vec<u8>, ConfigError>
where
    R: Read + AsRawFd,
{
    let fd = reader.as_raw_fd();
    let _guard = NonBlockingFdGuard::enter(fd)?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if bytes.is_empty() {
                    break;
                }

                wait_for_stdin_readable(fd)?;
            }
            Err(error) => return Err(stdin_read_error(error)),
        }
    }

    Ok(bytes)
}

#[cfg(unix)]
fn wait_for_stdin_readable(fd: RawFd) -> Result<(), ConfigError> {
    let mut poll_fd = libc::pollfd {
        fd,
        events: (libc::POLLIN | libc::POLLHUP),
        revents: 0,
    };

    loop {
        let result = unsafe { libc::poll(&mut poll_fd, 1, -1) };

        if result > 0 {
            return Ok(());
        }

        if result == 0 {
            continue;
        }

        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }

        return Err(stdin_read_error(error));
    }
}

#[cfg(not(unix))]
fn read_available_stdin<R>(reader: &mut R) -> Result<Vec<u8>, ConfigError>
where
    R: Read,
{
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(stdin_read_error)?;
    Ok(bytes)
}

#[cfg(unix)]
struct NonBlockingFdGuard {
    fd: RawFd,
    original_flags: i32,
}

#[cfg(unix)]
impl NonBlockingFdGuard {
    fn enter(fd: RawFd) -> Result<Self, ConfigError> {
        let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if original_flags < 0 {
            return Err(stdin_read_error(io::Error::last_os_error()));
        }

        if unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0 {
            return Err(stdin_read_error(io::Error::last_os_error()));
        }

        Ok(Self { fd, original_flags })
    }
}

#[cfg(unix)]
impl Drop for NonBlockingFdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(self.fd, libc::F_SETFL, self.original_flags);
        }
    }
}

impl AppConfig {
    pub fn new(
        bind: SocketAddr,
        log_level: impl Into<String>,
        config_source: ConfigSource,
        secrets: SecretsConfig,
    ) -> Self {
        Self {
            bind,
            log_level: log_level.into(),
            config_source,
            secrets,
        }
    }

    pub fn config_source(&self) -> &ConfigSource {
        &self.config_source
    }

    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub fn log_level(&self) -> &str {
        &self.log_level
    }

    pub fn secrets(&self) -> &SecretsConfig {
        &self.secrets
    }

    pub fn config_path(&self) -> Option<&Path> {
        match self.config_source() {
            ConfigSource::Path(path) => Some(path.as_path()),
            ConfigSource::Stdin => None,
        }
    }

    pub fn from_start_args(args: &StartArgs) -> Result<Self, ConfigError> {
        let stdin = StartConfigStdin::from_process()?;

        Self::from_start_args_with_stdin(args, stdin)
    }

    pub fn from_start_args_with_stdin(
        args: &StartArgs,
        stdin: StartConfigStdin,
    ) -> Result<Self, ConfigError> {
        let log_level = args.log_level.trim();

        if log_level.is_empty() {
            return Err(ConfigError::new("log level cannot be empty"));
        }

        let (config_source, secrets) = match stdin.into_non_empty_text()? {
            Some(contents) => (
                ConfigSource::Stdin,
                SecretsConfig::parse(&contents, "stdin")?,
            ),
            None => {
                let config_path = resolve_config_path(args.config.as_deref())?.path;
                let secrets = SecretsConfig::load_from_file_with_password_args(
                    &config_path,
                    &PasswordArgs {
                        password: args.password.clone(),
                    },
                )?;

                (ConfigSource::Path(config_path), secrets)
            }
        };

        Ok(Self::new(
            args.bind,
            log_level.to_owned(),
            config_source,
            secrets,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    #[cfg(unix)]
    use std::{thread, time::Duration};

    #[cfg(unix)]
    #[test]
    fn nonblocking_stdin_reader_returns_empty_when_stream_has_no_ready_bytes() {
        let (mut reader, _writer) = UnixStream::pair().expect("unix stream pair");

        let bytes = read_available_stdin(&mut reader).expect("nonblocking stdin read");

        assert!(bytes.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_stdin_reader_collects_chunked_bytes_until_eof() {
        let (mut reader, mut writer) = UnixStream::pair().expect("unix stream pair");
        writer
            .write_all(b"[auth]\nissuer = \"stdin\"\n")
            .expect("write stdin bytes");
        let writer_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            writer
                .write_all(b"audience = \"stdin-clients\"\n")
                .expect("write trailing stdin bytes");
        });

        let bytes = read_available_stdin(&mut reader).expect("nonblocking stdin read");
        writer_thread.join().expect("writer thread should finish");

        assert_eq!(
            String::from_utf8(bytes).expect("utf-8"),
            "[auth]\nissuer = \"stdin\"\naudience = \"stdin-clients\"\n"
        );
    }
}
