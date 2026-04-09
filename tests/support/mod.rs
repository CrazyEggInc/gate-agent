#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
};
use gate_agent::{
    auth::{
        claims::JwtClaims,
        jwt::{sign_local_test_token_for_client_with_access_at, sign_local_test_token_with_access},
    },
    config::{ConfigSource, app_config::AppConfig, secrets::SecretsConfig},
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Mutex, oneshot},
};

#[derive(Debug)]
pub struct CapturedRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: http::HeaderMap,
    pub body: bytes::Bytes,
}

pub type CaptureSender = Arc<Mutex<Option<oneshot::Sender<CapturedRequest>>>>;

pub struct ChunkedUpstream {
    pub base_url: String,
    pub captured_request: oneshot::Receiver<String>,
}

pub fn capture_channel() -> (CaptureSender, oneshot::Receiver<CapturedRequest>) {
    let (tx, rx) = oneshot::channel();
    (Arc::new(Mutex::new(Some(tx))), rx)
}

pub async fn capture_request(
    State(sender): State<CaptureSender>,
    request: Request<Body>,
) -> StatusCode {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .expect("collect upstream body")
        .to_bytes();

    if let Some(tx) = sender.lock().await.take() {
        tx.send(CapturedRequest {
            method: parts.method.to_string(),
            path_and_query: parts
                .uri
                .path_and_query()
                .map(|value| value.as_str().to_owned())
                .unwrap_or_else(|| parts.uri.path().to_owned()),
            headers: parts.headers,
            body,
        })
        .expect("send captured request");
    }

    StatusCode::OK
}

pub fn load_test_config(base_url: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    load_test_config_with_billing_timeout(base_url, 5_000)
}

pub fn load_multi_api_test_config(base_url: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_secrets_file(&format!(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "replace-me"

[clients.default]
api_key = "default-client-key"
api_key_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ projects = "write", billing = "write" }}

[clients.partner]
api_key = "partner-client-key"
api_key_expires_at = "2030-01-03T03:04:05Z"
api_access = {{ projects = "write" }}

[apis.projects]
base_url = "{base_url}"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000

[apis.billing]
base_url = "{base_url}/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = 5000
"#
    ))?;

    Ok(AppConfig::new(
        "127.0.0.1:0".parse()?,
        "debug",
        ConfigSource::Path(config_file.clone()),
        SecretsConfig::load_from_file(&config_file)?,
    ))
}

pub fn load_test_config_with_billing_timeout(
    base_url: &str,
    billing_timeout_ms: u64,
) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_secrets_file(&format!(
        r#"
[auth]
issuer = "gate-agent-dev"
audience = "gate-agent-clients"
signing_secret = "replace-me"

[clients.default]
api_key = "default-client-key"
api_key_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ billing = "write" }}

[clients.partner]
api_key = "partner-client-key"
api_key_expires_at = "2030-01-03T03:04:05Z"
api_access = {{ projects = "write" }}

[apis.projects]
base_url = "{base_url}"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000

[apis.billing]
base_url = "{base_url}/api"
auth_header = "authorization"
auth_scheme = "Bearer"
auth_value = "billing-secret-token"
timeout_ms = {billing_timeout_ms}
"#
    ))?;

    Ok(AppConfig::new(
        "127.0.0.1:0".parse()?,
        "debug",
        ConfigSource::Path(config_file.clone()),
        SecretsConfig::load_from_file(&config_file)?,
    ))
}

pub fn signed_token(
    api: &str,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    signed_token_with_access(api, gate_agent::auth::AccessLevel::Write, secrets)
}

pub fn signed_token_with_access(
    api: &str,
    access: gate_agent::auth::AccessLevel,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sign_local_test_token_with_access(api, access, secrets)?)
}

pub fn signed_token_for_client(
    client_slug: &str,
    api: &str,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    signed_token_for_client_with_access(
        client_slug,
        api,
        gate_agent::auth::AccessLevel::Write,
        secrets,
    )
}

pub fn signed_token_for_client_with_access(
    client_slug: &str,
    api: &str,
    access: gate_agent::auth::AccessLevel,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(sign_local_test_token_for_client_with_access_at(
        client_slug,
        api,
        access,
        secrets,
        issued_at,
        600,
    )?)
}

pub fn signed_token_with_subject_and_secret(
    subject_client_slug: &str,
    api: &str,
    signing_secret: &str,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = JwtClaims::new(
        subject_client_slug.to_owned(),
        [(api.to_owned(), gate_agent::auth::AccessLevel::Write)],
        secrets.auth.issuer.clone(),
        secrets.auth.audience.clone(),
        issued_at,
        issued_at + 600,
    )?;

    Ok(encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(signing_secret.as_bytes()),
    )?)
}

pub async fn spawn_chunked_upstream(
    status: &str,
    headers: &[(&str, &str)],
    body_chunks: &[&[u8]],
) -> Result<ChunkedUpstream, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (tx, rx) = oneshot::channel();
    let status = status.to_owned();
    let headers = headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect::<Vec<_>>();
    let body_chunks = body_chunks
        .iter()
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept upstream connection");
        let request = read_http_request(&mut stream)
            .await
            .expect("read upstream request");
        tx.send(String::from_utf8_lossy(&request).into_owned())
            .expect("send raw upstream request");

        let mut response =
            format!("HTTP/1.1 {status}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n");

        for (name, value) in headers {
            response.push_str(&format!("{name}: {value}\r\n"));
        }

        response.push_str("\r\n");

        stream
            .write_all(response.as_bytes())
            .await
            .expect("write upstream response head");

        for chunk in body_chunks {
            stream
                .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                .await
                .expect("write upstream chunk size");
            stream
                .write_all(&chunk)
                .await
                .expect("write upstream chunk body");
            stream
                .write_all(b"\r\n")
                .await
                .expect("write upstream chunk terminator");
            stream.flush().await.expect("flush upstream chunk");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        stream
            .write_all(b"0\r\n\r\n")
            .await
            .expect("write upstream final chunk");
    });

    Ok(ChunkedUpstream {
        base_url: format!("http://{address}"),
        captured_request: rx,
    })
}

pub async fn spawn_upstream(app: Router) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("upstream server should run");
    });

    Ok(format!("http://{address}"))
}

fn write_secrets_file(
    contents: &str,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let secrets_file = temp_dir.path().join(".secrets");
    std::fs::write(&secrets_file, contents)?;
    Ok((temp_dir, secrets_file))
}

async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    let header_end = loop {
        let bytes_read = stream.read(&mut buffer).await?;

        if bytes_read == 0 {
            return Err("upstream client closed before request completed".into());
        }

        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let content_length = parse_content_length(&request[..header_end])?;

    while request.len() < header_end + content_length {
        let bytes_read = stream.read(&mut buffer).await?;

        if bytes_read == 0 {
            return Err("upstream client closed before body completed".into());
        }

        request.extend_from_slice(&buffer[..bytes_read]);
    }

    Ok(request)
}

fn parse_content_length(headers: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    let headers = String::from_utf8_lossy(headers);

    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return Ok(value.trim().parse()?);
            }
        }
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::parse_content_length;

    #[test]
    fn parse_content_length_matches_mixed_case_header_names() {
        let headers = b"GET / HTTP/1.1\r\nCoNtEnT-LeNgTh : 42\r\n\r\n";

        let content_length = parse_content_length(headers).expect("content length should parse");

        assert_eq!(content_length, 42);
    }
}
