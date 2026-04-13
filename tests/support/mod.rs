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
use gate_agent::config::{
    ConfigSource,
    app_config::AppConfig,
    secrets::{AccessLevel, BearerTokenHash, SecretsConfig},
};
use http_body_util::BodyExt;
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
[clients.default]
bearer_token_id = "default-billing-write"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ projects = "write", billing = "write" }}

[clients.partner]
bearer_token_id = "partner-projects-write"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-03T03:04:05Z"
api_access = {{ projects = "write" }}

[clients.read-billing]
bearer_token_id = "read-billing"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-04T03:04:05Z"
api_access = {{ billing = "read" }}

[clients.read-projects]
bearer_token_id = "read-projects"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-05T03:04:05Z"
api_access = {{ projects = "read" }}

[clients.expired-billing]
bearer_token_id = "expired-billing"
bearer_token_hash = "{}"
bearer_token_expires_at = "2020-01-01T00:00:00Z"
api_access = {{ billing = "write" }}

[apis.projects]
base_url = "{base_url}"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000

[apis.billing]
base_url = "{base_url}/api"
auth_header = "authorization"
auth_value = "Bearer billing-secret-token"
timeout_ms = 5000
"#,
        BearerTokenHash::from_token("default-billing-write.default-billing-write-secret").as_str(),
        BearerTokenHash::from_token("partner-projects-write.partner-projects-write-secret")
            .as_str(),
        BearerTokenHash::from_token("read-billing.read-billing-secret").as_str(),
        BearerTokenHash::from_token("read-projects.read-projects-secret").as_str(),
        BearerTokenHash::from_token("expired-billing.expired-billing-secret").as_str(),
    ))?;

    Ok(AppConfig::new(
        "127.0.0.1:0".parse()?,
        "debug",
        ConfigSource::Path(config_file.clone()),
        SecretsConfig::load_from_file(&config_file)?,
    ))
}

pub fn load_multi_api_test_config_without_projects_auth_header(
    base_url: &str,
) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let (_temp_dir, config_file) = write_secrets_file(&format!(
        r#"
[clients.default]
bearer_token_id = "default-billing-write"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ projects = "write", billing = "write" }}

[clients.partner]
bearer_token_id = "partner-projects-write"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-03T03:04:05Z"
api_access = {{ projects = "write" }}

[clients.read-billing]
bearer_token_id = "read-billing"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-04T03:04:05Z"
api_access = {{ billing = "read" }}

[clients.read-projects]
bearer_token_id = "read-projects"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-05T03:04:05Z"
api_access = {{ projects = "read" }}

[clients.expired-billing]
bearer_token_id = "expired-billing"
bearer_token_hash = "{}"
bearer_token_expires_at = "2020-01-01T00:00:00Z"
api_access = {{ billing = "write" }}

[apis.projects]
base_url = "{base_url}"
timeout_ms = 5000

[apis.billing]
base_url = "{base_url}/api"
auth_header = "authorization"
auth_value = "Bearer billing-secret-token"
timeout_ms = 5000
"#,
        BearerTokenHash::from_token("default-billing-write.default-billing-write-secret").as_str(),
        BearerTokenHash::from_token("partner-projects-write.partner-projects-write-secret")
            .as_str(),
        BearerTokenHash::from_token("read-billing.read-billing-secret").as_str(),
        BearerTokenHash::from_token("read-projects.read-projects-secret").as_str(),
        BearerTokenHash::from_token("expired-billing.expired-billing-secret").as_str(),
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
[clients.default]
bearer_token_id = "default-billing-write"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-02T03:04:05Z"
api_access = {{ billing = "write" }}

[clients.partner]
bearer_token_id = "partner-projects-write"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-03T03:04:05Z"
api_access = {{ projects = "write" }}

[clients.read-billing]
bearer_token_id = "read-billing"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-04T03:04:05Z"
api_access = {{ billing = "read" }}

[clients.read-projects]
bearer_token_id = "read-projects"
bearer_token_hash = "{}"
bearer_token_expires_at = "2030-01-05T03:04:05Z"
api_access = {{ projects = "read" }}

[clients.expired-billing]
bearer_token_id = "expired-billing"
bearer_token_hash = "{}"
bearer_token_expires_at = "2020-01-01T00:00:00Z"
api_access = {{ billing = "write" }}

[apis.projects]
base_url = "{base_url}"
auth_header = "x-api-key"
auth_value = "projects-secret-value"
timeout_ms = 5000

[apis.billing]
base_url = "{base_url}/api"
auth_header = "authorization"
auth_value = "Bearer billing-secret-token"
timeout_ms = {billing_timeout_ms}
"#,
        BearerTokenHash::from_token("default-billing-write.default-billing-write-secret").as_str(),
        BearerTokenHash::from_token("partner-projects-write.partner-projects-write-secret")
            .as_str(),
        BearerTokenHash::from_token("read-billing.read-billing-secret").as_str(),
        BearerTokenHash::from_token("read-projects.read-projects-secret").as_str(),
        BearerTokenHash::from_token("expired-billing.expired-billing-secret").as_str(),
    ))?;

    Ok(AppConfig::new(
        "127.0.0.1:0".parse()?,
        "debug",
        ConfigSource::Path(config_file.clone()),
        SecretsConfig::load_from_file(&config_file)?,
    ))
}

pub fn bearer_token(
    api: &str,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    bearer_token_with_access(api, AccessLevel::Write, secrets)
}

pub fn bearer_token_with_access(
    api: &str,
    access: AccessLevel,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    if access == AccessLevel::Write {
        bearer_token_for_client(write_client_for_api(api, secrets)?, api, secrets)
    } else {
        Ok(read_only_bearer_token(api))
    }
}

pub fn bearer_token_for_client(
    client_slug: &str,
    api: &str,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = secrets
        .clients
        .get(client_slug)
        .ok_or_else(|| format!("missing test client '{client_slug}'"))?;
    let access = client
        .api_access
        .get(api)
        .copied()
        .ok_or_else(|| format!("client '{client_slug}' missing api '{api}' access"))?;

    if access != AccessLevel::Write {
        return Err(
            format!("client '{client_slug}' does not have write access for '{api}'").into(),
        );
    }

    Ok(match client_slug {
        "default" => "default-billing-write.default-billing-write-secret".to_owned(),
        "partner" => "partner-projects-write.partner-projects-write-secret".to_owned(),
        _ => {
            return Err(format!("unsupported test client '{client_slug}'").into());
        }
    })
}

pub fn expired_bearer_token(
    api: &str,
    secrets: &SecretsConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = secrets
        .clients
        .get("expired-billing")
        .ok_or("missing expired-billing test client")?;

    if !client.api_access.contains_key(api) {
        return Err(format!("expired test client missing api '{api}'").into());
    }

    Ok("expired-billing.expired-billing-secret".to_owned())
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

fn write_client_for_api(
    api: &str,
    secrets: &SecretsConfig,
) -> Result<&'static str, Box<dyn std::error::Error>> {
    for client_slug in ["default", "partner"] {
        if secrets
            .clients
            .get(client_slug)
            .and_then(|client| client.api_access.get(api))
            .copied()
            == Some(AccessLevel::Write)
        {
            return Ok(client_slug);
        }
    }

    Err(format!("no write client configured for api '{api}'").into())
}

fn read_only_bearer_token(api: &str) -> String {
    match api {
        "billing" => "read-billing.read-billing-secret".to_owned(),
        "projects" => "read-projects.read-projects-secret".to_owned(),
        other => format!("read-{other}.read-{other}-secret"),
    }
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
