use std::{error::Error, time::Duration};

use gate_agent::{error::AppError, proxy::upstream::execute_request};
use tokio::{io::AsyncReadExt, net::TcpListener};

async fn spawn_hanging_upstream() -> Result<String, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept upstream connection");
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    Ok(format!("http://{address}"))
}

async fn spawn_disconnecting_upstream() -> Result<String, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept upstream connection");
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
    });

    Ok(format!("http://{address}"))
}

#[tokio::test]
async fn execute_request_maps_outer_timeout_to_upstream_timeout() -> Result<(), Box<dyn Error>> {
    let upstream_url = spawn_hanging_upstream().await?;
    let client = reqwest::Client::new();
    let request = client.get(&upstream_url).build()?;

    let error = execute_request(&client, request, 50)
        .await
        .expect_err("request should time out");

    assert!(matches!(error, AppError::UpstreamTimeout));

    Ok(())
}

#[tokio::test]
async fn execute_request_maps_reqwest_timeout_to_upstream_timeout() -> Result<(), Box<dyn Error>> {
    let upstream_url = spawn_hanging_upstream().await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(50))
        .build()?;
    let request = client.get(&upstream_url).build()?;

    let error = execute_request(&client, request, 500)
        .await
        .expect_err("request should time out inside reqwest");

    assert!(matches!(error, AppError::UpstreamTimeout));

    Ok(())
}

#[tokio::test]
async fn execute_request_keeps_non_timeout_failures_as_upstream_request()
-> Result<(), Box<dyn Error>> {
    let upstream_url = spawn_disconnecting_upstream().await?;
    let client = reqwest::Client::new();
    let request = client.get(&upstream_url).build()?;

    let error = execute_request(&client, request, 500)
        .await
        .expect_err("request should fail");

    match error {
        AppError::UpstreamRequest(message) => assert!(!message.is_empty()),
        other => panic!("expected upstream request error, got {other:?}"),
    }

    Ok(())
}
