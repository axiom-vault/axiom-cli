use anyhow::{anyhow, Context, Result};
use std::future::Future;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

const OAUTH_CALLBACK_ADDR: &str = "127.0.0.1:8080";
const OAUTH_CALLBACK_URL: &str = "http://localhost:8080";

pub(crate) fn resolve_required_oauth_value(
    flag_value: Option<String>,
    env_value: Option<String>,
    legacy_env_value: Option<String>,
    missing_message: &str,
) -> Result<String> {
    flag_value
        .filter(|value| !value.is_empty())
        .or_else(|| env_value.filter(|value| !value.is_empty()))
        .or_else(|| legacy_env_value.filter(|value| !value.is_empty()))
        .ok_or_else(|| anyhow!(missing_message.to_string()))
}

pub(crate) fn resolve_optional_oauth_value(
    flag_value: Option<String>,
    env_value: Option<String>,
    legacy_env_value: Option<String>,
) -> Option<String> {
    flag_value
        .filter(|value| !value.is_empty())
        .or_else(|| env_value.filter(|value| !value.is_empty()))
        .or_else(|| legacy_env_value.filter(|value| !value.is_empty()))
}

pub(crate) async fn complete_local_oauth_flow<T, F, Fut>(
    provider_name: &str,
    auth_url: &str,
    csrf_token: &str,
    exchange_code: F,
) -> Result<T>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let listener = TcpListener::bind(OAUTH_CALLBACK_ADDR).await.context(
        "Failed to start local server on port 8080. Is another process using this port?",
    )?;

    println!("Starting {provider_name} authentication...");
    println!();
    println!("Opening your browser to authorize AxiomVault...");

    let browser_opened = open::that(auth_url).is_ok();
    if browser_opened {
        println!("Browser opened successfully!");
    } else {
        println!("Could not open browser automatically.");
        println!("Please visit this URL to authorize:");
        println!();
        println!("  {auth_url}");
    }

    println!();
    println!("Waiting for authorization... (Press Ctrl+C to cancel)");

    let (mut socket, _) =
        tokio::time::timeout(std::time::Duration::from_secs(300), listener.accept())
            .await
            .context("OAuth callback timed out after 5 minutes")?
            .context("Failed to accept connection")?;

    let mut buffer = vec![0u8; 4096];
    let n = socket
        .read(&mut buffer)
        .await
        .context("Failed to read request")?;
    let request = String::from_utf8_lossy(&buffer[..n]);
    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    let callback_url = format!("{OAUTH_CALLBACK_URL}{path}");
    let parsed_url = Url::parse(&callback_url).context("Failed to parse callback URL")?;

    let mut code = None;
    let mut state = None;
    for (key, value) in parsed_url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            _ => {}
        }
    }

    let auth_code = code.ok_or_else(|| anyhow!("No authorization code received"))?;
    let received_state = state.ok_or_else(|| anyhow!("No state parameter received"))?;

    if received_state != csrf_token {
        let error_html = r#"<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1 style="color: #d32f2f;">Authentication Failed</h1>
<p>Security validation failed. Please try again.</p>
</body>
</html>"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            error_html.len(),
            error_html
        );
        socket.write_all(response.as_bytes()).await.ok();
        anyhow::bail!("CSRF token mismatch - possible security issue");
    }

    let success_html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1 style="color: #4caf50;">Authentication Successful!</h1>
<p>You have successfully authorized AxiomVault to access your {provider_name}.</p>
<p>You can close this window and return to the terminal.</p>
</body>
</html>"#
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        success_html.len(),
        success_html
    );
    socket.write_all(response.as_bytes()).await.ok();

    println!();
    println!("Authorization received! Exchanging for access tokens...");

    exchange_code(auth_code).await
}

pub(crate) async fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    let _ = tokio::fs::remove_file(path).await;

    #[cfg(unix)]
    {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .await
            .context("Failed to create token file")?;
        file.write_all(contents.as_bytes())
            .await
            .context("Failed to write tokens file")?;
    }

    #[cfg(not(unix))]
    {
        tokio::fs::write(path, contents)
            .await
            .context("Failed to write tokens file")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn resolve_required_oauth_value_prefers_flag_then_primary_then_legacy() {
        assert_eq!(
            resolve_required_oauth_value(
                Some("flag".into()),
                Some("primary".into()),
                Some("legacy".into()),
                "missing"
            )
            .unwrap(),
            "flag"
        );
        assert_eq!(
            resolve_required_oauth_value(
                None,
                Some("primary".into()),
                Some("legacy".into()),
                "missing"
            )
            .unwrap(),
            "primary"
        );
        assert_eq!(
            resolve_required_oauth_value(None, None, Some("legacy".into()), "missing").unwrap(),
            "legacy"
        );
    }

    #[test]
    fn resolve_optional_oauth_value_ignores_empty_values() {
        assert_eq!(
            resolve_optional_oauth_value(
                Some(String::new()),
                Some(String::new()),
                Some("legacy".into())
            ),
            Some("legacy".into())
        );
        assert_eq!(
            resolve_optional_oauth_value(None, Some(String::new()), None),
            None
        );
    }

    #[tokio::test]
    async fn write_secret_file_replaces_existing_contents() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "axiom-remote-oauth-test-{}-{}",
            std::process::id(),
            unique
        ));

        write_secret_file(&path, "first").await.unwrap();
        write_secret_file(&path, "second").await.unwrap();

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents, "second");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = tokio::fs::remove_file(&path).await;
    }
}
