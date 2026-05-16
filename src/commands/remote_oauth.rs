use anyhow::{anyhow, Context, Result};
use std::future::Future;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

const OAUTH_CALLBACK_ADDR: &str = "127.0.0.1:8080";
const OAUTH_CALLBACK_URL: &str = "http://localhost:8080";

fn first_non_empty_value(values: [Option<String>; 3]) -> Option<String> {
    values.into_iter().flatten().find(|value| !value.is_empty())
}

pub(crate) fn resolve_required_oauth_value(
    flag_value: Option<String>,
    env_value: Option<String>,
    legacy_env_value: Option<String>,
    missing_message: &str,
) -> Result<String> {
    first_non_empty_value([flag_value, env_value, legacy_env_value])
        .ok_or_else(|| anyhow!(missing_message.to_string()))
}

pub(crate) fn resolve_optional_oauth_value(
    flag_value: Option<String>,
    env_value: Option<String>,
    legacy_env_value: Option<String>,
) -> Option<String> {
    first_non_empty_value([flag_value, env_value, legacy_env_value])
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

    if open::that(auth_url).is_ok() {
        println!("Browser opened successfully!");
    } else {
        println!("Could not open browser automatically.");
        println!("Please visit this URL to authorize:");
        println!();
        println!(" {auth_url}");
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

    let callback = match parse_callback(path, csrf_token, provider_name) {
        Ok(callback) => callback,
        Err(failure) => {
            let _ = write_html_response(
                &mut socket,
                failure.status_line,
                "Authentication Failed",
                &failure.browser_message,
                "#d32f2f",
            )
            .await;
            return Err(failure.error);
        }
    };

    println!();
    println!("Authorization received! Exchanging for access tokens...");

    match exchange_code(callback.auth_code).await {
        Ok(value) => {
            let _ = write_html_response(
                &mut socket,
                "200 OK",
                "Authentication Successful",
                &format!(
                    "You have successfully authorized AxiomVault to access your {provider_name}."
                ),
                "#4caf50",
            )
            .await;
            Ok(value)
        }
        Err(error) => {
            let _ = write_html_response(
                &mut socket,
                "500 Internal Server Error",
                "Authentication Failed",
                "AxiomVault could not finish exchanging or saving your tokens. Return to the terminal for details and try again.",
                "#d32f2f",
            )
            .await;
            Err(error)
        }
    }
}

pub(crate) async fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    write_secret_file_with_hook(path, contents, |_| Ok(())).await
}

async fn write_secret_file_with_hook<F>(path: &Path, contents: &str, before_rename: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    #[cfg(unix)]
    {
        let temp_path = secret_temp_path(path)?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .await
            .context("Failed to create temporary token file")?;

        file.write_all(contents.as_bytes())
            .await
            .context("Failed to write tokens file")?;
        file.sync_all()
            .await
            .context("Failed to flush tokens file to disk")?;
        drop(file);

        if let Err(error) = before_rename(&temp_path) {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(error);
        }

        tokio::fs::rename(&temp_path, path)
            .await
            .context("Failed to atomically replace token file")?;
        // Durability requires syncing the parent directory after rename so the
        // directory entry for the new token file is persisted before success.
        sync_parent_directory(path)
            .await
            .context("Failed to flush token parent directory to disk")?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = before_rename;
        tokio::fs::write(path, contents).await.context(
            "Failed to write tokens file (non-Unix platforms use a non-atomic fallback; prefer a protected directory)",
        )?;
        Ok(())
    }
}

#[cfg(unix)]
async fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Token path has no parent directory"))?;
    let directory = tokio::fs::File::open(parent)
        .await
        .context("Failed to open token parent directory")?;
    directory
        .sync_all()
        .await
        .context("Failed to sync token parent directory")?;
    Ok(())
}

#[derive(Debug)]
struct OAuthCallback {
    auth_code: String,
}

struct CallbackFailure {
    status_line: &'static str,
    browser_message: String,
    error: anyhow::Error,
}

impl CallbackFailure {
    fn bad_request(browser_message: impl Into<String>, error: anyhow::Error) -> Self {
        Self {
            status_line: "400 Bad Request",
            browser_message: browser_message.into(),
            error,
        }
    }
}

fn parse_callback(
    path: &str,
    csrf_token: &str,
    provider_name: &str,
) -> std::result::Result<OAuthCallback, CallbackFailure> {
    let callback_url = format!("{OAUTH_CALLBACK_URL}{path}");
    let parsed_url = Url::parse(&callback_url).map_err(|error| {
        CallbackFailure::bad_request(
            "The OAuth callback URL was malformed. Please close this window and try again.",
            anyhow::Error::new(error).context("Failed to parse callback URL"),
        )
    })?;

    let mut code = None;
    let mut state = None;
    let mut provider_error = None;
    let mut provider_error_description = None;

    for (key, value) in parsed_url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            "error" => provider_error = Some(value.to_string()),
            "error_description" => provider_error_description = Some(value.to_string()),
            _ => {}
        }
    }

    if let Some(error_code) = provider_error {
        let detail = provider_error_description
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "No additional details were provided by the OAuth provider.".into());
        return Err(CallbackFailure::bad_request(
            format!(
                "{provider_name} returned an authorization error. You can close this window and return to the terminal."
            ),
            anyhow!("{provider_name} authorization failed: {error_code} ({detail})"),
        ));
    }

    let received_state = state.ok_or_else(|| {
        CallbackFailure::bad_request(
            "The OAuth callback did not include a state parameter. Please close this window and try again.",
            anyhow!("No state parameter received"),
        )
    })?;

    if received_state != csrf_token {
        return Err(CallbackFailure::bad_request(
            "Security validation failed. Please close this window and try again.",
            anyhow!("CSRF token mismatch - possible security issue"),
        ));
    }

    let auth_code = code.ok_or_else(|| {
        CallbackFailure::bad_request(
            "The OAuth callback did not include an authorization code. Please close this window and try again.",
            anyhow!("No authorization code received"),
        )
    })?;

    Ok(OAuthCallback { auth_code })
}

async fn write_html_response(
    socket: &mut TcpStream,
    status_line: &str,
    title: &str,
    body_message: &str,
    heading_color: &str,
) -> Result<()> {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>{title}</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1 style="color: {heading_color};">{title}</h1>
<p>{body_message}</p>
<p>You can close this window and return to the terminal.</p>
</body>
</html>"#
    );
    let response = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        html.len(),
        html
    );
    socket
        .write_all(response.as_bytes())
        .await
        .context("Failed to write OAuth callback response")
}

fn secret_temp_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Token file path must include a file name"))?
        .to_string_lossy();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("System clock is before UNIX_EPOCH")?
        .as_nanos();

    Ok(parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        unique
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn resolve_required_oauth_value_prefers_flag_then_primary_then_legacy() {
        assert_eq!(
            resolve_required_oauth_value(
                Some("flag".into()),
                Some("primary".into()),
                Some("legacy".into()),
                "missing",
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
                Some("legacy".into()),
            ),
            Some("legacy".into())
        );
        assert_eq!(
            resolve_optional_oauth_value(None, Some(String::new()), None),
            None
        );
    }

    #[test]
    fn parse_callback_rejects_provider_error() {
        let error = parse_callback(
            "/callback?error=access_denied&error_description=user%20denied&state=csrf",
            "csrf",
            "Dropbox",
        )
        .unwrap_err();

        assert_eq!(error.status_line, "400 Bad Request");
        assert!(error
            .error
            .to_string()
            .contains("Dropbox authorization failed: access_denied (user denied)"));
    }

    #[test]
    fn parse_callback_rejects_csrf_mismatch() {
        let error =
            parse_callback("/callback?code=ok&state=wrong", "expected", "Dropbox").unwrap_err();

        assert_eq!(error.status_line, "400 Bad Request");
        assert!(error.error.to_string().contains("CSRF token mismatch"));
    }

    #[tokio::test]
    async fn write_secret_file_replaces_existing_contents() {
        let path = temp_test_path("replace");

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

    #[cfg(unix)]
    #[tokio::test]
    async fn write_secret_file_preserves_existing_contents_when_rename_aborted() {
        let path = temp_test_path("preserve");
        let temp_path = Arc::new(Mutex::new(None::<PathBuf>));

        write_secret_file(&path, "original").await.unwrap();
        let captured_temp_path = Arc::clone(&temp_path);

        let error = write_secret_file_with_hook(&path, "updated", move |pending_path| {
            *captured_temp_path.lock().unwrap() = Some(pending_path.to_path_buf());
            Err(anyhow!("simulated rename abort"))
        })
        .await
        .unwrap_err();

        assert!(error.to_string().contains("simulated rename abort"));
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), "original");

        let pending_path = temp_path.lock().unwrap().clone().unwrap();
        assert!(!pending_path.exists());

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn complete_local_oauth_flow_returns_browser_failure_on_exchange_error() {
        let flow = tokio::spawn(async move {
            complete_local_oauth_flow(
                "Dropbox",
                "http://localhost/authorize",
                "csrf-token",
                |code| async move {
                    assert_eq!(code, "auth-code");
                    Err(anyhow!("exchange failed"))
                },
            )
            .await
        });

        let response = send_callback_request("/callback?code=auth-code&state=csrf-token").await;
        let result: Result<String> = flow.await.unwrap();
        let error = result.unwrap_err();

        assert!(response.contains("500 Internal Server Error"));
        assert!(response.contains("Authentication Failed"));
        assert!(!response.contains("Authentication Successful"));
        assert!(error.to_string().contains("exchange failed"));
    }

    fn temp_test_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "axiom-remote-oauth-test-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    async fn send_callback_request(path: &str) -> String {
        for _ in 0..50 {
            match tokio::net::TcpStream::connect(OAUTH_CALLBACK_ADDR).await {
                Ok(mut stream) => {
                    let request = format!(
                        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    );
                    stream.write_all(request.as_bytes()).await.unwrap();
                    let _ = stream.shutdown().await;

                    let mut response = String::new();
                    stream.read_to_string(&mut response).await.unwrap();
                    return response;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
            }
        }

        panic!("callback listener did not start in time");
    }
}
