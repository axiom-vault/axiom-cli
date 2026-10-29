use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use std::future::Future;
use std::path::Path;
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

/// Largest token file read; a real one is well under 4 KiB.
pub(crate) const MAX_TOKENS_FILE_BYTES: u64 = 64 * 1024;

/// Read and parse a token file, refusing one larger than `MAX_TOKENS_FILE_BYTES`.
pub(crate) async fn read_tokens<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let read_error = || format!("Failed to read tokens file {}", path.display());
    let mut json = String::new();
    tokio::fs::File::open(path)
        .await
        .with_context(read_error)?
        .take(MAX_TOKENS_FILE_BYTES + 1)
        .read_to_string(&mut json)
        .await
        .with_context(read_error)?;
    if json.len() as u64 > MAX_TOKENS_FILE_BYTES {
        anyhow::bail!("Tokens file {} is larger than 64 KiB", path.display());
    }
    serde_json::from_str(&json).context("Failed to parse tokens file")
}

/// Publish the token file atomically: write a private temporary file beside it,
/// sync it, check that it is owner-only, then rename it into place. Only a
/// regular file that already holds tokens of type `T` is replaced; any other
/// existing path, including a symlink, is refused.
#[cfg(unix)]
pub(crate) async fn save_tokens<T: DeserializeOwned>(
    output: &Path,
    default_dir: Option<&Path>,
    json: &[u8],
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(existing) = tokio::fs::symlink_metadata(output).await {
        if !existing.is_file() || read_tokens::<T>(output).await.is_err() {
            anyhow::bail!(
                "{} already exists and is not a token file; refusing to overwrite it",
                output.display()
            );
        }
    }
    if let Some(dir) = default_dir {
        tokio::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .await
            .context("Failed to create token directory")?;
    }

    let mut tmp_name = output
        .file_name()
        .context("Token file path has no file name")?
        .to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = output.with_file_name(tmp_name);

    // Remove any stale file so the new one is created fresh with 0o600.
    // The mode flag in OpenOptions only applies on creation.
    let _ = tokio::fs::remove_file(&tmp_path).await;

    let published = async {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .await
            .context("Failed to create token file")?;
        f.write_all(json)
            .await
            .context("Failed to write tokens file")?;
        f.sync_all().await.context("Failed to write tokens file")?;
        let mode = f.metadata().await?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!("Token file permissions are {mode:o}, expected owner-only");
        }
        tokio::fs::rename(&tmp_path, output)
            .await
            .context("Failed to publish tokens file")
    }
    .await;
    if published.is_err() {
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }
    published?;

    // Sync the directory too, so the rename survives a crash.
    let dir = match output.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    tokio::fs::File::open(dir)
        .await
        .context("Failed to open token directory")?
        .sync_all()
        .await
        .context("Failed to sync token directory")
}

/// Owner-only permissions are not verified here, so refuse to write tokens.
#[cfg(not(unix))]
pub(crate) async fn save_tokens<T: DeserializeOwned>(
    _output: &Path,
    _default_dir: Option<&Path>,
    _json: &[u8],
) -> Result<()> {
    anyhow::bail!(
        "Saving OAuth tokens is supported only on Unix, where owner-only permissions can be checked"
    )
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

    // Check state first: without it, any local request could end the flow
    // and put text of its choosing into the terminal.
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

#[cfg(test)]
mod tests {
    use super::*;
    use axiomvault_storage::gdrive::Tokens;
    use std::path::PathBuf;
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
    fn parse_callback_checks_state_before_provider_error() {
        let error = parse_callback(
            "/callback?error=access_denied&error_description=forged",
            "csrf",
            "Dropbox",
        )
        .unwrap_err();
        assert!(error.error.to_string().contains("No state parameter"));

        let error = parse_callback(
            "/callback?error=access_denied&error_description=forged&state=wrong",
            "csrf",
            "Dropbox",
        )
        .unwrap_err();
        assert!(error.error.to_string().contains("CSRF token mismatch"));
    }

    #[test]
    fn parse_callback_rejects_csrf_mismatch() {
        let error =
            parse_callback("/callback?code=ok&state=wrong", "expected", "Dropbox").unwrap_err();

        assert_eq!(error.status_line, "400 Bad Request");
        assert!(error.error.to_string().contains("CSRF token mismatch"));
    }

    fn test_tokens() -> Tokens {
        Tokens {
            access_token: "access-secret".to_string(),
            refresh_token: "refresh-secret".to_string(),
            expires_at: chrono::Utc::now(),
        }
    }

    fn token_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("axiom-oauth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn save_tokens_replaces_only_a_token_file_and_keeps_it_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = token_test_dir("save");
        let output = dir.join("tokens.json");
        let mut rotated = test_tokens();
        rotated.access_token = "rotated-access".to_string();

        save_tokens::<Tokens>(&output, None, &serde_json::to_vec(&test_tokens()).unwrap())
            .await
            .unwrap();
        // Re-authentication replaces the previous token file.
        save_tokens::<Tokens>(&output, None, &serde_json::to_vec(&rotated).unwrap())
            .await
            .unwrap();
        assert_eq!(
            read_tokens::<Tokens>(&output).await.unwrap().access_token,
            "rotated-access"
        );
        let mode = std::fs::metadata(&output).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "temp file left"
        );

        let json = serde_json::to_vec(&rotated).unwrap();
        let other = dir.join("notes.txt");
        std::fs::write(&other, b"keep").unwrap();
        assert!(save_tokens::<Tokens>(&other, None, &json).await.is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"keep");

        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&output, &link).unwrap();
        assert!(save_tokens::<Tokens>(&link, None, &json).await.is_err());
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn read_tokens_refuses_an_oversized_file() {
        let dir = token_test_dir("oversized");
        let path = dir.join("tokens.json");
        std::fs::write(&path, vec![b' '; MAX_TOKENS_FILE_BYTES as usize + 1]).unwrap();

        let err = read_tokens::<Tokens>(&path).await.unwrap_err().to_string();
        assert!(err.contains("larger than 64 KiB"), "{err}");

        std::fs::remove_dir_all(&dir).unwrap();
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
