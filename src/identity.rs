//! Write identity: GitHub writes (issues, branches, PRs, reviews, merges) must be
//! made as the vuln-sentinel-fix-bot[bot] App installation, never as a person.
//!
//! Only an App installation token can list `/installation/repositories`; user
//! tokens (PATs, OAuth, `gh auth token`) get 401/403. That makes the check
//! independent of `VS_AUTH_MODE`, which is just an environment variable.
use crate::github::GitHub;
use anyhow::Result;

pub const BOT_LOGIN: &str = "vuln-sentinel-fix-bot[bot]";

/// Fail unless `gh` holds an App installation token. `allow_user_writes` is an
/// explicit opt-out for PAT users of the published action; the daily bot never sets it.
pub async fn require_bot_writer(gh: &GitHub, allow_user_writes: bool) -> Result<()> {
    match gh.get::<serde_json::Value>("/installation/repositories?per_page=1").await {
        Ok(_) => Ok(()),
        Err(e) if allow_user_writes => {
            tracing::warn!("writing to GitHub with a user token (--allow-user-writes); writes will not be attributed to {BOT_LOGIN}: {e:#}");
            Ok(())
        }
        Err(e) => anyhow::bail!(
            "refusing to write to GitHub: the token is not a GitHub App installation token, so writes would be made as a person instead of {BOT_LOGIN}. \
             Mint an installation token (actions/create-github-app-token) or use --dry-run. ({e:#})"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::tests::{json_response, mock};

    fn status(code: &str) -> String {
        format!("HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}")
    }

    #[tokio::test]
    async fn only_installation_tokens_may_write() {
        let (gh, finish) = mock(vec![
            json_response(r#"{"total_count":1,"repositories":[]}"#, ""),
            status("401 Unauthorized"),
            status("403 Forbidden"),
            status("403 Forbidden"),
        ]);
        require_bot_writer(&gh, false).await.unwrap();
        let e = require_bot_writer(&gh, false).await.unwrap_err().to_string();
        assert!(e.contains("not a GitHub App installation token") && e.contains(BOT_LOGIN), "{e}");
        assert!(require_bot_writer(&gh, false).await.is_err());
        require_bot_writer(&gh, true).await.unwrap();
        let requests = finish();
        assert!(requests.iter().all(|r| r.starts_with("GET /installation/repositories?per_page=1 HTTP/1.1")));
    }
}
