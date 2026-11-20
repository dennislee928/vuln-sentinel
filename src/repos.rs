//! Enumerate repositories accessible to a PAT or GitHub App installation.
use crate::github::GitHub;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repo {
    pub full_name: String,
    pub default_branch: String,
    pub archived: bool,
    pub fork: bool,
    pub private: bool,
    pub has_issues: bool,
    /// PAT push permission, when supplied. Always `None` in App mode: installation
    /// listings report user-style `permissions` (all false for a Bot), so Git push
    /// and PR creation enforce the installation token's actual permissions instead.
    pub can_push: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct RepoFilter {
    /// Restrict to these owners (user or org logins); empty = all.
    pub owners: Vec<String>,
    /// Restrict to these exact `owner/name`s; empty = all.
    pub only: Vec<String>,
    pub include_forks: bool,
    pub include_archived: bool,
    pub exclude: Vec<String>,
    pub limit: Option<usize>,
}

pub async fn list(gh: &GitHub, f: &RepoFilter) -> Result<Vec<Repo>> {
    let mode = std::env::var("VS_AUTH_MODE").unwrap_or_else(|_| "pat".into());
    list_with_mode(gh, f, &mode).await
}

async fn list_with_mode(gh: &GitHub, f: &RepoFilter, mode: &str) -> Result<Vec<Repo>> {
    let (path, pick) = repository_endpoint(mode)?;
    let raw = gh.paginate_all(path, pick, 100).await?;
    let mut repos: Vec<Repo> = raw
        .iter()
        .filter_map(|r| {
            Some(Repo {
                full_name: r["full_name"].as_str()?.to_string(),
                default_branch: r["default_branch"].as_str().unwrap_or("main").to_string(),
                archived: r["archived"].as_bool().unwrap_or(false),
                fork: r["fork"].as_bool().unwrap_or(false),
                private: r["private"].as_bool().unwrap_or(true),
                has_issues: r["has_issues"].as_bool().unwrap_or(true),
                can_push: if mode == "app" { None } else { r["permissions"]["push"].as_bool() },
            })
        })
        .filter(|r| keep(r, f))
        .collect();
    repos.sort_by_key(|r| r.full_name.to_lowercase());
    repos.dedup_by(|a, b| a.full_name == b.full_name);
    if let Some(n) = f.limit {
        repos.truncate(n);
    }
    Ok(repos)
}

fn repository_endpoint(mode: &str) -> Result<(&'static str, Option<&'static str>)> {
    match mode {
        "app" => Ok(("/installation/repositories?per_page=100", Some("repositories"))),
        "pat" => Ok(("/user/repos?affiliation=owner,organization_member&per_page=100&sort=full_name", None)),
        _ => bail!("invalid VS_AUTH_MODE {mode:?}; expected pat or app"),
    }
}

fn keep(r: &Repo, f: &RepoFilter) -> bool {
    let owner = r.full_name.split('/').next().unwrap_or_default();
    (f.include_archived || !r.archived)
        && (f.include_forks || !r.fork)
        && (f.owners.is_empty() || f.owners.iter().any(|o| o.eq_ignore_ascii_case(owner)))
        && (f.only.is_empty() || f.only.iter().any(|o| o.eq_ignore_ascii_case(&r.full_name)))
        && !f.exclude.iter().any(|o| o.eq_ignore_ascii_case(&r.full_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::tests::{json_response, mock};

    #[tokio::test]
    async fn app_envelope_pagination_and_pat_array() {
        let first = r#"{"repositories":[{"full_name":"org/b"}]}"#;
        let second = r#"{"repositories":[{"full_name":"org/a","permissions":{"admin":false,"push":false,"pull":false}}]}"#;
        let (gh, finish) = mock(vec![
            json_response(first, "Link: <{base}/installation/repositories?per_page=100&page=2>; rel=\"next\"\r\n"),
            json_response(second, ""),
            json_response(r#"[{"full_name":"user/a","permissions":{"admin":false,"push":true}}]"#, ""),
        ]);
        let repos = list_with_mode(&gh, &RepoFilter::default(), "app").await.unwrap();
        assert_eq!(repos.iter().map(|r| r.full_name.as_str()).collect::<Vec<_>>(), ["org/a", "org/b"]);
        assert_eq!(repos[0].can_push, None);
        let repos = list_with_mode(&gh, &RepoFilter::default(), "pat").await.unwrap();
        assert_eq!(repos[0].can_push, Some(true));
        assert!(list_with_mode(&gh, &RepoFilter::default(), "invalid").await.is_err());
        let requests = finish();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("GET /installation/repositories?per_page=100 HTTP/1.1"));
        assert!(requests[1].starts_with("GET /installation/repositories?per_page=100&page=2 HTTP/1.1"));
        assert!(requests[2].starts_with("GET /user/repos?affiliation=owner,organization_member&per_page=100&sort=full_name HTTP/1.1"));
    }

    fn repo(name: &str, archived: bool, fork: bool) -> Repo {
        Repo {
            full_name: name.into(),
            default_branch: "main".into(),
            archived,
            fork,
            private: false,
            has_issues: true,
            can_push: Some(true),
        }
    }

    #[test]
    fn filtering() {
        let f = RepoFilter { owners: vec!["Org".into()], ..Default::default() };
        assert!(keep(&repo("org/a", false, false), &f));
        assert!(!keep(&repo("org/a", true, false), &f));
        assert!(!keep(&repo("org/a", false, true), &f));
        assert!(!keep(&repo("me/a", false, false), &f));
        let f = RepoFilter { include_forks: true, exclude: vec!["me/b".into()], ..Default::default() };
        assert!(keep(&repo("me/a", false, true), &f));
        assert!(!keep(&repo("me/b", false, false), &f));
    }
}
