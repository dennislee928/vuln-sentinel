//! `coverage`: which scan targets the GitHub App can actually remediate.
//!
//! The scan targets are the repositories the PAT sees (with the usual
//! filters). The App side is every installation, listed with the App JWT. Each
//! target is classified as one of:
//!
//! - fixable: visible to an installation whose token has every write
//!   permission remediation needs, and the repository has CI.
//! - scan-only: visible, but a permission is missing or there is no CI (no CI
//!   means no merge gate, so fixes stay manual; see `rollout/README.md`).
//! - not selected: the owner has an installation that does not include it.
//! - not installed: the owner has no installation at all.
//!
//! Only a human can widen an installation's repository access or install the App
//! on an organization; this report lists exactly what to change.
use crate::app_auth::{self, Installation};
use crate::github::GitHub;
use crate::repos::{self, Repo, RepoFilter};
use anyhow::{Context, Result};
use futures::{stream, StreamExt, TryStreamExt};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Installation permissions remediation needs (README: App mode).
pub const REQUIRED_WRITE: [&str; 3] = ["contents", "pull_requests", "issues"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Access {
    Fixable,
    ScanOnly { reasons: Vec<String> },
    NotSelected,
    NotInstalled,
}

impl Access {
    fn label(&self) -> &'static str {
        match self {
            Access::Fixable => "fixable",
            Access::ScanOnly { .. } => "scan-only",
            Access::NotSelected => "not selected",
            Access::NotInstalled => "not installed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub repo: String,
    pub installation: Option<u64>,
    #[serde(flatten)]
    pub access: Access,
}

/// What one installation can see and what its token was granted.
#[derive(Debug, Clone, Serialize)]
pub struct InstallationView {
    pub id: u64,
    pub account: String,
    pub repository_selection: String,
    pub permissions: BTreeMap<String, String>,
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub targets: usize,
    pub installations: Vec<InstallationView>,
    pub rows: Vec<Row>,
}

impl Coverage {
    pub fn count(&self, label: &str) -> usize {
        self.rows.iter().filter(|r| r.access.label() == label).count()
    }

    /// Targets any installation can see.
    pub fn visible(&self) -> usize {
        self.rows.iter().filter(|r| r.installation.is_some()).count()
    }
}

fn missing_permissions(granted: &BTreeMap<String, String>) -> Vec<String> {
    REQUIRED_WRITE
        .iter()
        .filter(|p| granted.get(**p).map(String::as_str) != Some("write"))
        .map(|p| format!("{p}: write not granted"))
        .collect()
}

/// Classify every target. `has_ci` covers the targets an installation can see.
pub fn classify(targets: &[Repo], installs: &[InstallationView], has_ci: &HashMap<String, bool>) -> Vec<Row> {
    let lower = |s: &str| s.to_lowercase();
    let by_repo: HashMap<String, &InstallationView> =
        installs.iter().flat_map(|i| i.repositories.iter().map(move |r| (lower(r), i))).collect();
    let owners: HashSet<String> = installs.iter().map(|i| lower(&i.account)).collect();
    targets
        .iter()
        .map(|t| {
            let key = lower(&t.full_name);
            let owner = key.split('/').next().unwrap_or_default().to_string();
            let (installation, access) = match by_repo.get(&key) {
                Some(i) => {
                    let mut reasons = missing_permissions(&i.permissions);
                    if !has_ci.get(&key).copied().unwrap_or(false) {
                        reasons.push("no CI workflow, so no merge gate".into());
                    }
                    if t.archived {
                        reasons.push("archived".into());
                    }
                    (Some(i.id), if reasons.is_empty() { Access::Fixable } else { Access::ScanOnly { reasons } })
                }
                None if owners.contains(&owner) => (None, Access::NotSelected),
                None => (None, Access::NotInstalled),
            };
            Row { repo: t.full_name.clone(), installation, access }
        })
        .collect()
}

/// Whether `repo` has at least one active, non-dynamic Actions workflow.
/// Dynamic workflows (Dependabot, dependency graph) are not CI.
async fn has_ci(gh: &GitHub, repo: &str) -> Result<bool> {
    let v: serde_json::Value = gh.get(&format!("/repos/{repo}/actions/workflows?per_page=100")).await?;
    Ok(v["workflows"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|w| w["state"].as_str() == Some("active") && !w["path"].as_str().unwrap_or_default().starts_with("dynamic/")))
}

/// Gather everything: targets via the PAT, installations via the App JWT.
pub async fn collect(pat: &GitHub, app: &GitHub, filter: &RepoFilter, concurrency: usize) -> Result<Coverage> {
    let targets = repos::list_with_mode(pat, filter, "pat").await.context("listing scan targets with the PAT")?;
    let mut views = Vec::new();
    for Installation { id, account, repository_selection, permissions } in app_auth::installations(app).await? {
        let (token, granted) = app_auth::installation_token(app, id).await.with_context(|| format!("installation {id} ({account})"))?;
        let raw = app
            .with_token(token)
            .paginate_all("/installation/repositories?per_page=100", Some("repositories"), 100)
            .await
            .with_context(|| format!("listing repositories of installation {id} ({account})"))?;
        let repositories = raw.iter().filter_map(|r| r["full_name"].as_str().map(str::to_string)).collect();
        // The token's granted permissions are authoritative; fall back to the
        // installation's configured permissions if the response omitted them.
        let permissions = if granted.is_empty() { permissions } else { granted };
        views.push(InstallationView { id, account, repository_selection, permissions, repositories });
    }
    let visible: HashSet<String> = views.iter().flat_map(|v| v.repositories.iter().map(|r| r.to_lowercase())).collect();
    let checked: Vec<(String, bool)> = stream::iter(targets.iter().filter(|t| visible.contains(&t.full_name.to_lowercase())))
        .map(|t| async move { Ok::<_, anyhow::Error>((t.full_name.to_lowercase(), has_ci(pat, &t.full_name).await?)) })
        .buffer_unordered(concurrency.max(1))
        .try_collect()
        .await?;
    let rows = classify(&targets, &views, &checked.into_iter().collect());
    Ok(Coverage { targets: targets.len(), installations: views, rows })
}

pub fn render(date: &str, c: &Coverage) -> String {
    let mut s = format!("# GitHub App coverage {date}\n\n");
    s += &format!("The App can see **{} of {}** scan targets and can remediate **{}**.\n\n", c.visible(), c.targets, c.count("fixable"));
    s += "| Status | Repositories |\n|---|---|\n";
    for l in ["fixable", "scan-only", "not selected", "not installed"] {
        s += &format!("| {l} | {} |\n", c.count(l));
    }
    s += "\n## Installations\n\n| Account | Id | Repository access | Repositories | Missing write permissions |\n|---|---|---|---|---|\n";
    for i in &c.installations {
        let missing = missing_permissions(&i.permissions);
        let missing = if missing.is_empty() {
            "none".to_string()
        } else {
            missing.iter().map(|m| m.split(':').next().unwrap_or_default()).collect::<Vec<_>>().join(", ")
        };
        s += &format!("| {} | {} | {} | {} | {missing} |\n", i.account, i.id, i.repository_selection, i.repositories.len());
    }
    let mut by_owner: BTreeMap<String, Vec<&Row>> = BTreeMap::new();
    for r in c.rows.iter().filter(|r| r.access != Access::Fixable) {
        by_owner.entry(r.repo.split('/').next().unwrap_or_default().to_string()).or_default().push(r);
    }
    s += "\n## What to change\n\nOnly a human can do these, in GitHub settings. vuln-sentinel never widens its own access.\n";
    for (owner, rows) in by_owner {
        s += &format!("\n### {owner}\n\n");
        let not_installed = rows.iter().any(|r| r.access == Access::NotInstalled);
        if not_installed {
            s += &format!(
                "The App is not installed on `{owner}`. An owner of that account must install it (all repositories, or the ones below).\n\n"
            );
        }
        for r in rows {
            let what = match &r.access {
                Access::NotSelected => "add to the installation's repository access".to_string(),
                Access::NotInstalled => "install the App".to_string(),
                Access::ScanOnly { reasons } => reasons.join("; "),
                Access::Fixable => unreachable!(),
            };
            s += &format!("- `{}`: {} ({what})\n", r.repo, r.access.label());
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str) -> Repo {
        Repo {
            full_name: name.into(),
            default_branch: "main".into(),
            archived: false,
            fork: false,
            private: false,
            has_issues: true,
            can_push: Some(true),
        }
    }

    fn view(id: u64, account: &str, perms: &[(&str, &str)], repos: &[&str]) -> InstallationView {
        InstallationView {
            id,
            account: account.into(),
            repository_selection: "selected".into(),
            permissions: perms.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            repositories: repos.iter().map(|r| r.to_string()).collect(),
        }
    }

    const WRITE: [(&str, &str); 3] = [("contents", "write"), ("pull_requests", "write"), ("issues", "write")];

    #[test]
    fn classifies_every_target() {
        let targets: Vec<Repo> = ["me/ci", "me/no-ci", "me/other", "Org/x", "Org2/y", "org3/z"].map(target).to_vec();
        let installs = [
            view(1, "me", &WRITE, &["me/ci", "me/no-ci"]),
            view(2, "org", &[("contents", "write"), ("pull_requests", "read")], &["org/X"]),
            view(3, "org3", &WRITE, &[]),
        ];
        let ci = HashMap::from([("me/ci".to_string(), true), ("me/no-ci".to_string(), false), ("org/x".to_string(), true)]);
        let rows = classify(&targets, &installs, &ci);
        let got: Vec<(&str, &Access)> = rows.iter().map(|r| (r.repo.as_str(), &r.access)).collect();
        assert_eq!(got[0], ("me/ci", &Access::Fixable));
        assert_eq!(got[1], ("me/no-ci", &Access::ScanOnly { reasons: vec!["no CI workflow, so no merge gate".into()] }));
        assert_eq!(got[2], ("me/other", &Access::NotSelected));
        assert_eq!(
            got[3],
            ("Org/x", &Access::ScanOnly { reasons: vec!["pull_requests: write not granted".into(), "issues: write not granted".into()] })
        );
        assert_eq!(got[4], ("Org2/y", &Access::NotInstalled));
        assert_eq!(got[5], ("org3/z", &Access::NotSelected));
        assert_eq!(rows[3].installation, Some(2));

        let c = Coverage { targets: targets.len(), installations: installs.to_vec(), rows };
        assert_eq!((c.visible(), c.count("fixable"), c.count("not installed")), (3, 1, 1));
        let md = render("2026-11-20", &c);
        assert!(md.contains("The App can see **3 of 6** scan targets and can remediate **1**."), "{md}");
        assert!(md.contains("The App is not installed on `Org2`."), "{md}");
        assert!(md.contains("- `me/other`: not selected (add to the installation's repository access)"), "{md}");
        assert!(!md.contains("`me/ci`"), "fixable repos need no change: {md}");
    }

    #[tokio::test]
    async fn collect_walks_every_installation() {
        use crate::github::tests::{json_response, mock};
        let (gh, finish) = mock(vec![
            // PAT: scan targets.
            json_response(r#"[{"full_name":"me/a"},{"full_name":"org/b"},{"full_name":"org/c"}]"#, ""),
            // App JWT: installations.
            json_response(r#"[{"id":1,"account":{"login":"me"}},{"id":2,"account":{"login":"org"}}]"#, ""),
            json_response(r#"{"token":"ghs_FAKE1","permissions":{"contents":"write","pull_requests":"write","issues":"write"}}"#, ""),
            json_response(r#"{"total_count":1,"repositories":[{"full_name":"me/a"}]}"#, ""),
            json_response(r#"{"token":"ghs_FAKE2","permissions":{"contents":"read"}}"#, ""),
            json_response(r#"{"total_count":1,"repositories":[{"full_name":"org/b"}]}"#, ""),
            // CI checks for the two visible targets (concurrency 1 keeps order).
            json_response(r#"{"workflows":[{"state":"active","path":".github/workflows/ci.yml"}]}"#, ""),
            json_response(r#"{"workflows":[{"state":"active","path":"dynamic/dependabot/dependabot-updates"}]}"#, ""),
        ]);
        let c = collect(&gh, &gh, &RepoFilter::default(), 1).await.unwrap();
        let requests = finish();
        assert_eq!(c.rows.iter().map(|r| r.access.label()).collect::<Vec<_>>(), ["fixable", "scan-only", "not selected"]);
        assert!(requests[3].contains("authorization: Bearer ghs_FAKE1") || requests[3].contains("Authorization: Bearer ghs_FAKE1"));
        assert!(requests[3].starts_with("GET /installation/repositories?per_page=100 HTTP/1.1"));
        assert!(requests[6].starts_with("GET /repos/me/a/actions/workflows?per_page=100 HTTP/1.1"));
    }
}
