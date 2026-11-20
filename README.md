# Vuln Sentinel

A GitHub Action, written in Rust, that runs every day and:

1. **Collects** the newest advisories from CVE (NVD), OSV, ENISA EUVD, the GitHub Advisory Database, OpenSSF Malicious Packages, Vulners, Sploitus and AttackerKB. Each advisory is mapped to the OWASP Top 10 through its CWE. The results go into `reports/{date}.md`.
2. **Scans** every repository you own or reach through your organizations: lockfiles on the default branch are matched against the full OSV database, and hits that come from that day's advisories are highlighted.
3. **Opens tickets**: one issue per vulnerable package in the affected repo, plus a daily tracker issue in your ops repo.
4. **Fixes**: upgrades each package to the minimal fixed version with the ecosystem's own tool and opens one PR per repo for manual review and merge.
5. **Verifies** again until every finding from that day is resolved, then **archives** the report, the raw advisories and the resolution metrics into `archive/{date}/`.

## Quick start

Create a **private** ops repository; reports list private repos and their vulnerabilities. Then:

```bash
gh secret set SENTINEL_TOKEN   # classic PAT: repo, workflow, read:org (authorize SSO for orgs if required)
# optional feeds
gh secret set VULNERS_API_KEY
gh secret set ATTACKERKB_API_KEY
gh secret set NVD_API_KEY
```

Copy [`examples/daily.yml`](examples/daily.yml) and [`examples/verify.yml`](examples/verify.yml) into `.github/workflows/`.

```yaml
- uses: actions/checkout@v4
- uses: dennislee928/vuln-sentinel@v1
  with:
    token: ${{ secrets.SENTINEL_TOKEN }}
    mode: run          # run | collect | scan | ticket | fix | verify | archive
    auto-merge: "false"
    merge-without-checks: "false"
```

The workflow needs `permissions: contents: write, issues: write`. The action commits `reports/`, `state/` and `archive/` back to the ops repository.

For a GitHub App installation token, set `auth-mode: app` in the action's `with` block. The default `auth-mode: pat` preserves PAT enumeration through `/user/repos`; App mode lists only repositories accessible to the installation token through `/installation/repositories`, including pagination of the `repositories` array. See [GitHub's installation API documentation](https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation).

For remediation, grant the installation **Contents: write**, **Pull requests: write**, and **Issues: write** on the target repositories. Installation access alone does not imply write access: `permissions.admin` is not used to authorize fixes. In PAT mode, an explicit `permissions.push: false` skips remediation. In App mode that field is ignored, because installation listings report user-style permissions that are always false for a Bot; GitHub enforces the installation token's permissions during branch pushes and PR creation. A scan-only installation needs Contents read access. The bot does not change repository settings to enable auto-merge or bypass branch protections.

An installation token covers one account, and only the repositories selected for that installation. Repository and issue listings fail rather than return a partial list when pagination is cut short or `total_count` disagrees.

### Coverage

`vuln-sentinel coverage` shows which scan targets the App can actually remediate. It compares the repositories a PAT sees (with the usual `--owners`, `--include-forks` and similar filters) against every App installation, listed with the App's own JWT. It writes `reports/coverage-<date>.md` and `.json`.

```sh
VS_TOKEN=<PAT> VS_APP_ID=<app id> VS_APP_PRIVATE_KEY_FILE=app.pem vuln-sentinel coverage
```

Each target gets one of four statuses:

- **fixable:** the token was granted Contents, Pull requests and Issues write, and the repository has an active Actions workflow.
- **scan-only:** a permission is missing, there's no CI, or the repository is archived.
- **not selected:** the owner has an installation that doesn't include the repository.
- **not installed:** the owner has no installation at all.

Only a human can widen repository access or install the App on an organization; the report lists exactly what to change.

## Sources

| Source | How | Key |
|---|---|---|
| CVE (NVD) | NVD CVE API 2.0, by publish date | optional `NVD_API_KEY` |
| OSV | `modified_id.csv` per ecosystem, newly published records | – |
| ENISA EUVD | `euvdservices.enisa.europa.eu/api/search` | – |
| GitHub Advisory Database | `GET /advisories` | – |
| OpenSSF | `ossf/malicious-packages` new reports | – |
| OWASP | CWE → OWASP Top 10:2025 classification of everything collected | – |
| Vulners | Lucene search API (CVEs + exploits) | `VULNERS_API_KEY` |
| AttackerKB | Topics API (exploitability assessments) | `ATTACKERKB_API_KEY` |
| Sploitus | Exploit search (best effort, no official API) | – |

A source that is missing its key, or that errors, is shown in the report as *skipped* or *error*. It never fails the run.

## Supported lockfiles and fixers

| Ecosystem | Files | Fix |
|---|---|---|
| Rust | `Cargo.lock` | `cargo update -p name@old --precise fixed` |
| npm / Yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | bump the direct dependency, or add `overrides` / `resolutions` / `pnpm.overrides`, then regenerate the lockfile with scripts disabled |
| Go | `go.mod` | `go get mod@fixed && go mod tidy` |
| Python | `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`* | rewrite the pin / `poetry update --lock` / `uv lock --upgrade-package` |
| Ruby | `Gemfile.lock` | `bundle lock --update name` |
| PHP | `composer.lock` | `composer update name --with-dependencies --no-install` |
| Dart | `pubspec.lock` | `dart pub upgrade name` |

\* Scanned only. When no fix exists, or the fixer can't apply one, the issue gets a note and Dependabot security updates are switched on for that repository.

A change is committed only after re-parsing the lockfile confirms the vulnerable version is gone.

## Merge policy

Set `fix-reviewers` and `fix-assignees` (comma-separated GitHub logins) to request human review and assign fix PRs. The scoped token supplied through `token` is used for pushes, PR creation and review requests; use `auth-mode: app` with an installation token for Bot authorship. `fix-packages` optionally limits remediation to named packages while scans and reports continue to include every finding. Fix PRs link related issues without closing keywords, so issues close only after verification finds the vulnerable versions gone from the default branch.

- Automatic merging defaults to **off** in both the Action and CLI. Production remediation workflows should explicitly set `auto-merge: "false"` and `merge-without-checks: "false"`.
- With `auto-merge: false`, neither GitHub auto-merge enablement nor the direct merge API runs. Existing auto-merge is disabled on tracked open fix PRs during `verify`, and before updating an existing fix PR. Dry runs do not change GitHub settings or PRs.
- If you explicitly opt into `auto-merge: true`, GitHub auto-merge is requested when required checks exist and repository settings already permit it. Otherwise `verify` merges after all checks pass. Repositories with no CI require manual merge unless `merge-without-checks: true` is also set.
- If a fix PR is closed without merging, its findings go back to *open* and are retried. After `max-fix-attempts` tries the package is left to a human.

## Lifecycle

```
collect ─► scan ─► ticket ─► fix ─► (wait) ─► verify ─► fix ─► … ─► archive
                                     ▲________________________________│ every 4h
```

A day is archived once every finding first seen on it is resolved, meaning it no longer appears on the default branch. `archive/{date}/` then holds `report.md`, `advisories.json`, `findings.json`, `metrics.json` and `metrics.md`: counts per source and severity, tickets, PRs, auto-merges, and mean/max time to resolve.

## Inputs

See [`action.yml`](action.yml). The main ones: `auth-mode`, `owners`, `repos`, `exclude`, `include-forks`, `include-archived`, `auto-merge`, `merge-without-checks`, `dry-run`, `window-hours`, `max-new-issues`, `max-fix-repos`, `max-fix-groups`, `max-iterations`, `poll-minutes`.

## Local use

```bash
cargo build --release
VS_TOKEN=$(gh auth token) ./target/release/vuln-sentinel run --dry-run --limit 5
# For an installation token, also set VS_AUTH_MODE=app (default: pat).
```

## License

MIT
