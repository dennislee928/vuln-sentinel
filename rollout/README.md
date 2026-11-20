# Staged rollout

Each `stageN.txt` lists `owner/name` targets, one per line. `merge-gate-e2e.yml` refuses any repo not listed here.

| Stage | Targets | Gate to advance |
|---|---|---|
| 0 | `vuln-sentinel-e2e-lab` | G7 merge-gate E2E passes. G8 loop passes: Scan → Issue → Fix Branch → PR → Reviewer → CI → human Approval → human Merge → Rescan → Close Issue |
| 1 | 5 low-risk repos named by the owner | Ruleset applied, merge-gate E2E passes on each, fix PRs bot-authored and blocked until human approval, verify closes issues |
| 2 | 25 repos | Stage 1 clean for one daily cycle |
| 3 | 100 repos | Stage 2 clean, no unexpected PR churn |
| 4 | all 253 scan targets | Stage 3 clean |

Per stage:
1. `scripts/apply-ruleset.sh owner/name`: run with an admin token. It mirrors the lab ruleset with the repo's real CI checks.
2. Add the repo to the GitHub App installation (Settings → GitHub Apps → vuln-sentinel-fix-bot → Repository access).
3. `gh workflow run merge-gate-e2e.yml -f repo=owner/name`: every Bot bypass attempt must be rejected.
4. Scan in a dry run, then fix with `auto-merge: "false"` and `merge-without-checks: "false"`.

Repos without CI cannot get a `required_status_checks` rule, so they stay scan-only until CI exists.

**Organizations** (BabyGrootCICD, Twister5-com-tw-Dev-dep, National-Cheng-Chi-University-DCT-Dep, Jest-Test-Team, cyber-security-dev-dep-mitake-com-tw, quantumworld-dpdns-io): each needs its own App installation, approved by an org owner. Each workflow token step must set `owner:` to that org, because an installation token covers a single account.
