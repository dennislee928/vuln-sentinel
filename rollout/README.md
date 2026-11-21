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
1b. `scripts/apply-bot-branch-ruleset.sh owner/name`: only `vuln-sentinel-fix-bot[bot]` may create or update `vuln-sentinel/*` branches. GitHub rejects pushes from personal tokens, including other schedulers and chat agents, which never run vuln-sentinel's own identity check. On 2026-11-21 at 13:03 UTC, a personal account pushed to all three stage-2 fix branches; this rule blocks that.
2. Add the repo to the GitHub App installation (Settings → GitHub Apps → vuln-sentinel-fix-bot → Repository access).
3. `gh workflow run merge-gate-e2e.yml -f repo=owner/name`: every Bot bypass attempt must be rejected.
4. Scan in a dry run, then fix with `auto-merge: "false"` and `merge-without-checks: "false"`.

Repos without CI cannot get a `required_status_checks` rule, so they stay scan-only until CI exists.

**Organizations** (BabyGrootCICD, Twister5-com-tw-Dev-dep, National-Cheng-Chi-University-DCT-Dep, Jest-Test-Team, cyber-security-dev-dep-mitake-com-tw, quantumworld-dpdns-io): each needs its own App installation, approved by an org owner. Each workflow token step must set `owner:` to that org, because an installation token covers a single account.

## Status (2026-11-21)

| Goal | Status | Evidence |
|---|---|---|
| G7: approval and CI merge gate | Verified for the Bot and the admin | `merge-gate-e2e.yml` passed 16/16 on the lab and on 4 stage-1 repos. `scripts/check-admin-gate.sh` passed 12/12 on the lab: your own admin account can't merge an unapproved PR, can't self-approve, and can't push, fast-forward or force-push `main`. Rulesets have 0 bypass actors and `current_user_can_bypass=never`. Feeder#37 is approved but blocked by red CI. |
| Daily remediation | One repo: `dennislee928/QASM` | `fix-bot.yml` runs at 01:30 UTC with an App token scoped to the target. It runs a read-only gate preflight, sets `auto-merge false`, requests a reviewer, and caps fixes at 1 repo, 10 groups, 3 attempts and 20 new issues. `check-rollout.py` must pass. |
| Write identity | Enforced in code | `ticket`, `fix`, `verify`, `archive` and `run` refuse to write unless the token is an App installation token, so writes always come from `vuln-sentinel-fix-bot[bot]`. |
| G9: cross-organization automation | Not started | Each org needs its own App installation, approved by an org owner. Run `vuln-sentinel coverage` (see the main README) to list what is missing per owner. |

Next steps:
- Keep QASM daily and clean for one cycle.
- Add the other fixable stage-1 repos to the `fix-bot.yml` target list. Feeder needs green CI first; pokemon stays scan-only.
- Draft `stage2.txt` from the repos `coverage` marks **fixable**. For each, run `apply-ruleset.sh` and then `merge-gate-e2e.yml`.

## Instructions for external schedulers (for example a ChatGPT scheduled task)

Paste this in place of any older instruction:

> Never write to GitHub as a person. Every issue, branch, PR, comment or review must be made by `vuln-sentinel-fix-bot[bot]`, which means triggering `fix-bot.yml` or `rollout-stage.yml` in `dennislee928/vuln-sentinel`; those mint an App installation token. Never pass a personal access token to `vuln-sentinel` for `ticket`, `fix`, `verify`, `archive` or `run`, and never set `--allow-user-writes`. A personal token may only be used read-only (`scan`, `coverage`, or any command with `--dry-run`). Never merge, approve or enable auto-merge on a fix PR; a human approves and merges after CI passes.

A scheduler that ignores this still can't write as a person: `vuln-sentinel` refuses writes made with a user token.
