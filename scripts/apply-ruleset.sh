#!/usr/bin/env bash
# Apply the vuln-sentinel merge gate ruleset (same as vuln-sentinel-e2e-lab) to one repo.
# Run with an ADMIN token (your gh login), never with the Bot token.
# Usage: scripts/apply-ruleset.sh owner/name [check-context ...]
#   With no contexts, uses check runs that passed on the default branch's latest commit.
#   Idempotent: updates the ruleset with the same name if it already exists.
set -euo pipefail
REPO=${1:?usage: apply-ruleset.sh owner/name [check ...]}; shift
NAME="Human approval and CI required"
BASE=$(gh api "repos/$REPO" --jq .default_branch)
if [[ $# -gt 0 ]]; then
  CHECKS=$(printf '%s\n' "$@" | jq -R . | jq -s .)
else
  SHA=$(gh api "repos/$REPO/commits/$BASE" --jq .sha)
  CHECKS=$(gh api "repos/$REPO/commits/$SHA/check-runs?per_page=100" \
    --jq '[.check_runs[] | select(.app.slug == "github-actions" and .conclusion == "success") | .name] | unique')
fi
[[ "$(jq length <<<"$CHECKS")" -gt 0 ]] || { echo "No passing GitHub Actions checks on $REPO@$BASE; pass contexts explicitly or add CI first" >&2; exit 2; }
BODY=$(jq -n --arg name "$NAME" --argjson checks "$CHECKS" '{
  name: $name, target: "branch", enforcement: "active", bypass_actors: [],
  conditions: {ref_name: {include: ["~DEFAULT_BRANCH"], exclude: []}},
  rules: [
    {type: "deletion"}, {type: "non_fast_forward"},
    {type: "pull_request", parameters: {required_approving_review_count: 1, dismiss_stale_reviews_on_push: true,
      require_code_owner_review: false, require_last_push_approval: true, required_review_thread_resolution: true,
      allowed_merge_methods: ["merge", "squash", "rebase"]}},
    {type: "required_status_checks", parameters: {strict_required_status_checks_policy: true, do_not_enforce_on_create: false,
      required_status_checks: [$checks[] | {context: ., integration_id: 15368}]}}
  ]}')
RID=$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$NAME\") | .id")
if [[ -n "$RID" ]]; then
  gh api -X PUT "repos/$REPO/rulesets/$RID" --input - <<<"$BODY" --jq '"updated ruleset \(.id) on '"$REPO"'"'
else
  gh api -X POST "repos/$REPO/rulesets" --input - <<<"$BODY" --jq '"created ruleset \(.id) on '"$REPO"'"'
fi
gh api -X PATCH "repos/$REPO" -F allow_auto_merge=false --jq '"allow_auto_merge=\(.allow_auto_merge)"'
echo "checks: $(jq -c . <<<"$CHECKS")"
