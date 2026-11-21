#!/usr/bin/env bash
# G7 (human side): prove the merge gate also stops the repository OWNER/ADMIN.
# Run locally with your own gh login (an admin token), against an isolated repo only.
# Opens an unapproved probe PR, attempts every merge/bypass path as the admin, and
# asserts each is rejected and the default branch does not move. Cleans up on exit.
# Usage: scripts/check-admin-gate.sh [owner/name]   (default: the e2e lab)
set -euo pipefail
REPO=${1:-dennislee928/vuln-sentinel-e2e-lab}
[[ "$REPO" == "dennislee928/vuln-sentinel-e2e-lab" || "${ALLOW_NON_LAB:-0}" == 1 ]] \
  || { echo "refusing: run against the e2e lab only (set ALLOW_NON_LAB=1 to override)" >&2; exit 2; }
fail=0
pass() { echo "PASS: $*"; }
bad()  { echo "FAIL: $*"; fail=1; }
expect_reject() {
  local label=$1; shift
  local out
  if out=$("$@" 2>&1); then
    bad "$label was ACCEPTED: $out"
  elif grep -qiE 'rule|review|protect|approv|status check|not allowed|pull request|your own|not mergeable|merge.*blocked' <<<"$out"; then
    pass "$label rejected — $(tr '\n' ' ' <<<"$out" | cut -c1-160)"
  else
    bad "$label rejected for an unrelated reason: $out"
  fi
}

ME=$(gh api user --jq .login)
PERM=$(gh api "repos/$REPO/collaborators/$ME/permission" --jq .permission)
[[ "$PERM" == "admin" ]] && pass "running as $ME with admin permission" || bad "$ME has $PERM, not admin; this test needs an admin"
BASE=$(gh api "repos/$REPO" --jq .default_branch)
MAIN_SHA=$(gh api "repos/$REPO/git/ref/heads/$BASE" --jq .object.sha)
BRANCH="admin-gate-probe-$(date +%s)-$$"
gh api -X POST "repos/$REPO/git/refs" -f ref="refs/heads/$BRANCH" -f sha="$MAIN_SHA" >/dev/null
cleanup() {
  [[ -n "${PR:-}" ]] && gh api -X PATCH "repos/$REPO/pulls/$PR" -f state=closed >/dev/null 2>&1 || true
  gh api -X DELETE "repos/$REPO/git/refs/heads/$BRANCH" >/dev/null 2>&1 || true
}
trap cleanup EXIT
gh api -X PUT "repos/$REPO/contents/e2e/admin-gate.md" -f message="test: admin gate probe" \
  -f content="$(printf 'admin gate probe\n' | base64 | tr -d '\n')" -f branch="$BRANCH" >/dev/null
PR=$(gh api -X POST "repos/$REPO/pulls" -f title="test: admin gate probe (auto-closed)" \
  -f body="G7 human-side probe. The admin must not be able to merge this without approval. Closed automatically." \
  -f head="$BRANCH" -f base="$BASE" --jq .number)
NODE=$(gh api "repos/$REPO/pulls/$PR" --jq .node_id)
BRANCH_SHA=$(gh api "repos/$REPO/git/ref/heads/$BRANCH" --jq .object.sha)
pass "opened unapproved probe PR #$PR as $ME"

for m in merge squash rebase; do
  expect_reject "admin merge ($m)" gh api -X PUT "repos/$REPO/pulls/$PR/merge" -f merge_method=$m
done
expect_reject "admin merge (GraphQL mergePullRequest)" gh api graphql \
  -f query='mutation($id:ID!){mergePullRequest(input:{pullRequestId:$id}){clientMutationId}}' -f id="$NODE"
expect_reject "admin self-approve" gh api -X POST "repos/$REPO/pulls/$PR/reviews" -f event=APPROVE -f body="self-approval attempt"
expect_reject "admin direct commit to $BASE" gh api -X PUT "repos/$REPO/contents/e2e/admin-direct.md" \
  -f message="test: direct push attempt" -f content="$(printf 'direct\n' | base64 | tr -d '\n')" -f branch="$BASE"
expect_reject "admin fast-forward $BASE to PR head" gh api -X PATCH "repos/$REPO/git/refs/heads/$BASE" -f sha="$BRANCH_SHA" -F force=false
expect_reject "admin force-push $BASE" gh api -X PATCH "repos/$REPO/git/refs/heads/$BASE" -f sha="$BRANCH_SHA" -F force=true

[[ "$(gh api "repos/$REPO/pulls/$PR" --jq .merged)" == "false" ]] && pass "PR #$PR not merged" || bad "PR #$PR merged!"
[[ "$(gh api "repos/$REPO/git/ref/heads/$BASE" --jq .object.sha)" == "$MAIN_SHA" ]] && pass "$BASE unchanged at ${MAIN_SHA:0:12}" || bad "$BASE moved!"
exit $fail
