#!/usr/bin/env bash
# G7: prove the fix-bot App token cannot bypass review / CI on the default branch.
# Positive control: the token CAN create a branch and PR (so rejections are rule-driven,
# not a weak token). Every bypass attempt must then be rejected and main must not move.
# Env: GH_TOKEN (App installation token), REPO (owner/name), RULESET_NAME, BOT_LOGIN.
set -euo pipefail
: "${GH_TOKEN:?}" "${REPO:?}" "${RULESET_NAME:=Human approval and CI required}" "${BOT_LOGIN:=vuln-sentinel-fix-bot[bot]}"
fail=0
pass() { echo "PASS: $*"; echo "- ✅ $*" >>"${GITHUB_STEP_SUMMARY:-/dev/null}"; }
bad()  { echo "FAIL: $*"; echo "- ❌ $*" >>"${GITHUB_STEP_SUMMARY:-/dev/null}"; fail=1; }
# expect_reject <label> <gh api args...>: the call must fail with a rule/review style message.
expect_reject() {
  local label=$1; shift
  local out
  if out=$(gh api "$@" 2>&1); then
    bad "$label was ACCEPTED: $out"
  elif grep -qiE 'rule|review|protect|approv|status check|auto.?merge|not allowed|pull request' <<<"$out"; then
    pass "$label rejected — $(tr '\n' ' ' <<<"$out" | cut -c1-200)"
  else
    bad "$label rejected for an unrelated reason: $out"
  fi
}

BASE=$(gh api "repos/$REPO" --jq .default_branch)
MAIN_SHA=$(gh api "repos/$REPO/git/ref/heads/$BASE" --jq .object.sha)

# 1. Ruleset is active, targets the default branch, and the bot cannot bypass it.
RID=$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$RULESET_NAME\") | .id")
[[ -n "$RID" ]] || { bad "ruleset '$RULESET_NAME' not found"; exit 1; }
gh api "repos/$REPO/rulesets/$RID" > /tmp/ruleset.json
jq -e '.enforcement == "active"' /tmp/ruleset.json >/dev/null && pass "ruleset $RID active" || bad "ruleset not active"
jq -e '.current_user_can_bypass == "never"' /tmp/ruleset.json >/dev/null \
  && pass "bot current_user_can_bypass=never" || bad "bot bypass = $(jq -r .current_user_can_bypass /tmp/ruleset.json)"
gh api "repos/$REPO/rules/branches/$BASE" > /tmp/rules.json
jq -e 'any(.[]; .type == "pull_request" and .parameters.required_approving_review_count >= 1 and .parameters.require_last_push_approval and .parameters.dismiss_stale_reviews_on_push)' /tmp/rules.json >/dev/null \
  && pass "pull_request rule: ≥1 approval, last-push approval, stale dismissal" || bad "pull_request rule missing/weak"
jq -e 'any(.[]; .type == "required_status_checks" and (.parameters.required_status_checks | length) > 0)' /tmp/rules.json >/dev/null \
  && pass "required_status_checks: $(jq -c '[.[]|select(.type=="required_status_checks").parameters.required_status_checks[].context]' /tmp/rules.json)" || bad "no required status checks"
jq -e 'any(.[]; .type == "non_fast_forward") and any(.[]; .type == "deletion")' /tmp/rules.json >/dev/null \
  && pass "force-push and deletion blocked by rules" || bad "non_fast_forward/deletion rule missing"

# 2. Positive control: bot opens a throwaway PR.
BRANCH="vuln-sentinel/merge-gate-${GITHUB_RUN_ID:-local}-$$"
gh api -X POST "repos/$REPO/git/refs" -f ref="refs/heads/$BRANCH" -f sha="$MAIN_SHA" >/dev/null
cleanup() {
  [[ -n "${PR:-}" ]] && gh api -X PATCH "repos/$REPO/pulls/$PR" -f state=closed >/dev/null 2>&1 || true
  gh api -X DELETE "repos/$REPO/git/refs/heads/$BRANCH" >/dev/null 2>&1 || true
}
trap cleanup EXIT
gh api -X PUT "repos/$REPO/contents/e2e/merge-gate.md" -f message="test: merge gate probe" \
  -f content="$(printf 'merge gate probe %s\n' "${GITHUB_RUN_ID:-local}" | base64 | tr -d '\n')" -f branch="$BRANCH" >/dev/null
PR=$(gh api -X POST "repos/$REPO/pulls" -f title="test: merge gate probe (auto-closed)" \
  -f body="G7 probe. The bot must not be able to merge this. Closed automatically." -f head="$BRANCH" -f base="$BASE" --jq .number)
AUTHOR=$(gh api "repos/$REPO/pulls/$PR" --jq .user.login)
[[ "$AUTHOR" == "$BOT_LOGIN" ]] && pass "positive control: bot has write and opened PR #$PR" || bad "PR author is $AUTHOR"
NODE=$(gh api "repos/$REPO/pulls/$PR" --jq .node_id)

# 3. Bypass attempts.
expect_reject "bot merge (merge)"  -X PUT "repos/$REPO/pulls/$PR/merge" -f merge_method=merge
expect_reject "bot merge (squash)" -X PUT "repos/$REPO/pulls/$PR/merge" -f merge_method=squash
expect_reject "bot self-approve"   -X POST "repos/$REPO/pulls/$PR/reviews" -f event=APPROVE -f body="self-approval attempt"
expect_reject "bot enable auto-merge" graphql -f query='mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:SQUASH}){clientMutationId}}' -f id="$NODE"
expect_reject "bot direct commit to $BASE" -X PUT "repos/$REPO/contents/e2e/direct-push.md" -f message="test: direct push attempt" \
  -f content="$(printf 'direct\n' | base64 | tr -d '\n')" -f branch="$BASE"
BRANCH_SHA=$(gh api "repos/$REPO/git/ref/heads/$BRANCH" --jq .object.sha)
expect_reject "bot fast-forward $BASE to PR head" -X PATCH "repos/$REPO/git/refs/heads/$BASE" -f sha="$BRANCH_SHA" -F force=false
expect_reject "bot force-push $BASE" -X PATCH "repos/$REPO/git/refs/heads/$BASE" -f sha="$BRANCH_SHA" -F force=true
expect_reject "bot delete $BASE" -X DELETE "repos/$REPO/git/refs/heads/$BASE"

# 4. Nothing moved.
[[ "$(gh api "repos/$REPO/pulls/$PR" --jq .merged)" == "false" ]] && pass "PR #$PR not merged" || bad "PR #$PR merged!"
[[ "$(gh api "repos/$REPO/git/ref/heads/$BASE" --jq .object.sha)" == "$MAIN_SHA" ]] && pass "$BASE unchanged at ${MAIN_SHA:0:12}" || bad "$BASE moved!"
exit $fail
