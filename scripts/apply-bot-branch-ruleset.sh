#!/usr/bin/env bash
# P0 (bot-only writes): only vuln-sentinel-fix-bot[bot] may create or update vuln-sentinel/* branches.
# A personal token (yours, a PAT in another scheduler, a chat agent) is rejected by GitHub itself,
# so this holds even for tools that never run vuln-sentinel's own identity check.
# Run with an ADMIN token (your gh login). Idempotent.
# Usage: scripts/apply-bot-branch-ruleset.sh owner/name
set -euo pipefail
REPO=${1:?usage: apply-bot-branch-ruleset.sh owner/name}
NAME="Fix branches: vuln-sentinel-fix-bot only"
APP_ID=$(gh api apps/vuln-sentinel-fix-bot --jq .id)
BODY=$(jq -n --arg name "$NAME" --argjson app "$APP_ID" '{
  name: $name, target: "branch", enforcement: "active",
  bypass_actors: [{actor_id: $app, actor_type: "Integration", bypass_mode: "always"}],
  conditions: {ref_name: {include: ["refs/heads/vuln-sentinel/**"], exclude: []}},
  rules: [{type: "creation"}, {type: "update"}]}')
RID=$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$NAME\") | .id")
if [[ -n "$RID" ]]; then
  gh api -X PUT "repos/$REPO/rulesets/$RID" --input - <<<"$BODY" --jq '"updated ruleset \(.id) on '"$REPO"'"'
else
  gh api -X POST "repos/$REPO/rulesets" --input - <<<"$BODY" --jq '"created ruleset \(.id) on '"$REPO"'"'
fi
