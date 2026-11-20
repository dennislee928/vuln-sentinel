"""Assert every fix PR in rollout state is Bot-authored, human-gated and never auto-merged."""
import json
import os
import subprocess
import sys
from pathlib import Path

BOT = "vuln-sentinel-fix-bot[bot]"
phase = sys.argv[1]


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


state = json.loads(Path("state/findings.json").read_text())
tracked = list(state["findings"].values())
prs = sorted({(t["finding"]["repo"], t["pr"]["number"]) for t in tracked if t.get("pr")})
errors, lines = [], []
for repo, n in prs:
    pr = api(f"repos/{repo}/pulls/{n}")
    if pr["user"]["login"] != BOT:
        errors.append(f"{repo}#{n} author {pr['user']['login']}")
    if pr["auto_merge"] is not None:
        errors.append(f"{repo}#{n} has auto-merge enabled")
    if pr["merged"]:
        if pr["merged_by"]["login"] == BOT:
            errors.append(f"{repo}#{n} merged by the Bot")
        reviews = api(f"repos/{repo}/pulls/{n}/reviews?per_page=100")
        if not any(r["state"] == "APPROVED" and r["user"]["type"] == "User" for r in reviews):
            errors.append(f"{repo}#{n} merged without human approval")
    lines.append(f"{repo}#{n} state={pr['state']} merged={pr['merged']} {pr['html_url']}")
by_status = {}
for t in tracked:
    by_status[t["status"]] = by_status.get(t["status"], 0) + 1
scan_errors = sum(d.get("scan_errors", 0) for d in state["days"].values())
print("\n".join(lines) or "no fix PRs")
print(f"findings by status: {by_status}; scan_errors={scan_errors}")
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a") as out:
        out.write(f"## Rollout {phase}\n" + "".join(f"- {l}\n" for l in lines) + f"\n{by_status}, scan_errors={scan_errors}\n")
if errors:
    raise SystemExit("FAIL: " + "; ".join(errors))
print(f"PASS {phase}: {len(prs)} fix PRs gated")
