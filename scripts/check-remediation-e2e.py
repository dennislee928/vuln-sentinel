"""Assert live E2E evidence without approving or merging on behalf of a human."""
import json
import os
import subprocess
import sys
from pathlib import Path


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def require(condition, message):
    if not condition:
        raise SystemExit(message)


phase = sys.argv[1]
require(phase in ("proposed", "before-verify", "verified"), "Unknown phase")
repo = os.environ["TEST_REPO"]
require(repo == "dennislee928/Claude_Devboard_Pet", "Unexpected validation repository")
state = json.loads(Path("state/findings.json").read_text())
findings = list(state["findings"].values())
require(findings, "No findings: cannot claim a successful remediation test")
require(all(t["finding"]["repo"] == repo for t in findings), "Unexpected repository in state")
prs = {t["pr"]["number"] for t in findings if t.get("pr")}
issues = {t["issue"]["number"] for t in findings if t.get("issue")}
require(len(prs) == 1 and issues, "Expected one fix PR and at least one security issue")
pr_number = next(iter(prs))
pr = api(f"repos/{repo}/pulls/{pr_number}")
require(pr["user"]["login"] == "vuln-sentinel-fix-bot[bot]", "PR was not authored by the App")
require(pr["auto_merge"] is None, "GitHub auto-merge must remain disabled")
require("dennislee928" in {a["login"] for a in pr["assignees"]}, "Missing assignee")
if phase == "proposed":
    require(not pr["merged"] and pr["state"] == "open", "PR must await human approval")
    require("dennislee928" in {r["login"] for r in pr["requested_reviewers"]}, "Missing human reviewer")
    require(all(t["status"] == "fix_proposed" for t in findings), "Fix not proposed")
else:
    require(pr["merged"], "Human must approve and merge before verification")
    reviews = api(f"repos/{repo}/pulls/{pr_number}/reviews?per_page=100")
    latest = {}
    for review in reviews:
        if review["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[review["user"]["login"]] = review
    approval = latest.get("dennislee928", {})
    require(approval.get("state") == "APPROVED" and approval.get("commit_id") == pr["head"]["sha"],
            "Missing human approval of the final PR head")
for number in issues:
    issue = api(f"repos/{repo}/issues/{number}")
    expected = "closed" if phase == "verified" else "open"
    require(issue["state"] == expected, f"Issue must be {expected} during {phase}")
if phase == "verified":
    require(all(t["status"] == "resolved" for t in findings), "Findings remain unresolved")
    for day in state["days"].values():
        require(day.get("scan_errors", 0) == 0, "Scan errors must not count as resolution")
print(f"PASS {phase}: {pr['html_url']}; issues={sorted(issues)}")
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a") as out:
        out.write(f"\nE2E **{phase}**: {pr['html_url']} — issues {sorted(issues)}\n")
