#!/usr/bin/env python3
"""Build a Fortify SSC scan summary (markdown) for Azure DevOps.

Input is plain fcli JSON output, so this script makes no network calls:
  fcli ssc appversion get  "<app>:<version>" -o json                    > appversion.json
  fcli ssc issue list --av "<app>:<version>" --include=visible,removed -o json > issues.json

Issues are grouped by SSC scan status, which compares the latest scan with
the previous one (for a PR version copied from master: PR vs master):
  NEW           -> New
  REINTRODUCED  -> Re-introduced
  REMOVED       -> Fixed (only issues removed by the latest scan)
  UPDATED       -> Unchanged (still present)
"""
import argparse
import json
import sys
from datetime import datetime, timedelta
from urllib.parse import quote

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}


def parse_date(value):
    if not value:
        return None
    # SSC format: 2026-11-17T05:20:27.361+00:00
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def md(text):
    """Escape characters that would break a markdown table cell."""
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


class Links:
    def __init__(self, ssc_url, version_id, repo_url, branch):
        self.ssc_url = ssc_url.rstrip("/")
        self.version_id = version_id
        self.repo_url = repo_url.rstrip("/") if repo_url else ""
        self.branch = branch

    def version(self):
        return f"{self.ssc_url}/html/ssc/version/{self.version_id}/audit"

    def issue(self, issue_id):
        return f"{self.ssc_url}/html/ssc/version/{self.version_id}/fix/{issue_id}/"

    def source(self, path, line):
        if not self.repo_url or not path:
            return None
        url = f"{self.repo_url}?path=/{quote(path)}"
        if self.branch:
            url += f"&version=GB{quote(self.branch, safe='')}"
        if line:
            url += f"&line={line}&lineEnd={line}&lineStartColumn=1&lineEndColumn=999"
        return url


def location_cell(issue, links, linkable=True):
    path = issue.get("fullFileName") or issue.get("primaryLocation") or ""
    line = issue.get("lineNumber")
    label = f"{issue.get('primaryLocation') or path}:{line}" if line else (issue.get("primaryLocation") or path)
    url = links.source(path, line) if linkable else None
    return f"[{md(label)}]({url})" if url else md(label)


def issue_table(issues, links, linkable=True):
    rows = ["| Severity | Category | Location | SSC |", "|---|---|---|---|"]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for i in sorted(issues, key=lambda x: (order.get(x.get("friority"), 9), x.get("issueName") or "")):
        sev = i.get("friority") or "?"
        rows.append(
            f"| {SEV_ICON.get(sev, '')} {md(sev)} | {md(i.get('issueName'))} | "
            f"{location_cell(i, links, linkable)} | [#{i.get('id')}]({links.issue(i.get('id'))}) |"
        )
    return "\n".join(rows)


def build(appversion, issues, policy, links, app_name, version_name, is_pr, build_url, max_critical):
    state = appversion.get("currentState") or {}
    last_upload = parse_date(state.get("lastFprUploadDate"))

    visible = [i for i in issues if not i.get("removed")]
    removed = [i for i in issues if i.get("removed")]

    new = [i for i in visible if i.get("scanStatus") == "NEW"]
    reintroduced = [i for i in visible if i.get("scanStatus") == "REINTRODUCED"]
    unchanged = [i for i in visible if i.get("scanStatus") == "UPDATED"]
    # Fixed in THIS scan: removed at or after the latest upload (SSC sets
    # removedDate while processing that upload). Older removals are excluded.
    if last_upload:
        cutoff = last_upload - timedelta(minutes=1)
        fixed = [i for i in removed if (parse_date(i.get("removedDate")) or datetime.min.replace(tzinfo=cutoff.tzinfo)) >= cutoff]
    else:
        fixed = []

    counts = {s: sum(1 for i in visible if i.get("friority") == s) for s in SEVERITIES}
    policy_text = {"pass": "✅ Pass", "fail": "❌ Fail"}.get(policy, "⚪ Not checked")
    scan_date = last_upload.strftime("%Y-%m-%d %H:%M UTC") if last_upload else "n/a"

    out = []
    out.append("# 🛡️ Fortify Scan Summary")
    out.append("")
    out.append(f"**Application:** {md(app_name)}  ")
    out.append(f"**Version:** [{md(version_name)}]({links.version()})  ")
    out.append(f"**Security policy:** {policy_text}  ")
    out.append(f"**Last scan:** {scan_date}")
    out.append("")

    out.append("## 📊 Open issues by severity")
    out.append("| " + " | ".join(f"{SEV_ICON[s]} {s}" for s in SEVERITIES) + " | Total |")
    out.append("|" + "---|" * (len(SEVERITIES) + 1))
    out.append("| " + " | ".join(str(counts[s]) for s in SEVERITIES) + f" | **{len(visible)}** |")
    out.append("")

    baseline = "master" if is_pr else "the previous scan"
    out.append(f"## 🔄 Changes compared with {baseline}")
    out.append("| 🆕 New | ♻️ Re-introduced | ✅ Fixed | ➖ Unchanged |")
    out.append("|---|---|---|---|")
    out.append(f"| **{len(new)}** | {len(reintroduced)} | {len(fixed)} | {len(unchanged)} |")
    out.append("")

    if new:
        out.append(f"### 🆕 New issues ({len(new)})")
        out.append(issue_table(new, links))
        out.append("")
    if reintroduced:
        out.append(f"### ♻️ Re-introduced issues ({len(reintroduced)})")
        out.append(issue_table(reintroduced, links))
        out.append("")
    if fixed:
        # Fixed code is gone from the branch, so no source link
        out.append(f"### ✅ Fixed issues ({len(fixed)})")
        out.append(issue_table(fixed, links, linkable=False))
        out.append("")
    if not (new or reintroduced or fixed):
        out.append("*No new, re-introduced or fixed issues in this scan.* ✅")
        out.append("")

    # Full critical list only on branch builds; PR comments stay focused on changes
    criticals = sorted(
        (i for i in visible if i.get("friority") == "Critical"),
        key=lambda x: (x.get("issueName") or "", x.get("fullFileName") or "", x.get("lineNumber") or 0),
    )
    if not is_pr and criticals and max_critical > 0:
        shown = criticals[:max_critical]
        more = f", showing first {len(shown)}" if len(criticals) > len(shown) else ""
        out.append(f"## 🚨 Open critical issues ({len(criticals)}{more})")
        out.append(issue_table(shown, links))
        out.append("")

    out.append("---")
    out.append("### 🔗 Links")
    out.append(f"- [All issues in Fortify SSC]({links.version()})")
    if build_url:
        out.append(f"- [Build results (see the Scans tab for SARIF findings)]({build_url})")
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--appversion-json", required=True)
    p.add_argument("--issues-json", required=True)
    p.add_argument("--ssc-url", required=True)
    p.add_argument("--app", required=True, help="SSC application name")
    p.add_argument("--version", required=True, help="SSC version name")
    p.add_argument("--policy", choices=["pass", "fail", "unknown"], default="unknown")
    p.add_argument("--repo-url", default="", help="ADO repo web URL, for source links")
    p.add_argument("--branch", default="", help="Branch the source links point at")
    p.add_argument("--build-url", default="", help="ADO build results URL (…/_build/results?buildId=N)")
    p.add_argument("--pr", action="store_true", help="PR build: compare with master, skip full critical list")
    p.add_argument("--max-critical", type=int, default=20)
    p.add_argument("--out", default="-")
    a = p.parse_args()

    with open(a.appversion_json) as f:
        appversion = json.load(f)
    with open(a.issues_json) as f:
        issues = json.load(f)

    links = Links(a.ssc_url, appversion.get("id"), a.repo_url, a.branch)
    text = build(appversion, issues, a.policy, links, a.app, a.version, a.pr, a.build_url, a.max_critical)
    if a.out == "-":
        sys.stdout.write(text)
    else:
        with open(a.out, "w") as f:
            f.write(text)


if __name__ == "__main__":
    main()
