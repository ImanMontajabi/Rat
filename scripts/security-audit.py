#!/usr/bin/env python3
"""Known vulnerabilities in what Rat's build depends on (`.github/workflows/security-audit.yml`).

* GitHub Actions used in .github/ (`uses: owner/repo@<commit sha> # vX.Y.Z`): every advisory GitHub's Advisory
  Database lists for that version (`gh api /advisories?ecosystem=actions`), and every action that is not pinned to a
  full commit SHA or has no version comment (so it cannot be checked).
* Package lockfiles (a Swift `Package.resolved`, or any other ecosystem): osv-scanner's JSON report (`--osv`). Rat
  has no third-party packages today, so osv-scanner finds no package sources; the scan is there for the first one.

Writes a Markdown report (`--report`) and prints `found=true|false` (append it to $GITHUB_OUTPUT). The exit
status is 0 either way, so the workflow can open the issue before it fails the run.

    scripts/security-audit.py [--root .] [--osv osv.json] [--report report.md]
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*(?:#\s*(\S+))?")
SHA = re.compile(r"^[0-9a-f]{40}$")


def pins(root):
    """Every `uses:` of a published action under .github/, as dicts: file, line, action, repo, ref, version."""
    out = []
    for path in sorted((root / ".github").rglob("*")):
        if path.suffix not in (".yml", ".yaml") or not path.is_file():
            continue
        for n, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = USES.match(text)
            if not m or m.group(1).startswith(("./", "docker://")):
                continue
            action, _, ref = m.group(1).partition("@")
            out.append({
                "file": str(path.relative_to(root)), "line": n, "action": action,
                "repo": "/".join(action.split("/")[:2]), "ref": ref,
                "version": (m.group(2) or "").removeprefix("v") or None,
            })
    return out


def fetch_advisories(repo, version):
    """GitHub's reviewed advisories for one action version (the `gh` CLI, authenticated by GH_TOKEN)."""
    r = subprocess.run(["gh", "api", "-X", "GET", "/advisories", "-f", "ecosystem=actions",
                        "-f", f"affects={repo}@{version}", "-f", "per_page=100"],
                       capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def action_findings(found_pins, fetch=fetch_advisories):
    findings, cache = [], {}
    for p in found_pins:
        where = f"`{p['file']}:{p['line']}`"
        if not SHA.match(p["ref"]):
            findings.append(f"**{p['action']}@{p['ref']}** ({where}) is not pinned to a full commit SHA.")
            continue
        if not p["version"]:
            findings.append(f"**{p['action']}** ({where}) has no `# vX.Y.Z` comment, so its advisories cannot be looked up.")
            continue
        key = (p["repo"], p["version"])
        if key not in cache:
            cache[key] = fetch(*key)
        for a in cache[key]:
            ids = ", ".join(x for x in (a.get("ghsa_id"), a.get("cve_id")) if x)
            fixed = sorted({v.get("first_patched_version") or "none" for v in a.get("vulnerabilities") or []
                            if (v.get("package") or {}).get("name", "").lower() == p["repo"].lower()})
            findings.append(f"**{p['repo']} {p['version']}** ({where}): {a.get('summary', '').strip()} "
                            f"[{ids}]({a.get('html_url', '')}), severity {a.get('severity', 'unknown')}, "
                            f"fixed in {', '.join(fixed) or 'unknown'}.")
    return findings


def osv_findings(report):
    """osv-scanner's JSON (`scan source --format json`); a missing or empty file means no package sources."""
    findings = []
    for result in (report or {}).get("results") or []:
        source = (result.get("source") or {}).get("path", "?")
        for pkg in result.get("packages") or []:
            p = pkg.get("package") or {}
            for v in pkg.get("vulnerabilities") or []:
                aliases = ", ".join(v.get("aliases") or [])
                findings.append(f"**{p.get('name')} {p.get('version')}** ({p.get('ecosystem')}, `{source}`): "
                                f"{(v.get('summary') or '').strip()} [{v.get('id')}]"
                                f"(https://osv.dev/vulnerability/{v.get('id')}){f' ({aliases})' if aliases else ''}.")
    return findings


def load_osv(path):
    if not path:
        return None
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return json.loads(text) if text else None


def render(found_pins, actions, packages):
    lines = ["# Security audit", ""]
    if not actions and not packages:
        lines.append(f"No known vulnerabilities: {len(found_pins)} pinned GitHub Actions checked against the GitHub "
                     "Advisory Database; package lockfiles checked with osv-scanner.")
        return "\n".join(lines) + "\n"
    if actions:
        lines += ["## GitHub Actions", ""] + [f"- {f}" for f in actions] + [""]
    if packages:
        lines += ["## Packages", ""] + [f"- {f}" for f in packages] + [""]
    lines.append("Update the affected pin (commit SHA and version comment) or dependency, then run the "
                 "Security audit workflow again.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--osv", help="osv-scanner JSON report")
    ap.add_argument("--report", help="where to write the Markdown report (default: stdout)")
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root).resolve()
    found_pins = pins(root)
    actions = action_findings(found_pins)
    packages = osv_findings(load_osv(args.osv))
    text = render(found_pins, actions, packages)
    if args.report:
        pathlib.Path(args.report).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    print(f"found={'true' if actions or packages else 'false'}")


if __name__ == "__main__":
    main()
