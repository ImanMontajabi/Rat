#!/usr/bin/env python3
"""Changelog fragments for Rat (no dependencies: Python 3.9+ standard library).

Every change adds one small Markdown file to changelog.d/, named <slug>.<type>.md, for example
changelog.d/process-tree.added.md. The slug is the branch's topic (or the PR number). Releases compile the
fragments into CHANGELOG.md.

    scripts/changelog.py new added process-tree "Apps expand into their processes."
    scripts/changelog.py check [--base origin/main]    fragments are valid, and this branch adds one
    scripts/changelog.py render [--version 1.3.0]      print the unreleased notes (nightly builds, previews)
    scripts/changelog.py release 1.3.0                 write them into CHANGELOG.md and delete the fragments
    scripts/changelog.py release 1.3.0 --from-ref origin/release   only the fragments that ref contains
    scripts/changelog.py section 1.3.0                 print one released version's section of CHANGELOG.md
"""
import argparse
import datetime
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRAGMENTS = ROOT / "changelog.d"
CHANGELOG = ROOT / "CHANGELOG.md"
MARKER = "<!-- releases -->"

# Section order in the notes. `internal` covers CI, tests and tooling: listed last, under "Development".
TYPES = {
    "added": "Added",
    "changed": "Changed",
    "fixed": "Fixed",
    "removed": "Removed",
    "security": "Security",
    "internal": "Development",
}
NAME = re.compile(r"^(?P<slug>[a-z0-9][a-z0-9._-]*)\.(?P<type>[a-z]+)\.md$")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
IGNORED = {"README.md", ".gitkeep"}


class Fragment:
    def __init__(self, path):
        self.path = path
        m = NAME.match(path.name)
        self.slug = m and m.group("slug")
        self.type = m and m.group("type")
        self.text = path.read_text(encoding="utf-8").strip()

    def problems(self):
        if not self.slug:
            return [f"{self.path.name}: name must be <slug>.<type>.md"]
        out = []
        if self.type not in TYPES:
            out.append(f"{self.path.name}: type '{self.type}' is not one of {', '.join(TYPES)}")
        if not self.text:
            out.append(f"{self.path.name}: empty")
        if self.text.startswith("#"):
            out.append(f"{self.path.name}: no headings, write the entry itself")
        return out

    def entry(self):
        """The fragment as one list item; continuation lines are indented under it."""
        lines = self.text.splitlines()
        first = re.sub(r"^[-*]\s+", "", lines[0])
        rest = ["  " + l if l.strip() and not l.startswith("  ") else l for l in lines[1:]]
        return "\n".join([f"- {first}"] + rest)


def fragments(only=None):
    """All fragments, or those whose file names are in `only`."""
    if not FRAGMENTS.is_dir():
        return []
    return [Fragment(p) for p in sorted(FRAGMENTS.iterdir())
            if p.is_file() and p.name not in IGNORED and (only is None or p.name in only)]


def render(version=None, date=None, level=2, only=None):
    frags = [f for f in fragments(only) if not f.problems()]
    head = "#" * level
    title = f"{head} [{version}] - {date}" if version else f"{head} Unreleased"
    out = [title, ""]
    if not frags:
        out += ["_No changes recorded yet._", ""]
    for key, label in TYPES.items():
        items = [f.entry() for f in frags if f.type == key]
        if items:
            out += [f"{head}# {label}", ""] + items + [""]
    return "\n".join(out).rstrip() + "\n"


def cmd_new(a):
    if a.type not in TYPES:
        sys.exit(f"type must be one of: {', '.join(TYPES)}")
    if not SLUG.match(a.slug):
        sys.exit("slug: lowercase letters, digits and dashes (the branch topic or PR number)")
    path = FRAGMENTS / f"{a.slug}.{a.type}.md"
    if path.exists():
        sys.exit(f"{path.relative_to(ROOT)} exists already")
    FRAGMENTS.mkdir(exist_ok=True)
    path.write_text((a.text or "Describe the change for users, in one or two sentences.") + "\n", encoding="utf-8")
    print(path.relative_to(ROOT))


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        sys.exit(f"git {' '.join(args)} failed: {e.stderr.strip()}")


def changed_fragments(base):
    """Fragments added or edited since the branch left `base`: commits, uncommitted edits and new files."""
    fork = git("merge-base", base, "HEAD").strip()
    names = git("diff", "--name-only", "--diff-filter=AM", fork, "--", "changelog.d").splitlines()
    names += git("ls-files", "--others", "--exclude-standard", "--", "changelog.d").splitlines()
    return sorted({n for n in names if pathlib.Path(n).name not in IGNORED})


def cmd_check(a):
    problems = [p for f in fragments() for p in f.problems()]
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if problems:
        sys.exit(1)
    if a.base:
        added = changed_fragments(a.base)
        if not added:
            sys.exit(f"error: no changelog fragment added since {a.base}. Add one with\n"
                     f"  scripts/changelog.py new <{'|'.join(TYPES)}> <slug> \"What changed for users\"\n"
                     "or label the PR skip-changelog when nothing changes for anyone.")
        print("fragments: " + ", ".join(added))
    else:
        print(f"{len(fragments())} fragments OK")


def cmd_render(a):
    sys.stdout.write(render(a.version, a.date or datetime.date.today().isoformat(), a.level) if a.version else render(level=a.level))


def section(version):
    text = CHANGELOG.read_text(encoding="utf-8") if CHANGELOG.exists() else ""
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    return m and m.group(0).rstrip() + "\n"


def cmd_section(a):
    s = section(a.version)
    if not s:
        sys.exit(f"CHANGELOG.md has no section for {a.version}")
    sys.stdout.write(s)


def cmd_release(a):
    if section(a.version):
        sys.exit(f"CHANGELOG.md already has a section for {a.version}")
    # After a release, main may already hold fragments merged later: those stay for the next release.
    only = None
    if a.from_ref:
        only = {pathlib.Path(n).name for n in git("ls-tree", "--name-only", a.from_ref, "changelog.d/").splitlines()}
    problems = [p for f in fragments(only) for p in f.problems()]
    if problems:
        sys.exit("\n".join(problems))
    body = render(a.version, a.date or datetime.date.today().isoformat(), only=only)
    text = CHANGELOG.read_text(encoding="utf-8")
    if MARKER not in text:
        sys.exit(f"CHANGELOG.md lacks the {MARKER} line")
    CHANGELOG.write_text(text.replace(MARKER, f"{MARKER}\n\n{body.rstrip()}", 1), encoding="utf-8")
    for f in fragments(only):
        f.path.unlink()
    sys.stdout.write(body)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new", help="create a fragment")
    n.add_argument("type", choices=list(TYPES))
    n.add_argument("slug")
    n.add_argument("text", nargs="?")
    n.set_defaults(func=cmd_new)
    c = sub.add_parser("check", help="validate fragments; with --base, require one added on this branch")
    c.add_argument("--base")
    c.set_defaults(func=cmd_check)
    r = sub.add_parser("render", help="print the unreleased notes")
    r.add_argument("--version")
    r.add_argument("--date")
    r.add_argument("--level", type=int, default=2)
    r.set_defaults(func=cmd_render)
    s = sub.add_parser("section", help="print a released version's section")
    s.add_argument("version")
    s.set_defaults(func=cmd_section)
    rel = sub.add_parser("release", help="compile fragments into CHANGELOG.md and delete them")
    rel.add_argument("version")
    rel.add_argument("--date")
    rel.add_argument("--from-ref", help="compile only the fragments present in this git ref")
    rel.set_defaults(func=cmd_release)
    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
