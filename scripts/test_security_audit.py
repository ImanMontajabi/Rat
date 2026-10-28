"""Offline tests of scripts/security-audit.py: python3 -I -m unittest discover -s scripts -p 'test_*.py'"""
import importlib.util
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("audit", pathlib.Path(__file__).with_name("security-audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
WORKFLOW = f"""
jobs:
  build:
    steps:
      - uses: actions/checkout@{SHA} # v7.0.1
      - uses: ./.github/actions/setup-macos
      - name: unpinned
        uses: some/action@v2
      - uses: github/codeql-action/upload-sarif@{SHA}
      - uses: docker://alpine:3
"""


class SecurityAuditTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        (self.root / ".github" / "workflows").mkdir(parents=True)
        (self.root / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW, encoding="utf-8")

    def tearDown(self):
        self.dir.cleanup()

    def test_pins_skip_local_and_docker_actions(self):
        p = audit.pins(self.root)
        self.assertEqual([x["action"] for x in p], ["actions/checkout", "some/action", "github/codeql-action/upload-sarif"])
        self.assertEqual(p[0]["version"], "7.0.1")
        self.assertEqual(p[0]["line"], 5)
        self.assertEqual(p[2]["repo"], "github/codeql-action")

    def test_unpinned_and_unversioned_actions_are_findings(self):
        found = audit.action_findings(audit.pins(self.root), fetch=lambda repo, version: [])
        self.assertEqual(len(found), 2)
        self.assertIn("some/action@v2", found[0])
        self.assertIn("not pinned", found[0])
        self.assertIn("no `# vX.Y.Z` comment", found[1])

    def test_advisories_are_reported_once_per_version(self):
        calls = []
        advisory = {"ghsa_id": "GHSA-xxxx-yyyy-zzzz", "cve_id": "CVE-2026-0001", "summary": "Token leak",
                    "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz", "severity": "high",
                    "vulnerabilities": [{"package": {"name": "actions/checkout"}, "first_patched_version": "7.0.2"}]}
        def fetch(repo, version):
            calls.append((repo, version))
            return [advisory] if repo == "actions/checkout" else []
        pins = [p for p in audit.pins(self.root) if p["repo"] == "actions/checkout"] * 2
        found = audit.action_findings(pins, fetch=fetch)
        self.assertEqual(calls, [("actions/checkout", "7.0.1")])
        self.assertEqual(len(found), 2)
        self.assertIn("CVE-2026-0001", found[0])
        self.assertIn("fixed in 7.0.2", found[0])

    def test_osv_report(self):
        report = {"results": [{"source": {"path": "/r/Package.resolved"}, "packages": [{
            "package": {"name": "swift-nio", "version": "2.0.0", "ecosystem": "SwiftURL"},
            "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-0002"], "summary": "Crash"}]}]}]}
        found = audit.osv_findings(report)
        self.assertEqual(len(found), 1)
        self.assertIn("swift-nio 2.0.0", found[0])
        self.assertIn("CVE-2026-0002", found[0])
        self.assertEqual(audit.osv_findings(None), [], "no package sources")
        self.assertIsNone(audit.load_osv(str(self.root / "missing.json")))
        empty = self.root / "empty.json"
        empty.write_text("", encoding="utf-8")
        self.assertIsNone(audit.load_osv(str(empty)))

    def test_clean_report(self):
        text = audit.render([{}] * 3, [], [])
        self.assertIn("No known vulnerabilities: 3 pinned GitHub Actions", text)
        self.assertIn("## Packages", audit.render([], [], ["x"]))


if __name__ == "__main__":
    unittest.main()
