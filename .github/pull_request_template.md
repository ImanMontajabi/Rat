## Summary

<!-- What changes and why, for a reviewer who has not seen the branch. Link issues with "Closes #N". -->

## Architecture

<!-- Which modules change (RatFilter targets, App/Model, App/Views, Enforcerd, workflows) and how the pieces fit. -->

## Checklist

- [ ] Changelog fragment in `changelog.d/` (`scripts/changelog.py new …`), or the `skip-changelog` label
- [ ] Unit tests for new logic; `xcodebuild -scheme Rat test` and `swift test` (RatFilter) pass (counts: …)
- [ ] UI changes: `scripts/test-ui.sh` passes locally
- [ ] Live verification in the installed Release build and helper (what was observed: …); blocking changes: deny list → daemon status → pf anchor → real apps
- [ ] No regressions: the full suites pass, nothing newly skipped
- [ ] Resources (`scripts/measure-resources.sh 60`, before → after): Rat.app CPU …% / RSS … MB, rat-enforcerd CPU …% / RSS … MB
- [ ] Never blocks remote addresses in pf; tests never touch real preferences, rules or the helper
