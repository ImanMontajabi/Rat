## Summary

<!-- What changes and why, for a reviewer who has not seen the branch. Link issues with "Closes #N". -->

## Architecture

<!-- Which modules change (RatFilter targets, App/Model, App/Views, Enforcerd, workflows) and how the pieces fit. -->

## Checklist

- [ ] Changelog fragment in `changelog.d/` (`scripts/changelog.py new …`), or the `skip-changelog` label
- [ ] Unit tests for new logic; `xcodebuild -scheme Rat test` and `swift test` (RatFilter) pass
- [ ] UI changes: `scripts/test-ui.sh` passes locally
- [ ] Blocking changes: verified in the real Rat.app (deny list → daemon status → pf anchor → real apps)
- [ ] Never blocks remote addresses in pf; tests never touch real preferences, rules or the helper
