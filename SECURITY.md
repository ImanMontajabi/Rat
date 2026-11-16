# Security Policy

Rat installs an optional root helper (`rat-enforcerd`) that controls the packet filter, so security reports are
taken seriously and handled privately.

## Supported versions

| Version | Supported |
|---|---|
| The latest stable release (`release` branch, newest `vX.Y.Z` tag) | ✅ |
| Nightly pre-releases from `main` | ✅ (fixes land here first) |
| Older releases | ❌ (update to the latest release) |

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub: open the repository's **Security** tab and choose
**[Report a vulnerability](https://github.com/ImanMontajabi/Rat/security/advisories/new)**. Only the maintainer
can see the report.

Please include:

- the Rat version (Finder > Get Info on `/Applications/Rat.app`) and the macOS version;
- whether the firewall helper is installed, and its state (`scripts/rat-status.sh`);
- the steps to reproduce, what you expected and what happened;
- the impact as you understand it (for example: a local user gaining root through the helper, a denied app
  reaching the network, data readable by another user).

Reports are acknowledged as soon as possible, and you will be kept informed while a fix is prepared. Once a fixed
release is published, the advisory is made public and you are credited, unless you prefer not to be.

## Scope

In scope:

- `rat-enforcerd` and the root LaunchDaemons it is installed with (`com.imanmontajabi.rat.pf` and
  `com.imanmontajabi.rat.sampler`): privilege escalation, files it reads or writes, the pf anchor `com.apple/rat`;
- the files Rat hands the helper (`denied-apps.txt`, `denied-ports.txt`, `deny-rules.json`) and the ones the
  helper publishes under `/var/run`;
- a deny rule that is shown as enforced but lets the app's traffic through;
- parsing of untrusted input: GeoIP databases (`.mmdb`), imported rule files, proxy handshakes read on `lo0`;
- the release pipeline: workflows, pinned Actions and the published DMG.

Out of scope:

- limits Rat documents itself: without a Network Extension it reacts to connections after they start and never
  blocks remote addresses (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), sections 7–8);
- the monitor without the helper, which observes but does not enforce;
- vulnerabilities in macOS, Xcode or third-party apps, unless Rat makes them reachable.

## Supply chain

GitHub Actions are pinned to full commit SHAs, and `scripts/security-audit.py` checks them against the GitHub
Advisory Database every week and on every PR that changes dependencies or workflows. Bundled third-party data
(DB-IP Lite databases, the flag-icons artwork) is listed with its licence in the README.
