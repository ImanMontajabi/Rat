# Changelog fragments

Every pull request adds one file here describing its change for users. Releases compile the files into
[`CHANGELOG.md`](../CHANGELOG.md) and delete them; nightly pre-releases show them as a preview.

**Name:** `<slug>.<type>.md`. The slug is the branch topic (`feat/process-tree` → `process-tree`) or the PR
number. Types, in the order the notes list them:

| type | section | for |
|---|---|---|
| `added` | Added | new features |
| `changed` | Changed | changed behaviour |
| `fixed` | Fixed | bug fixes |
| `removed` | Removed | removed features |
| `security` | Security | anything that changes what Rat blocks or exposes |
| `internal` | Development | CI, tests, tooling: nothing users see |

**Content:** the entry itself, in plain Markdown, one or two sentences, no heading. Further lines become an
indented continuation of the same list item.

```sh
scripts/changelog.py new added process-tree "Apps expand into their processes and each process into its connections."
scripts/changelog.py check --base origin/main   # what CI runs on every PR
scripts/changelog.py render                     # preview the unreleased notes
```

A PR that changes nothing for anyone (a typo, a CI retry) can carry the `skip-changelog` label instead.
