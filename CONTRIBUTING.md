# Contributing

This repository is maintained by [Spyced Concepts Ltd.](https://spycedconcepts.co.uk)

**This is a publication point, not a community hub.** Rules are researched, written, tested, and reviewed internally. Contributions from the general public are not accepted.

If you find an error in a published rule — false positive, incorrect IoC, logic fault — contact us via the [Spyced Concepts contact form](https://spycedconcepts.co.uk/contact) and we will address it in the next publication cycle.

---

## For authorised contributors

This section covers how Spyced Concepts team members work with this repository. If you have been granted write access, follow these standards exactly.

### Branch workflow

All changes flow through a pull request. Direct push to `main` is blocked. Every branch must be reviewed before merge.

| Prefix | Use for | Example |
|---|---|---|
| `rules/<campaign>` | New rules for a named campaign | `rules/megalodon` |
| `update/<campaign>` | IoC updates, detection improvements to existing rules | `update/megalodon-c2-ips` |
| `fix/<rule>` | False positive corrections, logic fixes | `fix/megalodon-base64-fp` |
| `test/<campaign>` | Test fixture development before rule publication | `test/megalodon-fixtures` |
| `chore/<description>` | Repository maintenance, documentation, CI changes | `chore/update-readme` |

Never branch from another feature branch. Always branch from `main`.

### Commit standards

One logical change per commit. Commit messages follow this format:

```
<type>(<scope>): <imperative summary>

<optional body: why, not what>
```

Types: `rule` · `fix` · `test` · `docs` · `ci` · `chore`

Scope is the campaign or component: `megalodon` · `index` · `schema` · `ci` · `readme`

Examples:
```
rule(megalodon): add C2 IP YARA rule for 216.126.225.129
fix(megalodon): narrow base64 rule to avoid bash false positives
test(megalodon): add negative fixtures for common CI patterns
docs(index): update campaign-index with megalodon technique coverage
```

### Rule quality requirements

A rule is not ready to merge until all of the following are true:

**YARA rules:**
- Compile without error: `yara <file.yar> /dev/null`
- Tested against positive fixtures — at least one sample that the rule must match
- Tested against negative fixtures — common benign files the rule must not match
- False positive rate assessed and documented in the rule's `meta` block
- IoCs sourced and referenced in the `meta.reference` field

**Sigma rules:**
- Validate without error: `sigma check <file.yml>`
- All required fields present: `id` (UUID4) · `status` · `author` · `date` · `references` · `tags` (ATT&CK) · `level` · `falsepositives` · `logsource` · `detection`
- `status: test` until the rule has been validated against real log data; promote to `status: stable` once confirmed
- `falsepositives` field is honest — list known benign triggers, not just `None`

See [`TESTING.md`](TESTING.md) for the full testing procedure.

### Index maintenance

Every rule publication must update the indexes in `index/`. Do not merge a `rules/` PR without updating:

- `index/campaign-index.json` and `index/campaign-index.md` — add or update the campaign entry
- `index/technique-index.json` and `index/technique-index.md` — add technique entries for each ATT&CK technique the new rules cover
- `index/cve-index.json` and `index/cve-index.md` — add CVE entries if the campaign exploits a specific CVE

The JSON indexes must validate against the schema at `schemas/detection-index.schema.json`.

### Folder structure

Rules are organised campaign-first:

```
<campaign>/
├── yara/
│   └── <campaign>-<subject>.yar
└── sigma/
    └── <campaign>-<subject>.yml
```

One `.yar` file per campaign is the default — use multiple files only when rules have meaningfully different log sources or are intended to be deployed independently.

### Pull request process

1. Create a branch from `main` using the prefix table above
2. Write rules following the quality requirements
3. Run `yara <file.yar> /dev/null` and `sigma check` — fix all errors before opening PR
4. Update all three indexes
5. Open a draft PR
6. ReviewSentry will automatically review the PR — address all HIGH and CRITICAL findings
7. Mark PR ready for review once ReviewSentry is satisfied
8. A maintainer will merge

### What we do not accept

- External pull requests from contributors who have not been specifically invited
- Rules based on unverified threat intelligence
- Rules without tested positive and negative fixtures
- IoCs without a cited source
- Changes to `schemas/` without a version increment
- GitHub Issues — issues are not enabled on this repository; use the [contact form](https://spycedconcepts.co.uk/contact) to report errors

---

## Using published rules

All rules are published under the Apache 2.0 licence. Use them freely in your own tools, SIEM configurations, or security workflows. Attribution is appreciated but not required by the licence.
