# Contributing

Contributions welcome. These rules are community resources — improvements, new IoCs, false positive corrections, and new campaigns all help defenders.

## What we accept

- New YARA rules for supply chain, CI/CD, and developer tooling threats
- New Sigma rules covering the same scope
- Corrections to existing rules (false positive reduction, regex improvements, field name fixes)
- New IoCs for existing campaigns (additional C2 IPs, workflow names, forged identities)
- SIEM-specific tuning notes in rule comments

## What we don't accept

- Rules targeting end-user malware unrelated to supply chain or developer tooling (plenty of other repos for that)
- Rules with no cited source or observable evidence
- Untested rules — see Testing below

## Rule quality bar

**YARA:**
- Must compile cleanly: `yara -d megalodon-workflow.yar /dev/null` returns 0
- Must have `meta:` block with `description`, `author`, `date`, `reference`
- Regex patterns must be tested against both matching and non-matching fixtures
- No rules that fire on every file (condition must be specific)

**Sigma:**
- Must pass `sigma check` (sigma-cli)
- Must have `id` (UUID4), `status`, `author`, `date`, `references`, `tags`, `level`
- ATT&CK tags required where applicable (`attack.tNNNN`)
- `falsepositives` must be populated — "None" is rarely correct

## Submitting

1. Fork the repo
2. Add your rule(s) under the relevant campaign folder (`yara/<campaign>/` or `sigma/<campaign>/`)
3. For a new campaign, create the folder and add a brief description to `README.md`
4. Open a pull request with a summary of what the rule detects and how you verified it

## Testing

YARA rules must be tested with both positive fixtures (files that should match) and negative fixtures (files that should not). Document the test approach in your PR description.

For Sigma rules, note which SIEM/backend you validated against.
