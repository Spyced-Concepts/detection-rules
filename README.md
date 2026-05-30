---
title: detection-rules
author: Spyced Concepts Ltd.
created: 2026-05-30
updated: 2026-05-30
license: Apache-2.0
---

# detection-rules

Detection rules for supply chain, CI/CD, and developer tooling threats — YARA and Sigma.

Published by [Spyced Concepts Ltd.](https://spycedconcepts.co.uk) — a UK security software company. Rules are researched, written, and tested internally before publication. Use them freely under the Apache 2.0 licence.

---

## Indexes

The `index/` folder provides human-readable and machine-readable indexes of every rule in this repository. Start here.

| Index | Markdown | JSON | Description |
|---|---|---|---|
| Campaign index | [`index/campaign-index.md`](index/campaign-index.md) | [`index/campaign-index.json`](index/campaign-index.json) | Rules organised by threat campaign |
| CVE index | [`index/cve-index.md`](index/cve-index.md) | [`index/cve-index.json`](index/cve-index.json) | Rules organised by CVE identifier |
| ATT&CK technique index | [`index/technique-index.md`](index/technique-index.md) | [`index/technique-index.json`](index/technique-index.json) | Rules organised by MITRE ATT&CK technique |

The JSON indexes conform to the schema at [`schemas/detection-index.schema.json`](schemas/detection-index.schema.json). The schema is versioned — breaking changes increment the major version.

---

## Rules

| Path | Format | Coverage |
|---|---|---|
| `megalodon/yara/` | YARA | Megalodon GitHub CI backdoor campaign (2026-05-18) |
| `megalodon/sigma/` | Sigma | Megalodon GitHub CI backdoor campaign (2026-05-18) |

---

## Megalodon

**Campaign:** Mass GitHub CI workflow backdoor — 5,561 repositories compromised using stolen Personal Access Tokens (PATs) to push malicious workflow files directly to repository default branches, bypassing PR review.

**Attack variants:**
- `SysDiag.yml` — mass variant; uses `pull_request_target` + `id-token: write` to grant fork PRs access to OIDC tokens and secrets
- `Optimize-Build.yml` — targeted variant; triggered via `workflow_dispatch`; exfiltrates CI secrets to C2 at `216.126.225.129:8443` via a base64-encoded bash payload

**Primary defence:** Require pull requests for all pushes to protected branches (GitHub branch ruleset with `pull_request` rule, no bypass actors). This blocks the stolen-PAT direct-push vector entirely.

**Sources:**
- SafeDep.io: [Megalodon — Mass GitHub Repo Backdooring CI Workflows](https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/)
- Phoenix Security: no existing scanner signatures at time of writing (2026-05-30) — these rules fill that gap

### YARA rules (`megalodon/yara/megalodon-workflow.yar`)

| Rule | Severity | What it detects |
|---|---|---|
| `Megalodon_Workflow_C2_IP` | CRITICAL | C2 IP address `216.126.225.129` in workflow files |
| `Megalodon_Workflow_Names` | HIGH | Known malicious workflow names: `SysDiag`, `Optimize-Build` |
| `Megalodon_Forged_Author_Email` | HIGH | Forged git author emails and bot identity names used by the campaign |
| `Megalodon_Workflow_Dangerous_Permissions` | HIGH | `pull_request_target` + `id-token: write` — the mass-variant permission combination |
| `Megalodon_Base64_Eval_Payload` | CRITICAL | Base64-decode-pipe-to-bash payload delivery pattern |
| `Megalodon_Workflow_Dispatch_Backdoor` | MEDIUM | `workflow_dispatch` combined with C2 IoCs (targeted variant) |
| `Megalodon_High_Confidence` | CRITICAL | Multiple corroborating IoCs — high-confidence match |

**Usage:**
```bash
# Scan a repo's workflow directory
yara -r megalodon/yara/megalodon-workflow.yar /path/to/repo/.github/workflows/

# Scan all local clones
yara -r megalodon/yara/megalodon-workflow.yar ~/Projects/
```

### Sigma rules (`megalodon/sigma/`)

| Rule file | Log source | Level | What it detects |
|---|---|---|---|
| `megalodon-github-direct-push-workflow.yml` | GitHub audit | High | Direct push to workflow dir without a pull request |
| `megalodon-workflow-name-ioc.yml` | GitHub audit | Critical | Creation of SysDiag or Optimize-Build workflow files |
| `megalodon-c2-outbound-network.yml` | Network (Linux) | Critical | Outbound connection to `216.126.225.129:8443` from CI runner |
| `megalodon-base64-exec-ci-runner.yml` | Process creation (Linux) | High | Base64-decode piped to bash/sh on CI runner host |
| `megalodon-dangerous-workflow-permissions.yml` | GitHub audit | Medium | Workflow push flagged for content review |

**Convert to your SIEM with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):**
```bash
sigma convert -t splunk megalodon/sigma/
sigma convert -t elasticsearch megalodon/sigma/
sigma convert -t sentinel megalodon/sigma/
```

---

## Licence

Apache 2.0 — see [LICENSE](LICENSE).

## Contact

[stuart@spycedconcepts.co.uk](mailto:stuart@spycedconcepts.co.uk)

---

*Copyright 2026 Spyced Concepts Ltd. (company number 16978283) · Licensed under [Apache-2.0](LICENSE)*
