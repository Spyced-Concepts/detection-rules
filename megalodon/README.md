---
title: Megalodon — Campaign Detection Package
author: "Spyced Concepts Ltd., AI-assisted by Claude Sonnet 4.6"
created: 2026-05-30
updated: 2026-05-30
license: Apache-2.0
---

# Megalodon — Campaign Detection Package

YARA and Sigma detection rules for the Megalodon GitHub Actions supply-chain backdoor campaign (May 2026). Published by Spyced Concepts Ltd. under Apache 2.0.

## Campaign Summary

Megalodon compromised 5,561 GitHub repositories by pushing malicious workflow files using stolen Personal Access Tokens. Two variants were observed:

| Variant | Trigger | Filename | Purpose |
|---|---|---|---|
| Mass | `pull_request_target` + `id-token: write` | `SysDiag.yml` | Exfiltrate OIDC tokens from any contributor's fork PR |
| Targeted | `workflow_dispatch` | `Optimize-Build.yml` | Manual-trigger exfiltration of CI secrets |

Both variants deliver a base64-encoded bash payload that exfiltrates secrets to the C2 server at `216.126.225.129:8443`.

## Intelligence Sources

All IoC data used in these rules was sourced from original threat research by **SafeDep.io**:

> SafeDep.io, *"Megalodon: Mass GitHub Repository Backdooring via CI Workflows"*, 2026  
> https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/

The detection rule logic — YARA conditions, Sigma detection blocks, test fixtures, and reliability scoring methodology — is original work by Spyced Concepts Ltd., AI-assisted by Claude Sonnet 4.6.

SafeDep.io is cited in the `reference` field of every rule in this package. We are grateful for their research making these rules possible.

## Attribution and Notification Policy

We believe in transparent, good-faith threat intelligence sharing. When this package is published (blog post, social media, YARA community submissions):

1. **SafeDep.io are notified directly** — emailed or contacted via social/GitHub, credited as the source of the intelligence, and given the opportunity to review, link back, or raise any concerns before or after publication.
2. **All community submission PRs** (Neo23x0/signature-base, Elastic detection-rules) include an explicit statement in the PR description that IoC intelligence derives from SafeDep.io's original research, with a direct link.
3. **If a credited source is unhappy** with how their work is referenced, we will discuss with them and adapt the attribution or, if they request it, remove the content. Take-down requests go to [spycedconcepts.co.uk/contact](https://spycedconcepts.co.uk/contact).

The intent is that everyone knows what was done and why. The security community benefits from shared detection capability; SafeDep.io's research made that possible here.

## Rules Included

### YARA (`yara/megalodon-workflow.yar`)

Apply to `.github/workflows/` files across repositories.

| Rule | Severity | ATT&CK | Precision | Recall | F1 | Notes |
|---|---|---|---|---|---|---|
| `Megalodon_Workflow_C2_IP` | CRITICAL | T1071.001 | 100% | 100% | 1.00 | C2 IP IoC — highest confidence |
| `Megalodon_Workflow_Names` | HIGH | T1036.005 | 100% | 100% | 1.00 | Workflow name IoCs |
| `Megalodon_Forged_Author_Email` | HIGH | T1036 | 100% | 100% | 1.00 | Commit author email IoCs — apply to git log output |
| `Megalodon_Workflow_Dangerous_Permissions` | HIGH | T1078.004, T1552 | 66.7% | 100% | 0.80 | **Triage signal only** — 1 confirmed real-world FP; correlate before acting |
| `Megalodon_Base64_Eval_Payload` | CRITICAL | T1059.004, T1027 | 100% | 100% | 1.00 | Base64 payload delivery pattern |
| `Megalodon_Workflow_Dispatch_Backdoor` | MEDIUM | T1195.002 | 100% | 100% | 1.00 | Targeted variant (Optimize-Build) |
| `Megalodon_High_Confidence` | CRITICAL | T1195.002, T1071.001, T1059.004 | 100% | 100% | 1.00 | Multi-IoC corroboration rule |

Tested 2026-05-30 — 16 fixtures (7 positive, 9 negative). Score report: `../tests/megalodon/results/2026-05-30-score.txt`

### Sigma (`sigma/`)

| File | Severity | Log Source | Notes |
|---|---|---|---|
| `megalodon-c2-outbound-network.yml` | CRITICAL | Network connection (Linux) | Post-exploitation indicator; most reliable signal |
| `megalodon-base64-exec-ci-runner.yml` | HIGH | Process creation (Linux) | Self-hosted runners only |
| `megalodon-dangerous-workflow-permissions.yml` | HIGH | GitHub Audit Log | Triage signal; pair with YARA content scan |
| `megalodon-github-direct-push-workflow.yml` | HIGH | GitHub Audit Log | Direct push without PR — primary delivery vector |
| `megalodon-workflow-name-ioc.yml` | CRITICAL | GitHub Audit Log | Known malicious workflow filenames |

Sigma rules pass `sigma check` linting. Fixture-based FP/FN scoring for Sigma is not yet implemented — see `../../TESTING.md`.

## Usage

```bash
# YARA — scan all workflow files in a repository (Docker, recommended)
docker run --rm -v $(pwd):/rules:ro detection-rules-test \
  yara /rules/megalodon/yara/megalodon-workflow.yar \
  /rules/tests/megalodon/fixtures/

# YARA — scan a live repository
yara -r megalodon/yara/megalodon-workflow.yar /path/to/repo/.github/workflows/

# Sigma — convert to your SIEM format
sigma convert -t splunk megalodon/sigma/megalodon-c2-outbound-network.yml
sigma convert -t elastic-dsl megalodon/sigma/megalodon-base64-exec-ci-runner.yml
```

## TLP

All rules in this package are **TLP:CLEAR** — approved for unrestricted public redistribution.

---

Copyright 2026 Spyced Concepts Ltd. (company number 16978283)  
Licensed under the Apache License, Version 2.0 — SPDX-License-Identifier: Apache-2.0
