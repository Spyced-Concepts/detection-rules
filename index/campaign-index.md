---
title: Campaign Index
author: Spyced Concepts Ltd.
created: 2026-05-30
updated: 2026-05-30
license: Apache-2.0
---

# Campaign Index

Detection rules published in this repository, organised by threat campaign.

For machine-readable data see [`campaign-index.json`](campaign-index.json) — schema at [`../schemas/detection-index.schema.json`](../schemas/detection-index.schema.json).

---

## Active Campaigns

| Campaign | First Seen | Added | Severity | Techniques | YARA Rules | Sigma Rules | Notes |
|---|---|---|---|---|---|---|---|
| [Megalodon](#megalodon) | 2026-05-18 | 2026-05-30 | CRITICAL | T1059.004, T1071.001, T1195.002, T1078.004, T1552 | 7 | 5 | No prior community rules at publication |

---

## Megalodon

**Mass GitHub CI workflow backdoor** — stolen PATs used to push malicious workflow files directly to default branches, bypassing PR review. 5,561 repositories affected.

**Variants:**
- `SysDiag.yml` — mass variant; abuses `pull_request_target` + `id-token: write` to expose OIDC tokens and org secrets to fork PRs
- `Optimize-Build.yml` — targeted variant; uses `workflow_dispatch`; exfiltrates CI secrets via base64-encoded bash payload to C2 at `216.126.225.129:8443`

**ATT&CK techniques:** T1059.004 · T1071.001 · T1195.002 · T1078.004 · T1552

**Folder:** `megalodon/`

### YARA rules — `megalodon/yara/megalodon-workflow.yar`

| Rule | Severity | Detects |
|---|---|---|
| `Megalodon_Workflow_C2_IP` | CRITICAL | C2 IP `216.126.225.129` hardcoded in workflow files |
| `Megalodon_Workflow_Names` | HIGH | Malicious workflow filenames: `SysDiag`, `Optimize-Build` |
| `Megalodon_Forged_Author_Email` | HIGH | Forged git author emails and bot identity strings |
| `Megalodon_Workflow_Dangerous_Permissions` | HIGH | `pull_request_target` + `id-token: write` combination |
| `Megalodon_Base64_Eval_Payload` | CRITICAL | Base64-decode-pipe-to-bash payload delivery |
| `Megalodon_Workflow_Dispatch_Backdoor` | MEDIUM | `workflow_dispatch` + C2 IoCs together |
| `Megalodon_High_Confidence` | CRITICAL | Multiple corroborating IoCs — high-confidence composite |

### Sigma rules — `megalodon/sigma/`

| Rule file | Log source | Level | Detects |
|---|---|---|---|
| `megalodon-github-direct-push-workflow.yml` | GitHub audit | HIGH | Direct push to `.github/workflows/` without PR |
| `megalodon-workflow-name-ioc.yml` | GitHub audit | CRITICAL | Creation of `SysDiag.yml` or `Optimize-Build.yml` |
| `megalodon-c2-outbound-network.yml` | Network (Linux) | CRITICAL | Outbound to `216.126.225.129:8443` from CI runner |
| `megalodon-base64-exec-ci-runner.yml` | Process creation (Linux) | HIGH | `base64` piped to `bash`/`sh` on CI runner |
| `megalodon-dangerous-workflow-permissions.yml` | GitHub audit | MEDIUM | Workflow file flagged for dangerous permission combination |

**Sources:**
- SafeDep.io: [Megalodon — Mass GitHub Repo Backdooring CI Workflows](https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/)

**Notes:** No CVEs — the attack exploits legitimate PAT access and GitHub platform features, not software vulnerabilities. No community rules existed at time of publication (2026-05-30).

---

## Archived Campaigns

*(none)*

---

*Published by [Spyced Concepts Ltd.](https://spycedconcepts.co.uk) — Apache 2.0*
