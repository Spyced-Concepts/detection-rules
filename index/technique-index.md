---
title: ATT&CK Technique Index
author: "Spyced Concepts Ltd., AI-assisted by Claude Sonnet 4.6"
created: 2026-05-30
updated: 2026-05-30
license: Apache-2.0
---

# ATT&CK Technique Index

Detection rules in this repository, organised by MITRE ATT&CK technique.

For machine-readable data see [`technique-index.json`](technique-index.json) — schema at [`../schemas/detection-index.schema.json`](../schemas/detection-index.schema.json).

---

## Techniques Covered

| Technique ID | Name | Tactic | Campaigns | YARA | Sigma |
|---|---|---|---|---|---|
| [T1059.004](#t1059004) | Command and Scripting Interpreter: Unix Shell | Execution | megalodon | 1 | 1 |
| [T1071.001](#t1071001) | Application Layer Protocol: Web Protocols | Command & Control | megalodon | 1 | 1 |
| [T1195.002](#t1195002) | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access | megalodon | 1 | 2 |
| [T1078.004](#t1078004) | Valid Accounts: Cloud Accounts | Defence Evasion | megalodon | 0 | 1 |
| [T1552](#t1552) | Unsecured Credentials | Credential Access | megalodon | 1 | 1 |

---

## T1059.004

**Command and Scripting Interpreter: Unix Shell** · Tactic: Execution

Megalodon's targeted variant delivers its payload as a base64-encoded string piped to `bash`, executing arbitrary commands on the CI runner host.

| Rule | Format | File |
|---|---|---|
| `Megalodon_Base64_Eval_Payload` | YARA | `megalodon/yara/megalodon-workflow.yar` |
| `megalodon-base64-exec-ci-runner` | Sigma | `megalodon/sigma/megalodon-base64-exec-ci-runner.yml` |

---

## T1071.001

**Application Layer Protocol: Web Protocols** · Tactic: Command & Control

Megalodon exfiltrates CI secrets to a hard-coded C2 endpoint at `216.126.225.129:8443` over HTTPS from the CI runner.

| Rule | Format | File |
|---|---|---|
| `Megalodon_Workflow_C2_IP` | YARA | `megalodon/yara/megalodon-workflow.yar` |
| `megalodon-c2-outbound-network` | Sigma | `megalodon/sigma/megalodon-c2-outbound-network.yml` |

---

## T1195.002

**Supply Chain Compromise: Compromise Software Supply Chain** · Tactic: Initial Access

The campaign compromised 5,561+ repositories by using stolen PATs to push malicious workflow files directly to default branches, poisoning CI pipelines across a large number of downstream users.

| Rule | Format | File |
|---|---|---|
| `Megalodon_High_Confidence` | YARA | `megalodon/yara/megalodon-workflow.yar` |
| `megalodon-github-direct-push-workflow` | Sigma | `megalodon/sigma/megalodon-github-direct-push-workflow.yml` |
| `megalodon-workflow-name-ioc` | Sigma | `megalodon/sigma/megalodon-workflow-name-ioc.yml` |

---

## T1078.004

**Valid Accounts: Cloud Accounts** · Tactic: Defence Evasion

Stolen Personal Access Tokens are used as legitimate credentials for the direct-push action, making the initial compromise indistinguishable from a normal authenticated push in basic audit logs.

| Rule | Format | File |
|---|---|---|
| `megalodon-github-direct-push-workflow` | Sigma | `megalodon/sigma/megalodon-github-direct-push-workflow.yml` |

---

## T1552

**Unsecured Credentials** · Tactic: Credential Access

Megalodon's mass variant exploits `pull_request_target` combined with `id-token: write` to expose OIDC tokens and org-level Actions secrets to fork pull requests — configurations that are technically valid but create an unintended credential access surface.

| Rule | Format | File |
|---|---|---|
| `Megalodon_Workflow_Dangerous_Permissions` | YARA | `megalodon/yara/megalodon-workflow.yar` |
| `megalodon-dangerous-workflow-permissions` | Sigma | `megalodon/sigma/megalodon-dangerous-workflow-permissions.yml` |

---

*Published by [Spyced Concepts Ltd.](https://spycedconcepts.co.uk) — Apache 2.0*
