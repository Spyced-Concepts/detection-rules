# Testing Detection Rules

**All YARA testing MUST run inside an isolated container. Running YARA directly on a development machine is not permitted.**

The isolation requirement is not a preference — it is the safety control. The test container is stood up, used, and torn down for each test run. Nothing from the test environment persists on the host after the container exits.

---

## Why isolation is mandatory

YARA scans byte patterns in files. For current fixtures (GitHub Actions YAML — plain text), the risk of direct host execution is low. The mandatory isolation rule exists because:

1. **Future fixtures may not be text files.** If we ever test rules against binary samples, kernel exploits, or packed payloads, a container breach could escalate to host compromise. Establishing the isolation requirement now means it is already in place when the risk increases.
2. **Consistent, reproducible environment.** The container pins the YARA version. Results on macOS, Linux, and Windows CI are identical.
3. **Stand-up and tear-down are the control.** The container is created from a known-good image and destroyed after use. No test artefacts remain on the host.

**VM vs Docker:** Docker shares the host kernel — a kernel-level exploit could escape the container. A VM runs its own kernel and provides stronger isolation. For the current campaign (YAML text fixtures), Docker is appropriate. If the repository ever covers binary malware samples, switch to a VM with a pre-scan snapshot, no network adapter, and no shared folders. This document must be updated before that happens.

---

## Setup — build the test container

Build once per machine. Rebuild only when the YARA or Python version needs updating.

```bash
docker build -t detection-rules-yara tests/
```

This produces a minimal Ubuntu 24.04 container with YARA and Python 3. Nothing is installed on the host. The image is local only — it is never pushed to a registry.

---

## Run tests

All commands below mount the repository root into the container as **read-only**. The container cannot write back to the host.

### Compile check

```bash
docker run --rm -v "$(pwd)":/rules:ro detection-rules-yara \
  yara megalodon/yara/megalodon-workflow.yar /dev/null
```

A clean return (exit 0, no output) means the rule compiles. The CI pipeline runs this automatically on every PR.

### Positive fixture test — all must match

```bash
docker run --rm -v "$(pwd)":/rules:ro detection-rules-yara \
  yara megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/positive/
```

Every file in `positive/` must produce at least one rule match. Any file with no output is a false negative — the rule must be revised.

### Negative fixture test — zero matches expected

```bash
docker run --rm -v "$(pwd)":/rules:ro detection-rules-yara \
  yara megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/negative/
```

Any output from this command is a false positive — a benign file incorrectly matched. Every false positive must be resolved before merging.

### Full score — precision, recall, F1

```bash
docker run --rm -v "$(pwd)":/rules:ro detection-rules-yara \
  python3 tests/run-tests.py tests/megalodon/test-manifest.json
```

Reports TP/FP/FN/TN per rule plus precision, recall, and F1. Exits with code 1 if any rule has `FP > 0` or `FN > 0`.

| Metric | Definition | Required to publish |
|---|---|---|
| **TP** | Positive fixture correctly matched | All positive fixtures must match |
| **FP** | Negative fixture incorrectly matched | **0** |
| **FN** | Positive fixture failed to match | **0** |
| **TN** | Negative fixture correctly not matched | — |
| **Precision** | TP ÷ (TP + FP) | **100%** |
| **Recall** | TP ÷ (TP + FN) | **100%** |
| **F1** | Harmonic mean | **1.00** |

### Tear down

The `--rm` flag on every `docker run` command destroys the container automatically when it exits. No manual cleanup is needed. To also remove the image:

```bash
docker rmi detection-rules-yara
```

---

## Test manifest

Each campaign has `tests/<campaign>/test-manifest.json` declaring:
- `rules_file` — YARA file path (relative to repo root)
- `all_rules` — all rule names in the file (required to count TN correctly)
- `fixtures` — array of specs; `expected_rules` is empty for negative fixtures
- `false_positive_risk` — optional flag on high-risk negative fixtures

Update the manifest whenever rules or fixtures change.

### False positive risk fixtures

Negative fixtures marked `"false_positive_risk": "HIGH"` are legitimate real-world patterns that closely resemble the IoC. If these trigger a rule, it is a confirmed real-world false positive. Document it in the rule's `meta` block and advise operators on suppression.

Example: `Megalodon_Workflow_Dangerous_Permissions` detects `pull_request_target` + `id-token: write`. This combination is also used by legitimate PR-triggered OIDC deployments. The `benign-prt-with-oidc.yml` fixture confirms whether this is a real-world FP.

### Recording results in rule meta

After a clean run, record the outcome in each rule's `meta` block:

```yara
meta:
    tested              = "2026-05-30"
    positive_fixtures   = "7"
    negative_fixtures   = "9"
    false_positives     = "0 in test set — see tests/megalodon/test-manifest.json"
    precision           = "100%"
    recall              = "100%"
    f1                  = "1.00"
```

---

## Fixture organisation

```
tests/
├── Dockerfile                        # Test container definition (YARA + Python 3)
├── run-tests.py                      # Scoring script (campaign-agnostic)
└── <campaign>/
    ├── test-manifest.json            # Declares expected matches per fixture
    └── fixtures/
        ├── positive/                 # Files the rules must match
        └── negative/                 # Files the rules must not match
```

**Fixture rules:**
- Synthetic text fixtures only — contain only the specific IoC string, not a working exploit
- Comment at top of each file explaining what it tests and why it is safe
- Never commit real malware samples

---

## Validating rules against external malware databases

For validation beyond synthetic fixtures, these services scan rules against real samples without local handling:

- **YARA Scan Service (abuse.ch):** Upload the rule; the service scans it against known malware. Your rule is the input — no sample upload required.
- **Intezer YARA Playground:** Client-side, browser-based. Rule and sample stay local.

Do not upload rules containing unpublished IoCs or internal indicators to third-party services.

---

## Sigma testing

Sigma linting does not scan potentially malicious files — `sigma check` validates rule syntax only. Local execution is acceptable.

### Lint check (automated in CI)

```bash
pip install sigma-cli
sigma check megalodon/sigma/megalodon-github-direct-push-workflow.yml
```

### Required fields

Every Sigma rule must include all of these fields before promotion from `status: test` to `status: stable`:

| Field | Requirement |
|---|---|
| `id` | UUID4 — `python3 -c "import uuid; print(uuid.uuid4())"` |
| `status` | `test` on first publish; `stable` once validated against live log data |
| `author` | Author name or team |
| `date` | ISO 8601 date (`YYYY-MM-DD`) |
| `references` | At least one external source |
| `tags` | At least one ATT&CK tag (`attack.t1234` format) |
| `level` | `critical` / `high` / `medium` / `low` / `informational` |
| `falsepositives` | Honest list of known benign triggers |
| `logsource` | Product, category, and/or service |
| `detection` | Selection and filter conditions |

### SIEM backend validation

Convert to at least one SIEM target before publishing:

```bash
sigma convert -t splunk megalodon/sigma/megalodon-github-direct-push-workflow.yml
sigma convert -t elasticsearch megalodon/sigma/megalodon-github-direct-push-workflow.yml
sigma convert -t sentinel megalodon/sigma/megalodon-github-direct-push-workflow.yml
```

---

## Other rule formats — future consideration

| Format | Use case | Status |
|---|---|---|
| **Suricata** | Network IDS/IPS — complements Sigma network rules with inline enforcement | Planned |
| **STIX 2.1** | Structured threat intel sharing — IoC bundles for threat intel platforms | Planned |
| **KQL** | Microsoft Sentinel native — sigma-cli generates KQL; standalone only if conversion is lossy | Under review |

---

*See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full rule quality gate and pull request process.*
