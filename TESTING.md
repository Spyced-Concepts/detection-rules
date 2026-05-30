---
title: Testing Detection Rules
author: "Spyced Concepts Ltd., AI-assisted by Claude Sonnet 4.6"
created: 2026-05-30
updated: 2026-05-30
license: Apache-2.0
---

# Testing Detection Rules

**All testing MUST run inside an isolated container. Running YARA or Sigma tools directly on a development machine is not permitted.**

The isolation requirement is not a preference — it is the safety control. The test container is stood up, used, and torn down for each test run. Nothing from the test environment persists on the host after the container exits.

---

## Why isolation is mandatory

YARA scans byte patterns in files. For current fixtures (GitHub Actions YAML — plain text), the risk of direct host execution is low. The mandatory isolation rule exists because:

1. **Future fixtures may not be text files.** If we ever test rules against binary samples, kernel exploits, or packed payloads, a container breach could escalate to host compromise. Establishing the isolation requirement now means it is already in place when the risk increases.
2. **Consistent, reproducible environment.** The container pins the YARA and sigma-cli versions. Results on macOS, Linux, and Windows CI are identical.
3. **Stand-up and tear-down are the control.** The container is created from a known-good image and destroyed after use. No test artefacts remain on the host.

**No bind mounts.** The container has no access to the host filesystem. All file I/O is explicit: input files are copied in before the run; result files are copied out after. This prevents the container from reading or writing anything beyond the files explicitly provided.

**VM vs Docker:** Docker shares the host kernel — a kernel-level exploit could escape the container. A VM runs its own kernel and provides stronger isolation. For the current campaign (YAML text fixtures), Docker is appropriate. If the repository ever covers binary malware samples, switch to a VM with a pre-scan snapshot, no network adapter, and no shared folders. This document must be updated before that happens.

---

## Architecture — one image, multiple services

All tests share a single image (`detection-rules-tests`) built from `tests/Dockerfile`. The image contains:

- **YARA** — rule scanner
- **sigma-cli** — Sigma rule converter
- **pySigma backends** — Splunk, Elasticsearch, OpenSearch
- **Test scripts** baked in at `/tests/` — `yara-score.py` (YARA) and `sigma-convert.py` (Sigma), sourced from `tests/docker-scripts/`
- **`/input/` and `/output/`** — empty directories for explicit file I/O; no host path is mounted

`tests/docker-compose.yml` defines services using this image. The `entrypoint` (the script) is fixed per service; the `command` (args) provides sensible defaults and can be overridden on the command line.

| Service | Script | Input path (inside container) | Default output |
|---|---|---|---|
| `yara-tests` | `/tests/yara-score.py` | `/input/test/yara/test-manifest.json` (manifest); `/input/yara/` (rules) | `/output/yara-YYYY-MM-DD.txt` |
| `sigma-tests` | `/tests/sigma-convert.py` | `/input/sigma/` (rules) | `/output/sigma-YYYY-MM-DD.txt` |

---

## Repository layout

Rules and test data live under the campaign directory. The `tests/` directory holds only the container tooling.

```
<campaign>/
├── sigma/                        # Sigma rules
│   └── *.yml
├── yara/                         # YARA rules
│   ├── <campaign>.yar
│   └── single-rules/
│       └── *.yar
└── test/
    ├── yara/                     # YARA test data
    │   ├── test-manifest.json
    │   ├── results/              # Scored result files (committed as evidence)
    │   │   └── yara-YYYY-MM-DD.txt
    │   └── fixtures/
    │       ├── positive/         # Files the rules must match
    │       └── negative/         # Files the rules must not match
    └── sigma/                    # Sigma test data (future)

tests/
├── Dockerfile                    # Single image definition
├── docker-compose.yml            # Service definitions
├── run.py                        # Standard import/run/export entry point
└── docker-scripts/               # Scripts baked into the container
    ├── yara-score.py
    └── sigma-convert.py
```

---

## Setup — build the image

Build once per machine. Rebuild when the Dockerfile or pip dependencies change.

```bash
cd tests
docker compose build
```

This produces a local-only `detection-rules-tests` image. Nothing is installed on the host. The image is never pushed to a registry.

---

## Run tests — standard workflow (recommended)

`tests/run.py` is the entry point for all standard test runs. It handles import, run, and export in one command. Run all commands from the **repository root**. Both services accept the same flags.

```
python tests/run.py <service> --in-dir <campaign-dir> [--out-dir <dir>]
```

| Flag | Required | Description |
|---|---|---|
| `--in-dir DIR` | Yes | Copy the campaign directory into `/input/` inside the container |
| `--out-dir DIR` | No | Where to save results on the host (default: `tests/results/`) |

### YARA tests

```bash
python tests/run.py yara-tests --in-dir megalodon --out-dir megalodon/test/yara/results
```

Copies `megalodon/` into the container, runs the scorer against `test/yara/test-manifest.json`, and saves a dated report to the specified output directory.

### Sigma conversion tests

```bash
python tests/run.py sigma-tests --in-dir megalodon --out-dir megalodon/test/sigma/results
```

Copies `megalodon/` into the container, converts every rule in `sigma/` to Splunk, Elasticsearch (Lucene), and OpenSearch, and saves a dated report.

### Adding a new test service

1. Add a new service entry to `tests/docker-compose.yml`, referencing the same `image: detection-rules-tests`.
2. Add an entry to the `SERVICES` dict in `tests/run.py` with `cmd` and `hint`.
3. Update this document with the new service's usage.

---

## Run tests — advanced (manual import/export)

For non-standard runs or custom commands, drive the container directly. `run.py` uses these raw docker commands internally.

### YARA tests with custom args

```bash
# Build
(cd tests && docker compose build)

# Create container (without starting)
docker create --name yara-run detection-rules-tests \
  python3 /tests/yara-score.py \
    /input/test/yara/test-manifest.json \
    --root /input --beta 1 --output /output/yara.txt

# Import the campaign directory
docker cp megalodon/. yara-run:/input/

# Run (blocks until exit)
docker start --attach yara-run

# Export results
docker cp yara-run:/output/yara.txt ./megalodon/test/yara/results/

# Clean up
docker rm yara-run
```

### Sigma tests with custom args

```bash
docker create --name sigma-run detection-rules-tests \
  python3 /tests/sigma-convert.py --rules-dir /input/sigma --output /output/sigma.txt

docker cp megalodon/. sigma-run:/input/
docker start --attach sigma-run
docker cp sigma-run:/output/sigma.txt ./megalodon/test/sigma/results/
docker rm sigma-run
```

### Compile check only

```bash
docker create --name compile-check detection-rules-tests \
  yara /input/yara/megalodon-workflow.yar /dev/null
docker cp megalodon/. compile-check:/input/
docker start --attach compile-check
docker rm compile-check
```

A clean return (exit 0, no output) means the rule compiles.

### Passing custom args via docker compose

The `entrypoint` (script path) is fixed per service. The `command` block can be overridden by passing args after the service name:

```bash
cd tests
docker compose run sigma-tests --rules-dir /input/sigma --backends splunk --output /output/splunk-only.txt
docker compose run yara-tests /input/test/yara/test-manifest.json --root /input --beta 1
```

`docker compose run` does not handle the file import/export step. Use `run.py` for standard runs, or do the `docker cp` steps manually as shown above.

---

## YARA score output

The scorer prints TP/FP/FN/TN per rule, precision, recall, F1, and Fb (default b = 2). It also prints the scoring formulae at the top of every run — the basis is always visible in the saved output. Exits with code 1 if any rule has `FP > 0` or `FN > 0`. See **[Reliability scoring](#reliability-scoring--basis-and-calculation)** below for the mathematical basis and weighting rationale.

| Metric | Definition | Required to publish |
|---|---|---|
| **TP** | Positive fixture correctly matched | All positive fixtures must match |
| **FP** | Negative fixture incorrectly matched | **0** |
| **FN** | Positive fixture failed to match | **0** |
| **TN** | Negative fixture correctly not matched | — |
| **Precision** | TP / (TP + FP) | **100%** |
| **Recall** | TP / (TP + FN) | **100%** |
| **F1** | Harmonic mean of P and R | **1.00** |
| **Fb (b = 2)** | Recall-weighted harmonic mean | **1.00** |

### Tear down

`run.py` removes the container automatically after each run. To also remove the image:

```bash
docker rmi detection-rules-tests
```

---

## Reliability scoring — basis and calculation

### Confusion matrix

For each fixture, each rule produces one of four outcomes:

| Fixture type | Rule fires | Outcome |
|---|---|---|
| Positive (expected to match) | Yes | **True Positive (TP)** — correct detection |
| Positive (expected to match) | No | **False Negative (FN)** — missed threat |
| Negative (expected not to match) | Yes | **False Positive (FP)** — false alarm |
| Negative (expected not to match) | No | **True Negative (TN)** — correct non-detection |

### Formulae

**Precision** — of all files the rule fired on, what fraction were genuinely malicious?

```
Precision = TP / (TP + FP)
```

Low precision floods analysts with false alarms. In a SOC context this leads to alert fatigue and rules being disabled.

**Recall** — of all genuinely malicious files, what fraction did the rule catch?

```
Recall = TP / (TP + FN)
```

Low recall lets threats pass undetected. A missed threat may allow an attack to proceed without any alert.

**F1** — harmonic mean; treats a missed threat and a false alarm as equally costly:

```
F1 = 2 x Precision x Recall / (Precision + Recall)
```

**Why F1 alone is not enough:** in security detection, a false negative (missed threat) and a false positive (false alarm) are not equally costly. The relative cost depends on the deployment context. F1 cannot express this asymmetry.

**Fb** — weighted harmonic mean that adjusts the cost ratio between FP and FN:

```
Fb = (1 + b^2) x Precision x Recall / (b^2 x Precision + Recall)
```

| b value | Effect | When to use |
|---|---|---|
| b > 1 | Recall weighted more heavily — missed threats penalised harder | Default for detection rules: a missed threat is more dangerous than a false alarm |
| b = 1 | Equal weight — identical to F1 | Symmetric cost environments |
| b < 1 | Precision weighted more heavily — false alarms penalised harder | Very high-volume noisy environments where alert fatigue is the dominant risk |

**Default: b = 2 (F2 score).** Recall is weighted 4x more than precision (b^2 = 4). This expresses the judgement that a missed threat is four times more costly than a false alarm — the conventional choice for security detection rules. Override with `--beta <value>` when a campaign warrants a different weighting.

### Why all four metrics must reach 1.00 to publish

When both FP = 0 and FN = 0, precision and recall are both 1.00, which forces F1 = 1.00 and Fb = 1.00 regardless of b. The weighting does not create a softer bar — it is a diagnostic that identifies *which type of error* is present when the rule fails. A rule that passes all four metrics at 1.00 has zero errors of either type in the test set.

### Saved output and traceability

Every test run that precedes publishing must produce a saved report file committed alongside the rule. The file includes the formulae, b value, fixture-level PASS/FAIL, and per-rule scores — so anyone reading the commit can reproduce the exact calculation.

```
<campaign>/test/yara/results/yara-YYYY-MM-DD.txt
```

The `--output /output/yara-YYYY-MM-DD.txt` argument to `yara-score.py` produces this file. `run.py` then copies it to the host via `docker cp`.

---

## Test manifest

Each campaign has `<campaign>/test/yara/test-manifest.json` declaring:
- `rules_file` — YARA file path relative to the campaign root (e.g. `yara/megalodon-workflow.yar`)
- `all_rules` — all rule names in the file (required to count TN correctly)
- `fixtures` — array of specs; `expected_rules` is empty for negative fixtures
- `false_positive_risk` — optional flag on high-risk negative fixtures

Update the manifest whenever rules or fixtures change.

### False positive risk fixtures

Negative fixtures marked `"false_positive_risk": "HIGH"` are legitimate real-world patterns that closely resemble the IoC. If these trigger a rule, it is a confirmed real-world false positive. Document it in the rule's `meta` block and advise operators on suppression.

Example: `Megalodon_Workflow_Dangerous_Permissions` detects `pull_request_target` + `id-token: write`. This combination is also used by legitimate PR-triggered OIDC deployments. The `benign-prt-with-oidc.yml` fixture confirms whether this is a real-world FP.

### Recording results in rule meta

After a clean run, append the outcome to each rule's `meta` block. The full set of standard meta fields is:

```yara
meta:
    description     = "..."
    author          = "Spyced Concepts Ltd. <https://spycedconcepts.co.uk>"
    created         = "2026-05-30"
    version         = "1.0"
    reference       = "https://..."
    license         = "Apache-2.0"
    severity        = "CRITICAL|HIGH|MEDIUM|LOW"
    campaign        = "<campaign>"
    mitre_attack    = "T1234,T1234.001"
    tlp             = "TLP:CLEAR"
    falsepositives  = "..."
    tested          = "2026-05-30"
    positive_fixtures = "N"
    negative_fixtures = "N"
    false_positives = "0 in test set - see <campaign>/test/yara/test-manifest.json"
    precision       = "100%"
    recall          = "100%"
    f1              = "1.00"
    f2              = "1.00"
    score_report    = "<campaign>/test/yara/results/yara-YYYY-MM-DD.txt"
```

All fields above `tested` are required at rule creation. Fields from `tested` onward are added after the first successful test run.

---

## Sigma testing

Sigma conversion tests run via `python tests/run.py sigma-tests --in-dir megalodon`. The script converts each Sigma rule to every configured backend and reports the output for manual review. This tests that rules compile to valid query language — it is not FP/FN detection testing against log fixtures.

Output is saved to `<campaign>/test/sigma/results/sigma-YYYY-MM-DD.txt`.

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

### Sigma reliability scoring — current gap

**The fixture-based FP/FN scoring covers YARA rules only.** There is no equivalent precision/recall/F1 framework for Sigma rules yet.

Testing a Sigma rule for false positives and false negatives requires:
1. **Log data samples** — real or synthetic EVTX / audit log files representing both attack and benign events
2. **A Sigma evaluation engine** — tools like `sigma-test` (community) or a live SIEM backend to run the converted query against the sample data
3. **A separate test harness** — a parallel implementation of the manifest format that invokes the evaluation engine against log fixtures

Until this is built, Sigma rules carry a lower evidence bar than YARA rules. Validation against live log data (or a representative sample set) must be completed before `status: experimental` is promoted to `status: stable`.

---

## Other rule formats — future consideration

| Format | Use case | Status |
|---|---|---|
| **Suricata** | Network IDS/IPS — complements Sigma network rules with inline enforcement | Planned |
| **STIX 2.1** | Structured threat intel sharing — IoC bundles for threat intel platforms | Planned |
| **KQL** | Microsoft Sentinel native — sigma-cli generates KQL; standalone only if conversion is lossy | Under review |

---

*See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full rule quality gate and pull request process.*

---

*Copyright 2026 Spyced Concepts Ltd. (company number 16978283) · Licensed under [Apache-2.0](LICENSE)*
