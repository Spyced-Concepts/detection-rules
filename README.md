# detection-rules

Community detection rules for supply chain, CI/CD, and developer tooling threats — YARA and Sigma. Apache 2.0.

Maintained by [Spyced Concepts Ltd.](https://spycedconcepts.co.uk) — a UK security software company building tools for developers and SMEs.

---

## Contents

| Path | Format | Coverage |
|---|---|---|
| `yara/megalodon/` | YARA | Megalodon GitHub CI backdoor campaign (2026-05-18) |
| `sigma/megalodon/` | Sigma | Megalodon GitHub CI backdoor campaign (2026-05-18) |

## Megalodon

**Campaign:** Mass GitHub CI workflow backdoor — 5,561 repositories compromised using stolen Personal Access Tokens to push malicious workflow files directly to default branches.

**Attack variants:**
- `SysDiag.yml` — mass variant; uses `pull_request_target` + `id-token: write` to give fork PRs access to OIDC tokens and secrets
- `Optimize-Build.yml` — targeted variant; triggered via `workflow_dispatch`; exfiltrates CI secrets to C2 at `216.126.225.129:8443` via base64-encoded bash payload

**Primary defence:** Require pull requests for all pushes to protected branches (GitHub branch ruleset with `pull_request` rule, no bypass actors). This blocks the stolen-PAT direct-push vector entirely.

**Sources:**
- SafeDep.io: [Megalodon — Mass GitHub Repo Backdooring CI Workflows](https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/)
- Phoenix Security: no existing scanner signatures at time of writing (2026-05-30) — these rules fill that gap

### YARA rules (`yara/megalodon/megalodon-workflow.yar`)

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
# Scan a single repo's workflows
yara -r yara/megalodon/megalodon-workflow.yar /path/to/repo/.github/workflows/

# Scan all local clones
yara -r yara/megalodon/megalodon-workflow.yar ~/Projects/
```

### Sigma rules (`sigma/megalodon/`)

| Rule file | Log source | Level | What it detects |
|---|---|---|---|
| `megalodon-github-direct-push-workflow.yml` | GitHub audit | High | Direct push to workflow dir without a pull request |
| `megalodon-workflow-name-ioc.yml` | GitHub audit | Critical | Creation of SysDiag or Optimize-Build workflow files |
| `megalodon-c2-outbound-network.yml` | Network (Linux) | Critical | Outbound connection to `216.126.225.129:8443` from CI runner |
| `megalodon-base64-exec-ci-runner.yml` | Process creation (Linux) | High | Base64-decode piped to bash/sh on CI runner host |
| `megalodon-dangerous-workflow-permissions.yml` | GitHub audit | Medium | Workflow push for manual content review (pairs with YARA rule) |

**Convert to your SIEM with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):**
```bash
sigma convert -t splunk sigma/megalodon/
sigma convert -t elasticsearch sigma/megalodon/
sigma convert -t sentinel sigma/megalodon/
```

---

## Licence

Apache 2.0 — see [LICENSE](LICENSE). Attribution appreciated but not required.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contact

Security issues: open an issue or contact [stuart@spycedconcepts.co.uk](mailto:stuart@spycedconcepts.co.uk).
