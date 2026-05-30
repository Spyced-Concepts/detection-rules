/*
 * Megalodon_Workflow_Dangerous_Permissions
 * SEC-104 | Spyced Concepts Ltd. | 2026-05-30
 *
 * Copyright 2026 Spyced Concepts Ltd.
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * Source: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
 *
 * TRIAGE SIGNAL ONLY - 1 confirmed real-world FP. Correlate with other Megalodon IoCs.
 *
 * Apply to: .github/workflows/*.yml files
 * Usage: yara megalodon-dangerous-permissions.yar /path/to/repo/.github/workflows/
 */

rule Megalodon_Workflow_Dangerous_Permissions {
    meta:
        description     = "Detects workflows combining a fork-PR trigger with an OIDC token permission  -  the core Megalodon mass-variant pattern"
        author          = "Spyced Concepts Ltd. <https://spycedconcepts.co.uk>, AI-assisted by Claude Sonnet 4.6"
        created         = "2026-05-30"
        version         = "1.0"
        reference       = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
        intelligence_source = "IoC data (C2 IP, workflow names, forged email patterns) sourced from original Megalodon threat research by SafeDep.io  -  see reference. Detection rule logic is original work by Spyced Concepts Ltd."
        license         = "Apache-2.0"
        severity        = "HIGH"
        campaign        = "megalodon"
        mitre_attack    = "T1078.004,T1552"
        tlp             = "TLP:CLEAR"
        falsepositives  = "Confirmed real-world FP: legitimate PR deploy preview workflows also combine a fork-PR trigger with an OIDC token grant. This rule fires on both malicious and benign uses of the pattern."
        operator_note   = "Treat as a triage signal, not an auto-block. Correlate with workflow name (SysDiag, Optimize-Build), C2 IP, or base64 payload IoCs before acting. A match here without corroborating indicators warrants review, not immediate response."
        tested          = "2026-05-30"
        test_fixtures   = "16 (7 positive, 9 negative)  -  megalodon/test/yara/test-manifest.json"
        fp_confirmed    = "1  -  benign-prt-with-oidc.yml (legitimate PR deploy preview); real-world FP cannot be eliminated without losing detection coverage"
        precision       = "66.7%"
        recall          = "100%"
        f1              = "0.80"
        f2              = "0.91"
        score_report    = "megalodon/test/yara/results/yara-2026-05-30.txt"

    strings:
        $prt = "pull_request_target" ascii
        $id_token = "id-token: write" ascii
        $id_token2 = "id-token:write" ascii

    condition:
        $prt and ($id_token or $id_token2)
}
