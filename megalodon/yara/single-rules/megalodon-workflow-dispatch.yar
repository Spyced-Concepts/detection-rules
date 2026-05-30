/*
 * Megalodon_Workflow_Dispatch_Backdoor
 * SEC-104 | Spyced Concepts Ltd. | 2026-05-30
 *
 * Copyright 2026 Spyced Concepts Ltd.
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * Source: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
 *
 * Apply to: .github/workflows/*.yml files
 * Usage: yara megalodon-workflow-dispatch.yar /path/to/repo/.github/workflows/
 */

rule Megalodon_Workflow_Dispatch_Backdoor {
    meta:
        description     = "Detects Megalodon targeted variant  -  workflow_dispatch as sole trigger, combined with Optimize-Build name or C2 IoCs"
        author          = "Spyced Concepts Ltd. <https://spycedconcepts.co.uk>, AI-assisted by Claude Sonnet 4.6"
        created         = "2026-05-30"
        version         = "1.0"
        reference       = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
        intelligence_source = "IoC data (C2 IP, workflow names, forged email patterns) sourced from original Megalodon threat research by SafeDep.io  -  see reference. Detection rule logic is original work by Spyced Concepts Ltd."
        license         = "Apache-2.0"
        severity        = "MEDIUM"
        campaign        = "megalodon"
        mitre_attack    = "T1195.002"
        tlp             = "TLP:CLEAR"
        falsepositives  = "workflow_dispatch alone is extremely common; this rule fires only when combined with Optimize-Build name or C2 IP  -  false positives on those combinations are not expected"
        tested          = "2026-05-30"
        test_fixtures   = "16 (7 positive, 9 negative)  -  tests/megalodon/test-manifest.json"
        fp_confirmed    = "0"
        precision       = "100%"
        recall          = "100%"
        f1              = "1.00"
        f2              = "1.00"
        score_report    = "tests/megalodon/results/2026-05-30-score.txt"

    strings:
        $wf_dispatch = "workflow_dispatch:" ascii
        $optimize_name = "name: Optimize-Build" ascii
        $base64_any = /base64/ ascii
        $c2_ip = "216.126.225.129" ascii

    condition:
        ($optimize_name and $wf_dispatch) or
        ($wf_dispatch and $c2_ip) or
        ($wf_dispatch and $base64_any and $c2_ip)
}
