/*
 * Megalodon_Workflow_Names
 * SEC-104 | Spyced Concepts Ltd. | 2026-05-30
 *
 * Copyright 2026 Spyced Concepts Ltd.
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * Source: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
 *
 * Apply to: .github/workflows/*.yml files
 * Usage: yara megalodon-workflow-names.yar /path/to/repo/.github/workflows/
 */

rule Megalodon_Workflow_Names {
    meta:
        description     = "Detects Megalodon malicious workflow names (SysDiag, Optimize-Build)"
        author          = "Spyced Concepts Ltd. <https://spycedconcepts.co.uk>, AI-assisted by Claude Sonnet 4.6"
        created         = "2026-05-30"
        version         = "1.0"
        reference       = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
        intelligence_source = "IoC data (C2 IP, workflow names, forged email patterns) sourced from original Megalodon threat research by SafeDep.io  -  see reference. Detection rule logic is original work by Spyced Concepts Ltd."
        license         = "Apache-2.0"
        severity        = "HIGH"
        campaign        = "megalodon"
        mitre_attack    = "T1036.005"
        tlp             = "TLP:CLEAR"
        falsepositives  = "Legitimate in-house workflows named SysDiag or Optimize-Build; correlate with additional IoCs before acting"
        tested          = "2026-05-30"
        test_fixtures   = "16 (7 positive, 9 negative)  -  megalodon/test/yara/test-manifest.json"
        fp_confirmed    = "0"
        precision       = "100%"
        recall          = "100%"
        f1              = "1.00"
        f2              = "1.00"
        score_report    = "megalodon/test/yara/results/yara-2026-05-30.txt"

    strings:
        $sysdiag = "name: SysDiag" ascii
        $optimize_build = "name: Optimize-Build" ascii

    condition:
        any of them
}
