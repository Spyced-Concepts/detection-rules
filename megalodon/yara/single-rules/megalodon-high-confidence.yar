/*
 * Megalodon_High_Confidence
 * SEC-104 | Spyced Concepts Ltd. | 2026-05-30
 *
 * Copyright 2026 Spyced Concepts Ltd.
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * Source: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
 *
 * Apply to: .github/workflows/*.yml files
 * Usage: yara megalodon-high-confidence.yar /path/to/repo/.github/workflows/
 */

rule Megalodon_High_Confidence {
    meta:
        description     = "High-confidence Megalodon detection  -  multiple corroborating IoCs present"
        author          = "Spyced Concepts Ltd. <https://spycedconcepts.co.uk>, AI-assisted by Claude Sonnet 4.6"
        created         = "2026-05-30"
        version         = "1.0"
        reference       = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
        intelligence_source = "IoC data (C2 IP, workflow names, forged email patterns) sourced from original Megalodon threat research by SafeDep.io  -  see reference. Detection rule logic is original work by Spyced Concepts Ltd."
        license         = "Apache-2.0"
        severity        = "CRITICAL"
        campaign        = "megalodon"
        mitre_attack    = "T1195.002,T1071.001,T1059.004"
        tlp             = "TLP:CLEAR"
        falsepositives  = "None expected  -  requires C2 IP or two corroborating Megalodon-specific indicators"
        tested          = "2026-05-30"
        test_fixtures   = "16 (7 positive, 9 negative)  -  megalodon/test/yara/test-manifest.json"
        fp_confirmed    = "0"
        precision       = "100%"
        recall          = "100%"
        f1              = "1.00"
        f2              = "1.00"
        score_report    = "megalodon/test/yara/results/yara-2026-05-30.txt"

    strings:
        $c2_ip = "216.126.225.129" ascii
        $sysdiag = "name: SysDiag" ascii
        $optimize = "name: Optimize-Build" ascii
        $base64_payload = /base64\s+(-d|-D|--decode)\s*[^#\n]*\|\s*(bash|sh)/ ascii
        $prt = "pull_request_target" ascii

    condition:
        $c2_ip or
        ($sysdiag and $base64_payload) or
        ($optimize and $base64_payload) or
        ($prt and $base64_payload and $c2_ip)
}
