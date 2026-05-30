/*
 * Megalodon_Base64_Eval_Payload
 * SEC-104 | Spyced Concepts Ltd. | 2026-05-30
 *
 * Copyright 2026 Spyced Concepts Ltd.
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * Source: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
 *
 * Apply to: .github/workflows/*.yml files
 * Usage: yara megalodon-base64-payload.yar /path/to/repo/.github/workflows/
 */

rule Megalodon_Base64_Eval_Payload {
    meta:
        description     = "Detects base64-encoded bash payload pattern in workflow run: steps"
        author          = "Spyced Concepts Ltd. <https://spycedconcepts.co.uk>, AI-assisted by Claude Sonnet 4.6"
        created         = "2026-05-30"
        version         = "1.0"
        reference       = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
        intelligence_source = "IoC data (C2 IP, workflow names, forged email patterns) sourced from original Megalodon threat research by SafeDep.io  -  see reference. Detection rule logic is original work by Spyced Concepts Ltd."
        license         = "Apache-2.0"
        severity        = "CRITICAL"
        campaign        = "megalodon"
        mitre_attack    = "T1059.004,T1027"
        tlp             = "TLP:CLEAR"
        falsepositives  = "Unusual but possible in legitimate workflows decoding and executing trusted setup scripts; require code review"
        note            = "Base64-encoded execution is the primary payload delivery mechanism for both Megalodon variants"
        tested          = "2026-05-30"
        test_fixtures   = "16 (7 positive, 9 negative)  -  tests/megalodon/test-manifest.json"
        fp_confirmed    = "0"
        precision       = "100%"
        recall          = "100%"
        f1              = "1.00"
        f2              = "1.00"
        score_report    = "tests/megalodon/results/2026-05-30-score.txt"

    strings:
        $base64_pipe_bash = /\|\s*base64\s+(-d|-D|--decode)\s*\|\s*(bash|sh)/ ascii
        $base64_decode_exec = /base64\s+(-d|-D|--decode)\s+[^\|]+\|\s*(bash|sh)/ ascii
        $eval_base64 = /eval\s+\$\(echo\s+[A-Za-z0-9+\/]{20,}={0,2}\s*\|\s*base64/ ascii
        $echo_base64_pipe = /echo\s+[A-Za-z0-9+\/]{40,}={0,2}\s*\|\s*base64\s+(-d|-D|--decode)\s*\|\s*(bash|sh)/ ascii

    condition:
        any of them
}
