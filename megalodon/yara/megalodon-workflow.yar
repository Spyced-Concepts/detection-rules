/*
 * YARA rules for detecting Megalodon GitHub CI backdoor campaign
 * SEC-104 | Spyced Concepts Ltd. | 2026-05-30
 *
 * Copyright 2026 Spyced Concepts Ltd.
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * Source: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
 *
 * Apply to: .github/workflows/*.yml files across all repos
 * Usage: yara -r megalodon-workflow.yar /path/to/repo/.github/workflows/
 */

import "hash"

rule Megalodon_Workflow_C2_IP {
    meta:
        description     = "Detects Megalodon C2 IP address in GitHub Actions workflow files"
        author          = "Spyced Concepts Ltd. <https://spycedconcepts.co.uk>, AI-assisted by Claude Sonnet 4.6"
        created         = "2026-05-30"
        version         = "1.0"
        reference       = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
        intelligence_source = "IoC data (C2 IP, workflow names, forged email patterns) sourced from original Megalodon threat research by SafeDep.io  -  see reference. Detection rule logic is original work by Spyced Concepts Ltd."
        license         = "Apache-2.0"
        severity        = "CRITICAL"
        campaign        = "megalodon"
        mitre_attack    = "T1071.001"
        tlp             = "TLP:CLEAR"
        falsepositives  = "None  -  216.126.225.129 has been observed exclusively in malicious Megalodon workflows"
        tested          = "2026-05-30"
        test_fixtures   = "16 (7 positive, 9 negative)  -  tests/megalodon/test-manifest.json"
        fp_confirmed    = "0"
        precision       = "100%"
        recall          = "100%"
        f1              = "1.00"
        f2              = "1.00"
        score_report    = "tests/megalodon/results/2026-05-30-score.txt"

    strings:
        $c2_ip = "216.126.225.129" ascii wide
        $c2_port = "216.126.225.129:8443" ascii wide

    condition:
        any of them
}

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
        test_fixtures   = "16 (7 positive, 9 negative)  -  tests/megalodon/test-manifest.json"
        fp_confirmed    = "0"
        precision       = "100%"
        recall          = "100%"
        f1              = "1.00"
        f2              = "1.00"
        score_report    = "tests/megalodon/results/2026-05-30-score.txt"

    strings:
        $sysdiag = "name: SysDiag" ascii
        $optimize_build = "name: Optimize-Build" ascii

    condition:
        any of them
}

rule Megalodon_Forged_Author_Email {
    meta:
        description     = "Detects Megalodon forged git author email addresses and bot identity strings"
        author          = "Spyced Concepts Ltd. <https://spycedconcepts.co.uk>, AI-assisted by Claude Sonnet 4.6"
        created         = "2026-05-30"
        version         = "1.0"
        reference       = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
        intelligence_source = "IoC data (C2 IP, workflow names, forged email patterns) sourced from original Megalodon threat research by SafeDep.io  -  see reference. Detection rule logic is original work by Spyced Concepts Ltd."
        license         = "Apache-2.0"
        severity        = "HIGH"
        campaign        = "megalodon"
        mitre_attack    = "T1036"
        tlp             = "TLP:CLEAR"
        falsepositives  = "Organisations using ci-bot, build-bot, or auto-ci as legitimate automation identities"
        note            = "Apply to git log output or commit metadata, not workflow files"
        tested          = "2026-05-30"
        test_fixtures   = "16 (7 positive, 9 negative)  -  tests/megalodon/test-manifest.json"
        fp_confirmed    = "0"
        precision       = "100%"
        recall          = "100%"
        f1              = "1.00"
        f2              = "1.00"
        score_report    = "tests/megalodon/results/2026-05-30-score.txt"

    strings:
        $email1 = "[email protected]" ascii
        $email2 = "[email protected]" ascii
        $name1 = "\"build-bot\"" ascii
        $name2 = "\"auto-ci\"" ascii
        $name3 = "\"ci-bot\"" ascii
        $name4 = "\"pipeline-bot\"" ascii

    condition:
        any of them
}

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
        test_fixtures   = "16 (7 positive, 9 negative)  -  tests/megalodon/test-manifest.json"
        fp_confirmed    = "1  -  benign-prt-with-oidc.yml (legitimate PR deploy preview); real-world FP cannot be eliminated without losing detection coverage"
        precision       = "66.7%"
        recall          = "100%"
        f1              = "0.80"
        f2              = "0.91"
        score_report    = "tests/megalodon/results/2026-05-30-score.txt"

    strings:
        $prt = "pull_request_target" ascii
        $id_token = "id-token: write" ascii
        $id_token2 = "id-token:write" ascii

    condition:
        $prt and ($id_token or $id_token2)
}

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
        falsepositives  = "workflow_dispatch alone is extremely common; this rule fires only when combined with Optimize-Build name or C2 IP  -  false positives on those combinations are unlikely"
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
        test_fixtures   = "16 (7 positive, 9 negative)  -  tests/megalodon/test-manifest.json"
        fp_confirmed    = "0"
        precision       = "100%"
        recall          = "100%"
        f1              = "1.00"
        f2              = "1.00"
        score_report    = "tests/megalodon/results/2026-05-30-score.txt"

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
