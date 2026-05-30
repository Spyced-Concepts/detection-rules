/*
 * YARA rules for detecting Megalodon GitHub CI backdoor campaign
 * SEC-104 | Spyced Concepts Ltd. | 2026-05-30
 *
 * Source: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
 *
 * Apply to: .github/workflows/*.yml files across all repos
 * Usage: yara -r megalodon-workflow.yar /path/to/repo/.github/workflows/
 */

import "hash"

rule Megalodon_Workflow_C2_IP {
    meta:
        description = "Detects Megalodon C2 IP address in GitHub Actions workflow files"
        severity = "CRITICAL"
        campaign = "megalodon"
        created = "2026-05-30"
        reference = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"

    strings:
        $c2_ip = "216.126.225.129" ascii wide
        $c2_port = "216.126.225.129:8443" ascii wide

    condition:
        any of them
}

rule Megalodon_Workflow_Names {
    meta:
        description = "Detects Megalodon malicious workflow names (SysDiag, Optimize-Build)"
        severity = "HIGH"
        campaign = "megalodon"
        created = "2026-05-30"
        note = "Match on YAML name: field — may produce false positives on legitimate workflows with similar names; correlate with other indicators"

    strings:
        $sysdiag = "name: SysDiag" ascii
        $optimize_build = "name: Optimize-Build" ascii

    condition:
        any of them
}

rule Megalodon_Forged_Author_Email {
    meta:
        description = "Detects Megalodon forged git author email addresses"
        severity = "HIGH"
        campaign = "megalodon"
        created = "2026-05-30"
        note = "Apply to git log output or commit metadata, not workflow files"

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
        description = "Detects workflows requesting id-token:write with pull_request_target — high-risk combination used by Megalodon mass variant"
        severity = "HIGH"
        campaign = "megalodon"
        created = "2026-05-30"
        note = "pull_request_target with id-token:write gives fork PRs write access to secrets — legitimate use exists but requires review"

    strings:
        $prt = "pull_request_target" ascii
        $id_token = "id-token: write" ascii
        $id_token2 = "id-token:write" ascii

    condition:
        $prt and ($id_token or $id_token2)
}

rule Megalodon_Base64_Eval_Payload {
    meta:
        description = "Detects base64-encoded bash payload pattern in workflow run: steps"
        severity = "CRITICAL"
        campaign = "megalodon"
        created = "2026-05-30"
        note = "Base64-encoded execution is the primary payload delivery mechanism for both Megalodon variants"

    strings:
        $base64_pipe_bash = /\|\s*base64\s+(-d|-D|--decode)\s*\|\s*(bash|sh)/ ascii
        $base64_decode_exec = /base64\s+(-d|-D|--decode)\s+[^\|]+\|\s*(bash|sh)/ ascii
        $eval_base64 = /eval\s+\$\(echo\s+[A-Za-z0-9+\/]{20,}={0,2}\s*\|\s*base64/ ascii
        $echo_base64_pipe = /echo\s+[A-Za-z0-9+\/]{40,}={0,2}\s*\|\s*base64/ ascii

    condition:
        any of them
}

rule Megalodon_Workflow_Dispatch_Backdoor {
    meta:
        description = "Detects Megalodon targeted variant — workflow_dispatch as sole trigger, with suspicious payload patterns"
        severity = "MEDIUM"
        campaign = "megalodon"
        created = "2026-05-30"
        note = "workflow_dispatch alone is common; flag only if combined with base64 payload or C2 IoCs"

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
        description = "High-confidence Megalodon detection — multiple corroborating IoCs present"
        severity = "CRITICAL"
        campaign = "megalodon"
        created = "2026-05-30"

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
