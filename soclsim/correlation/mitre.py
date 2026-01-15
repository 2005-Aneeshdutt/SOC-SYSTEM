from __future__ import annotations

from typing import Dict, List


# Minimal, high-signal mappings for the scenarios we generate + detect.
# You can extend this table based on your environment (EDR fields, DNS, proxy, etc.).
MITRE_MAP: List[Dict[str, str]] = [
    {
        "key": "bruteforce",
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
    },
    {
        "key": "valid_accounts",
        "tactic": "Defense Evasion",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
    },
    {
        "key": "command_and_control",
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
    },
    {
        "key": "ingress_tool_transfer",
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer",
        "technique_id": "T1105",
    },
    {
        "key": "account_manipulation",
        "tactic": "Persistence",
        "technique": "Account Manipulation",
        "technique_id": "T1098",
    },
    {
        "key": "remote_services",
        "tactic": "Lateral Movement",
        "technique": "Remote Services",
        "technique_id": "T1021",
    },
    {
        "key": "port_scan",
        "tactic": "Discovery",
        "technique": "Network Service Scanning",
        "technique_id": "T1046",
    },
]


def mitre_for_keys(keys: List[str]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for k in keys:
        for m in MITRE_MAP:
            if m["key"] == k:
                out.append(
                    {
                        "tactic": m["tactic"],
                        "technique": m["technique"],
                        "technique_id": m["technique_id"],
                    }
                )
    # dedupe
    seen = set()
    deduped = []
    for m in out:
        key = (m["technique_id"], m["technique"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(m)
    return deduped


