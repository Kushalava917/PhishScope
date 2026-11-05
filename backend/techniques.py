"""Small curated Enterprise ATT&CK subset; official sources reviewed 2026-11-05."""

TECHNIQUES = [
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Social engineering delivered electronically to obtain access.",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "A targeted message delivers an attachment intended to facilitate access.",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "A message uses a link to lure a recipient into an adversary-controlled workflow.",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    {
        "id": "T1204.001",
        "name": "Malicious Link",
        "tactic": "Execution",
        "description": "A user follows a malicious link that leads to code execution. A credential lure alone does not establish execution.",
        "url": "https://attack.mitre.org/techniques/T1204/001/",
    },
    {
        "id": "T1204.002",
        "name": "Malicious File",
        "tactic": "Execution",
        "description": "A user opens a malicious file, leading to execution. Email evidence alone cannot confirm this action.",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
    },
]
