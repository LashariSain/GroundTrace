"""
CWE -> security design principle mapping.

This powers report field #5 ("which security design principle was violated").
The map is deliberately small but covers the CWEs you'll see most often. Add
rows as your research needs grow.
"""
from __future__ import annotations

# CWE id -> (short principle name, one-line explanation)
CWE_PRINCIPLE: dict[str, tuple[str, str]] = {
    "CWE-20":  ("Input Validation", "All external input must be validated before use."),
    "CWE-22":  ("Input Validation / Canonicalization", "Paths must be canonicalized and confined."),
    "CWE-77":  ("Input Validation", "Command input must be neutralized before execution."),
    "CWE-78":  ("Input Validation", "OS command input must be parameterized, never concatenated."),
    "CWE-79":  ("Output Encoding", "Untrusted data must be encoded for its output context."),
    "CWE-89":  ("Input Validation", "Use parameterized queries; never build SQL from input."),
    "CWE-94":  ("Input Validation", "Never evaluate untrusted data as code."),
    "CWE-119": ("Memory Safety", "Access must stay within allocated buffer bounds."),
    "CWE-125": ("Memory Safety", "Reads must stay within buffer bounds."),
    "CWE-190": ("Memory Safety", "Arithmetic must not overflow security-relevant values."),
    "CWE-200": ("Least Privilege / Confidentiality", "Do not expose sensitive information."),
    "CWE-269": ("Least Privilege", "Grant only the minimum privileges required."),
    "CWE-284": ("Least Privilege / Access Control", "Enforce authorization on every access path."),
    "CWE-287": ("Authentication", "Verify identity correctly and completely."),
    "CWE-306": ("Complete Mediation", "Every request to a resource must be authenticated."),
    "CWE-352": ("Complete Mediation", "State-changing requests must carry an anti-forgery token."),
    "CWE-416": ("Memory Safety", "Do not use memory after it is freed."),
    "CWE-434": ("Input Validation", "Validate and confine uploaded file types."),
    "CWE-502": ("Input Validation", "Never deserialize untrusted data."),
    "CWE-522": ("Confidentiality", "Credentials must be stored and transmitted protected."),
    "CWE-611": ("Input Validation", "Disable external entity resolution in XML parsers."),
    "CWE-732": ("Least Privilege", "Resources must have least-privilege permissions."),
    "CWE-787": ("Memory Safety", "Writes must stay within buffer bounds."),
    "CWE-798": ("Secrets Management", "Never hard-code credentials."),
    "CWE-862": ("Complete Mediation", "Authorization must be checked, not assumed."),
    "CWE-863": ("Access Control", "Authorization logic must be correct for the subject."),
    "CWE-918": ("Input Validation / Defense in Depth", "Validate and restrict server-side request targets."),
}

DEFAULT = ("Secure Design", "A core secure-design principle was not upheld.")

# CWE id -> human-readable weakness name (for citing "CWE-502 (Deserialization
# of Untrusted Data)" instead of a bare code in the report).
CWE_NAMES: dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-611": "XML External Entity Injection",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-787": "Out-of-Bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-917": "Expression Language Injection (JNDI)",
    "CWE-918": "Server-Side Request Forgery",
}

# Rough CIA-triad / outcome tag per CWE, used to build the business-impact
# narrative rather than a single generic sentence.
CWE_OUTCOME: dict[str, str] = {
    "CWE-20": "can enable further downstream attacks via unvalidated input",
    "CWE-78": "can lead to arbitrary OS command execution",
    "CWE-89": "can lead to unauthorized database read/write or full data exfiltration",
    "CWE-94": "can lead to arbitrary code execution",
    "CWE-119": "can lead to memory corruption and potential code execution",
    "CWE-125": "can leak process memory contents",
    "CWE-190": "can corrupt security-relevant calculations (e.g. buffer sizing)",
    "CWE-200": "can expose sensitive configuration, credentials, or user data",
    "CWE-269": "can allow privilege escalation to a higher-trust role",
    "CWE-284": "can allow bypass of intended access restrictions",
    "CWE-287": "can allow authentication bypass or account takeover",
    "CWE-306": "can allow unauthenticated access to protected functionality",
    "CWE-352": "can allow attackers to perform state-changing actions as the victim",
    "CWE-400": "can allow denial of service through resource exhaustion",
    "CWE-416": "can lead to memory corruption and potential code execution",
    "CWE-434": "can allow attacker-controlled files to be executed server-side",
    "CWE-502": "can lead to remote code execution via attacker-controlled object deserialization",
    "CWE-522": "can expose credentials to interception or theft",
    "CWE-611": "can allow local file disclosure or server-side request forgery",
    "CWE-732": "can expose sensitive resources to unauthorized users",
    "CWE-787": "can lead to memory corruption and potential code execution",
    "CWE-798": "can allow full authentication bypass using embedded credentials",
    "CWE-862": "can allow unauthorized users to reach protected functionality",
    "CWE-863": "can allow access-control logic to be bypassed for the wrong subject",
    "CWE-917": "can lead to remote code execution via injected expression-language lookups",
    "CWE-918": "can allow the server to be used to reach internal-only network resources",
}


def principle_for(cwe_ids: list[str]) -> tuple[str, str]:
    for cwe in cwe_ids:
        key = cwe.upper().strip()
        if key in CWE_PRINCIPLE:
            return CWE_PRINCIPLE[key]
    return DEFAULT


def name_for(cwe: str) -> str:
    return CWE_NAMES.get(cwe.upper().strip(), cwe)


def outcomes_for(cwe_ids: list[str]) -> list[str]:
    """Distinct impact-outcome phrases for every recognized CWE, in order."""
    out = []
    for cwe in cwe_ids:
        phrase = CWE_OUTCOME.get(cwe.upper().strip())
        if phrase and phrase not in out:
            out.append(phrase)
    return out
