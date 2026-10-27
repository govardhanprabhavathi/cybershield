import math
import re
from typing import NamedTuple


class SecretPattern(NamedTuple):
    name: str
    pattern: re.Pattern
    cwe_id: str
    severity: str
    description: str


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="HARDCODED_JWT_SECRET",
        pattern=re.compile(
            r"""(?i)(?:jwt_secret|jwt_key)\s*=\s*["']([a-zA-Z0-9_\-]{16,})["']""",
        ),
        cwe_id="CWE-798",
        severity="HIGH",
        description="Hardcoded JWT signing secret detected in configuration or source code.",
    ),
    SecretPattern(
        name="HARDCODED_API_KEY",
        pattern=re.compile(
            r"""(?i)(?:api_key|apikey|secret_key|app_secret)\s*=\s*["']([a-zA-Z0-9_\-]{20,})["']""",
        ),
        cwe_id="CWE-798",
        severity="HIGH",
        description="Hardcoded generic API or application secret key detected.",
    ),
    SecretPattern(
        name="DATABASE_CREDENTIAL_IN_URI",
        pattern=re.compile(
            r"""(?i)(?:postgres(?:ql)?(?:\+asyncpg)?|mysql|mongodb)://[^:]+:([^@\s'"]{4,})@""",
        ),
        cwe_id="CWE-256",
        severity="HIGH",
        description="Plaintext database password embedded directly within connection URI.",
    ),
    SecretPattern(
        name="ASYMMETRIC_PRIVATE_KEY",
        pattern=re.compile(
            r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----""",
        ),
        cwe_id="CWE-312",
        severity="CRITICAL",
        description="Unencrypted private cryptographic key block committed to repository.",
    ),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a given string to detect high-randomness secrets."""
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    frequencies: dict[str, int] = {}

    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    for count in frequencies.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return entropy


def mask_secret(secret: str) -> str:
    """Mask a secret string for safe evidence logging (e.g. 'se********34')."""
    if len(secret) <= 4:
        return "****"
    prefix = secret[:2]
    suffix = secret[-2:]
    return f"{prefix}{'*' * (len(secret) - 4)}{suffix}"
