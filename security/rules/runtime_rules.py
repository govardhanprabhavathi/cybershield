"""Deterministic detection rules and regular expression patterns for runtime threat analysis."""

import re

SQLI_PATTERNS = [
    re.compile(r"(\b(?:or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+)", re.IGNORECASE),
    re.compile(r"(\bunion\s+(?:all\s+)?select\b)", re.IGNORECASE),
    re.compile(r"(--|\#|/\*|\*/)", re.IGNORECASE),
    re.compile(r"(;\s*(?:select|insert|update|delete|drop|alter)\b)", re.IGNORECASE),
    re.compile(r"('|\")\s*(?:or|and)\s*('|\")?", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
    re.compile(r"\bon(?:error|load|click|mouseover|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"javascript:\s*", re.IGNORECASE),
]


def match_sqli(text: str) -> str | None:
    """Matches text against SQL injection patterns, returning matched substring or None."""
    for pattern in SQLI_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def match_xss(text: str) -> str | None:
    """Matches text against XSS patterns, returning matched substring or None."""
    for pattern in XSS_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None
