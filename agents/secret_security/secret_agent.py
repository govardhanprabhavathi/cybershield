import os
from pathlib import Path

from security.rules.secret_patterns import SECRET_PATTERNS, calculate_shannon_entropy, mask_secret
from security.schemas.findings import SecurityFinding

EXCLUDED_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache"}
EXCLUDED_EXTS = {".pyc", ".png", ".jpg", ".svg", ".ico", ".lock"}


class SecretSecurityAgent:
    """Agent 5: Scans codebase for hardcoded credentials, JWT secrets, and high-entropy keys."""

    def __init__(self, target_dir: str = "."):
        self.target_dir = target_dir

    def scan(self, target_dir: str | None = None) -> list[SecurityFinding]:
        scan_path = Path(target_dir or self.target_dir)
        findings: list[SecurityFinding] = []

        if not scan_path.exists():
            return findings

        for root, dirs, files in os.walk(scan_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

            for file in files:
                if any(file.endswith(ext) for ext in EXCLUDED_EXTS):
                    continue

                file_path = Path(root) / file
                # Skip example files where mock credentials are deliberately demonstrated
                if file.endswith((".example", "_test.py")) or file.startswith("test_"):
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except (UnicodeDecodeError, OSError):
                    continue

                for line_idx, line in enumerate(lines, start=1):
                    # Check regex patterns
                    for pattern_def in SECRET_PATTERNS:
                        match = pattern_def.pattern.search(line)
                        if match:
                            raw_secret = match.group(1) if match.groups() else match.group(0)
                            entropy = calculate_shannon_entropy(raw_secret)
                            findings.append(
                                SecurityFinding(
                                    agent_source="secret_security",
                                    category="HARDCODED_SECRET",
                                    cwe_id=pattern_def.cwe_id,
                                    owasp_category="OWASP Top 10 - Identification and Authentication Failures",
                                    severity=pattern_def.severity,
                                    confidence=0.95,
                                    title=f"Hardcoded Credential Detected: {pattern_def.name}",
                                    description=(
                                        f"{pattern_def.description} Found at line {line_idx}. "
                                        f"Secret entropy score: {entropy:.2f}."
                                    ),
                                    file_path=str(file_path.as_posix()),
                                    line_number=line_idx,
                                    endpoint=None,
                                    method=None,
                                    parameter=None,
                                    raw_evidence={
                                        "rule": pattern_def.name,
                                        "masked_value": mask_secret(raw_secret),
                                        "entropy": round(entropy, 2),
                                    },
                                    remediation_guidance=(
                                        "Migrate secret to a secure external secret manager or load dynamically "
                                        "from environment variables without checking default keys into source code."
                                    ),
                                )
                            )
                            break

        return findings
