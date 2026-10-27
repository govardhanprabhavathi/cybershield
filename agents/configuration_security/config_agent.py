from app.core.config import Settings

from security.schemas.findings import SecurityFinding


class ConfigurationSecurityAgent:
    """Agent 6: Audits system settings, CORS policies, environment configurations, and deployment posture."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings

    def scan(self, settings: Settings | None = None) -> list[SecurityFinding]:
        cfg = settings or self.settings
        if cfg is None:
            from app.core.config import get_settings
            cfg = get_settings()

        findings: list[SecurityFinding] = []

        # Audit 1: Default Development Secret Usage
        if "cybershield-dev-secret-key" in cfg.SECRET_KEY:
            findings.append(
                SecurityFinding(
                    agent_source="configuration_security",
                    category="INSECURE_CONFIGURATION",
                    cwe_id="CWE-1188",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity="HIGH",
                    confidence=0.98,
                    title="Default Development Secret Key in Active Configuration",
                    description="Application is executing with the default repository SECRET_KEY.",
                    file_path="app/core/config.py",
                    line_number=None,
                    endpoint=None,
                    method=None,
                    parameter="SECRET_KEY",
                    raw_evidence={"setting": "SECRET_KEY", "value_type": "default_dev_key"},
                    remediation_guidance="Generate a cryptographically random 32+ character SECRET_KEY for production deployments.",
                )
            )

        # Audit 2: Default JWT Secret Key
        if "super-secret-jwt-signing-key" in cfg.JWT_SECRET:
            findings.append(
                SecurityFinding(
                    agent_source="configuration_security",
                    category="INSECURE_CONFIGURATION",
                    cwe_id="CWE-1188",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity="HIGH",
                    confidence=0.98,
                    title="Default JWT Signing Secret in Active Configuration",
                    description="The JWT signing key matches the default template value from .env.example.",
                    file_path="app/core/config.py",
                    line_number=None,
                    endpoint=None,
                    method=None,
                    parameter="JWT_SECRET",
                    raw_evidence={"setting": "JWT_SECRET", "value_type": "default_jwt_key"},
                    remediation_guidance="Rotate JWT_SECRET using a dedicated secret generator and environment injection.",
                )
            )

        # Audit 3: Debug Mode Exposure
        if cfg.DEBUG:
            findings.append(
                SecurityFinding(
                    agent_source="configuration_security",
                    category="INSECURE_CONFIGURATION",
                    cwe_id="CWE-215",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity="LOW",
                    confidence=0.95,
                    title="Interactive Debug Mode Enabled",
                    description="DEBUG flag is set to True. Interactive documentation and verbose error details are exposed.",
                    file_path="app/core/config.py",
                    line_number=None,
                    endpoint="/docs",
                    method="GET",
                    parameter="DEBUG",
                    raw_evidence={"setting": "DEBUG", "value": True},
                    remediation_guidance="Disable DEBUG (set DEBUG=false) in all public and production environments.",
                )
            )

        # Audit 4: Controlled Vulnerabilities Active Notice
        if cfg.VULNERABILITY_MODE:
            findings.append(
                SecurityFinding(
                    agent_source="configuration_security",
                    category="INSECURE_CONFIGURATION",
                    cwe_id="CWE-16",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity="MEDIUM",
                    confidence=1.0,
                    title="Research Vulnerability Toggles Active",
                    description=(
                        "VULNERABILITY_MODE is enabled. Intentional testbed vulnerabilities (SQLi, BOLA, Business flow) "
                        "are currently exploitable for experimental research."
                    ),
                    file_path="app/core/config.py",
                    line_number=None,
                    endpoint=None,
                    method=None,
                    parameter="VULNERABILITY_MODE",
                    raw_evidence={"VULNERABILITY_MODE": True},
                    remediation_guidance="Set VULNERABILITY_MODE=false to enforce hardened production logic.",
                )
            )

        return findings
