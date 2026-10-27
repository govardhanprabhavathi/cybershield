"""Dynamic Attack Probing Payloads, Detection Signatures and Verification Oracles for DAST."""

from dataclasses import dataclass, field


@dataclass
class SQLiProbeVector:
    payload: str
    description: str
    expected_error_substrings: list[str] = field(
        default_factory=lambda: [
            "database execution error",
            "syntax error",
            "operationalerror",
            "unrecognized token",
            "sqlite3",
            "psycopg2",
            "sql syntax",
        ]
    )


SQLI_PROBE_VECTORS = [
    SQLiProbeVector(
        payload="laptop' OR '1'='1",
        description="Boolean-based OR tautology payload attempting to alter query selection logic.",
    ),
    SQLiProbeVector(
        payload="laptop'--",
        description="Inline comment termination payload attempting to truncate query tail.",
    ),
    SQLiProbeVector(
        payload="laptop'\"",
        description="Unbalanced quote payload designed to trigger SQL parser syntax errors.",
    ),
]


@dataclass
class BusinessFlowProbeVector:
    quantity: int
    description: str


BUSINESS_FLOW_PROBES = [
    BusinessFlowProbeVector(
        quantity=-1,
        description="Negative single unit quantity attempting line-item deduction abuse.",
    ),
    BusinessFlowProbeVector(
        quantity=-10,
        description="Large negative quantity attempting cart total deflation.",
    ),
    BusinessFlowProbeVector(
        quantity=0,
        description="Zero quantity item addition testing boundary invariants.",
    ),
]


@dataclass
class ResourceConsumptionProbeVector:
    limit: int
    max_acceptable_limit: int = 100
    description: str = "Excessive limit parameter attempting memory or database resource exhaustion."


RESOURCE_PROBE = ResourceConsumptionProbeVector(limit=10000, max_acceptable_limit=100)
