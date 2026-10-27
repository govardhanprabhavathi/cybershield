"""Unit tests for RootCauseAnalyzer and SecurityPlaybookRunner."""


from security.orchestrator.playbooks import SecurityPlaybookRunner
from security.orchestrator.rca_engine import RootCauseAnalyzer


def test_rca_generation_sqli():
    """Verify detailed RCA output for CWE-89 SQL Injection."""
    rca = RootCauseAnalyzer.generate_rca(
        cwe_id="CWE-89",
        normalized_route="/api/v1/products/search",
        attack_payload="q=' UNION SELECT password FROM users--",
        vulnerable_file="apps/ecommerce-backend/app/services/product_service.py",
        vulnerable_line=48,
    )
    assert rca.cwe_id == "CWE-89"
    assert "SQL" in rca.cwe_title
    assert "Critical" in rca.blast_radius
    assert len(rca.preventive_recommendations) >= 2
    assert "SQLAlchemy" in rca.preventive_recommendations[0] or "parameterized" in rca.preventive_recommendations[0]
    assert rca.vulnerable_file == "apps/ecommerce-backend/app/services/product_service.py"
    assert rca.vulnerable_line == 48


def test_rca_generation_bola_and_logic():
    """Verify RCA synthesis for CWE-284 BOLA and CWE-840 Business Logic."""
    bola_rca = RootCauseAnalyzer.generate_rca(
        cwe_id="CWE-284",
        normalized_route="/api/v1/orders/{order_id}",
    )
    assert "Authorization" in bola_rca.cwe_title or "Access Control" in bola_rca.cwe_title
    assert "High" in bola_rca.blast_radius

    logic_rca = RootCauseAnalyzer.generate_rca(
        cwe_id="CWE-840",
        normalized_route="/api/v1/cart/items",
    )
    assert "Business Logic" in logic_rca.cwe_title
    assert any("gt=0" in r for r in logic_rca.preventive_recommendations)


def test_security_playbook_generation():
    """Verify that tailored defense playbooks are generated correctly."""
    sqli_playbook = SecurityPlaybookRunner.get_playbook_actions(
        cwe_id="CWE-89", session_id="sess_adversary_99"
    )
    assert len(sqli_playbook) >= 4
    action_types = [a.action_type for a in sqli_playbook]
    assert "CONTAIN_SESSION" in action_types
    assert "DRAFT_AST_PATCH" in action_types
    assert "VERIFY_SANDBOX" in action_types

    bola_playbook = SecurityPlaybookRunner.get_playbook_actions(
        cwe_id="CWE-284", session_id="sess_cross_tenant_12"
    )
    assert len(bola_playbook) >= 3
    assert any(a.action_type == "DRAFT_AST_PATCH" for a in bola_playbook)
