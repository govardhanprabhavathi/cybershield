from agents.code_security.code_security_agent import CodeSecurityAgent


def test_code_security_detects_sqli_and_bola():
    agent = CodeSecurityAgent(target_dir="apps/ecommerce-backend/app")
    findings = agent.scan()

    assert len(findings) >= 2

    categories = {f.category for f in findings}
    assert "SQL_INJECTION" in categories
    assert "BOLA_IDOR" in categories

    # Verify SQL Injection Finding details
    sqli_findings = [f for f in findings if f.category == "SQL_INJECTION"]
    assert len(sqli_findings) >= 1
    sqli = sqli_findings[0]
    assert sqli.cwe_id == "CWE-89"
    assert sqli.endpoint == "/api/v1/products"
    assert sqli.parameter == "search"
    assert sqli.confidence >= 0.90
    assert "product_service.py" in sqli.file_path

    # Verify BOLA Finding details
    bola_findings = [f for f in findings if f.category == "BOLA_IDOR"]
    assert len(bola_findings) >= 1
    bola = bola_findings[0]
    assert bola.cwe_id == "CWE-284"
    assert bola.endpoint == "/api/v1/orders/{order_id}"
    assert bola.confidence >= 0.90
    assert "order_service.py" in bola.file_path
