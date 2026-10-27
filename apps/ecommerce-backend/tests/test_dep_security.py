from agents.dependency_security.dependency_agent import DependencySecurityAgent


def test_dependency_security_scan():
    agent = DependencySecurityAgent(manifest_path="pyproject.toml")
    findings = agent.scan()

    assert len(findings) >= 1
    categories = {f.category for f in findings}
    assert "VULNERABLE_DEPENDENCY" in categories

    pkg_names = [f.raw_evidence.get("package") for f in findings]
    assert "python-jose" in pkg_names or "passlib" in pkg_names
