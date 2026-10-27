from app.core.config import Settings

from agents.configuration_security.config_agent import ConfigurationSecurityAgent


def test_config_security_scan_detects_default_keys():
    test_settings = Settings(
        SECRET_KEY="cybershield-dev-secret-key-32-chars-minimum-length-needed-1234",
        JWT_SECRET="super-secret-jwt-signing-key-for-cybershield-tokens-9876",
        DEBUG=True,
        VULNERABILITY_MODE=True,
    )
    agent = ConfigurationSecurityAgent(settings=test_settings)
    findings = agent.scan()

    assert len(findings) >= 3
    categories = {f.category for f in findings}
    assert "INSECURE_CONFIGURATION" in categories

    titles = [f.title for f in findings]
    assert any("Default Development Secret Key" in t for t in titles)
    assert any("Default JWT Signing Secret" in t for t in titles)
    assert any("Interactive Debug Mode" in t for t in titles)
