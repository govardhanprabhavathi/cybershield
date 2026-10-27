from agents.secret_security.secret_agent import SecretSecurityAgent
from security.rules.secret_patterns import calculate_shannon_entropy, mask_secret


def test_secret_entropy_calculation():
    low_entropy = calculate_shannon_entropy("aaaaaaaabbbbbbbb")
    high_entropy = calculate_shannon_entropy("7fA9!qK2#zP8$mX1@vL4&eR0")
    assert high_entropy > low_entropy
    assert high_entropy > 4.0


def test_secret_masking():
    masked = mask_secret("my-super-secret-key-1234")
    assert masked.startswith("my")
    assert masked.endswith("34")
    assert "super" not in masked
    assert "*" in masked


def test_secret_security_scan(tmp_path):
    # Create a temporary file with a hardcoded JWT key
    test_file = tmp_path / "settings_leak.py"
    test_file.write_text('JWT_SECRET = "super-secret-jwt-signing-key-for-cybershield-tokens-9876"\n')

    agent = SecretSecurityAgent(target_dir=str(tmp_path))
    findings = agent.scan()

    assert len(findings) >= 1
    assert findings[0].category == "HARDCODED_SECRET"
    assert findings[0].cwe_id == "CWE-798"
    assert "masked_value" in findings[0].raw_evidence
