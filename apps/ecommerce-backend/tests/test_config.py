from app.core.config import Settings, get_settings


def test_settings_initialization():
    settings = get_settings()
    assert settings.PROJECT_NAME == "CyberShield E-Commerce Defense Platform"
    assert settings.API_V1_PREFIX == "/api/v1"
    assert settings.SECURITY_V1_PREFIX == "/security/v1"
    assert settings.JWT_ALGORITHM == "HS256"


def test_graduated_response_thresholds():
    settings = get_settings()
    assert 0 < settings.RISK_THRESHOLD_MONITOR < settings.RISK_THRESHOLD_THROTTLE
    assert settings.RISK_THRESHOLD_THROTTLE < settings.RISK_THRESHOLD_CONTAIN
    assert 0.0 < settings.CONFIDENCE_THRESHOLD_CONTAIN <= 1.0


def test_environment_flags():
    dev_settings = Settings(ENVIRONMENT="development")
    assert not dev_settings.is_production

    prod_settings = Settings(ENVIRONMENT="production")
    assert prod_settings.is_production
