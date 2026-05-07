import pytest
from app.config import settings


def test_settings_has_database_url():
    assert hasattr(settings, "DATABASE_URL")
    assert "postgresql" in settings.DATABASE_URL


def test_settings_has_redis_url():
    assert hasattr(settings, "REDIS_URL")


def test_settings_has_secret_key():
    assert hasattr(settings, "SECRET_KEY")
    assert len(settings.SECRET_KEY) > 0


def test_settings_has_embedding_dim():
    assert hasattr(settings, "EMBEDDING_DIM")
    assert settings.EMBEDDING_DIM > 0


def test_settings_has_algorithm():
    assert hasattr(settings, "ALGORITHM")
    assert settings.ALGORITHM == "HS256"


def test_settings_has_api_keys():
    for field in ["NVD_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY"]:
        assert hasattr(settings, field)


def test_settings_has_llm_config():
    for field in ["LLM_BASE_URL", "LLM_API_KEY"]:
        assert hasattr(settings, field)
