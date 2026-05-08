"""Tests for BYOK encryption + provider api_key_override + change-password validation."""
import pytest

from app.auth.byok import (
    BYOK_PROVIDERS,
    encrypt_key,
    decrypt_key,
    key_hint,
    resolve_user_provider_key,
)


def test_byok_roundtrip():
    plaintext = "vt-abcdef0123456789"
    ct = encrypt_key(plaintext)
    assert ct != plaintext
    assert decrypt_key(ct) == plaintext


def test_byok_decrypt_failure_returns_none():
    assert decrypt_key("not-a-valid-fernet-token") is None


def test_byok_hint_last_four():
    assert key_hint("supersecretkey1234") == "...1234"
    assert key_hint("ab") == "..."


def test_byok_supported_providers():
    assert set(BYOK_PROVIDERS) == {"virustotal", "greynoise", "ipinfo", "shodan"}


@pytest.mark.asyncio
async def test_resolve_user_provider_key_no_user():
    # Should short-circuit when no user_id supplied
    assert await resolve_user_provider_key(db=None, user_id=None, provider="virustotal") is None


@pytest.mark.asyncio
async def test_resolve_unsupported_provider():
    assert await resolve_user_provider_key(db=None, user_id="anything", provider="not-a-provider") is None


def test_provider_api_key_override():
    from app.enrichment.providers.virustotal import VirusTotalProvider
    from app.enrichment.providers.greynoise import GreyNoiseProvider
    from app.enrichment.providers.ipinfo import IPinfoProvider
    from app.enrichment.providers.shodan import ShodanProvider

    for cls in (VirusTotalProvider, GreyNoiseProvider, IPinfoProvider, ShodanProvider):
        inst = cls(api_key="user-supplied-key")
        assert inst.api_key_override == "user-supplied-key"
        # supported_kinds should be non-empty
        assert cls.supported_kinds, f"{cls.__name__} missing supported_kinds"


def test_change_password_request_validation():
    from app.routers.auth import ChangePasswordRequest

    # Too short
    with pytest.raises(Exception):
        ChangePasswordRequest(current_password="old", new_password="short1A")
    # Missing digit
    with pytest.raises(Exception):
        ChangePasswordRequest(current_password="old", new_password="NoDigitsHereAtAll")
    # All lowercase
    with pytest.raises(Exception):
        ChangePasswordRequest(current_password="old", new_password="alllowercase1234")
    # Valid
    ok = ChangePasswordRequest(current_password="old", new_password="GoodPass123word")
    assert ok.new_password == "GoodPass123word"


def test_provider_key_request_validation():
    from app.routers.auth import ProviderKeyRequest

    with pytest.raises(Exception):
        ProviderKeyRequest(api_key="tiny")
    ok = ProviderKeyRequest(api_key="  spaced-key-1234  ")
    assert ok.api_key == "spaced-key-1234"


def test_get_template_user_no_cookie():
    from app.ui.deps import get_template_user
    from unittest.mock import MagicMock

    req = MagicMock()
    req.cookies = {}
    assert get_template_user(req) is None


def test_get_template_user_with_valid_cookie():
    from app.ui.deps import get_template_user
    from app.auth.jwt import create_access_token
    from app.config import settings
    from unittest.mock import MagicMock

    token = create_access_token({
        "sub": "user-123",
        "tenant_id": "tenant-456",
        "email": "x@example.com",
        "role": "admin",
    })
    req = MagicMock()
    req.cookies = {settings.SESSION_COOKIE_NAME: token}
    user = get_template_user(req)
    assert user == {
        "user_id": "user-123",
        "tenant_id": "tenant-456",
        "email": "x@example.com",
        "role": "admin",
    }


def test_get_template_user_invalid_cookie():
    from app.ui.deps import get_template_user
    from app.config import settings
    from unittest.mock import MagicMock

    req = MagicMock()
    req.cookies = {settings.SESSION_COOKIE_NAME: "garbage.not.jwt"}
    assert get_template_user(req) is None
