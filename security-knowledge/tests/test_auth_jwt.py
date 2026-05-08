import pytest
from app.auth.jwt import create_access_token, decode_access_token


def test_create_and_decode_token():
    data = {"sub": "tenant-123", "tenant_id": "tenant-123"}
    token = create_access_token(data)
    assert isinstance(token, str)
    decoded = decode_access_token(token)
    assert decoded["tenant_id"] == "tenant-123"


def test_invalid_token_returns_none():
    result = decode_access_token("invalid.token.here")
    assert result is None


def test_token_has_expiry():
    from app.auth.jwt import create_access_token
    import jose.jwt as jwt
    data = {"sub": "t1", "tenant_id": "t1"}
    token = create_access_token(data)
    from app.config import settings
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert "exp" in payload
