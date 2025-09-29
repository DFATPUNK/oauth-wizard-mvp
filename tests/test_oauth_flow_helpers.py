import json
from pathlib import Path
from types import SimpleNamespace

from oauth import flow


class DummyProvider:
    def __init__(self):
        self.refresh_called_with = None
        self.fetch_scopes_called_with = None
        self.fetch_email_called_with = None
        self.tokeninfo_endpoint = "https://example.com/tokeninfo"

    def refresh_access_token(self, client_id, client_secret, refresh_token):
        self.refresh_called_with = (client_id, client_secret, refresh_token)
        return {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
        }

    def fetch_token_scopes(self, access_token):
        self.fetch_scopes_called_with = access_token
        return ["scope.a", "scope.b"]

    def fetch_user_email(self, access_token):
        self.fetch_email_called_with = access_token
        return "user@example.com"

    def userinfo_endpoints(self):  # pragma: no cover - required by protocol
        return []


class NoopProvider(DummyProvider):
    def refresh_access_token(self, *args, **kwargs):  # pragma: no cover - ensures not called
        raise AssertionError("refresh_access_token should not be called")

    def fetch_token_scopes(self, *args, **kwargs):  # pragma: no cover
        raise AssertionError("fetch_token_scopes should not be called")

    def fetch_user_email(self, *args, **kwargs):  # pragma: no cover
        raise AssertionError("fetch_user_email should not be called")


class StubHTTPClient:
    def __init__(self):
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "timeout": timeout})
        return SimpleNamespace(status_code=200, json=lambda: {"email": "user@example.com"})


def test_safe_mask_partial_masking():
    token = "abcdefghijklmnopqrstuvwxyz"
    assert flow.safe_mask(token) == "abcdefghijkl…uvwxyz"


def test_safe_mask_short_token_returns_original():
    token = "short"
    assert flow.safe_mask(token) == token


def test_build_tokeninfo_url_uses_provider_endpoint():
    provider = DummyProvider()
    url = flow.build_tokeninfo_url(provider, "abc")
    assert url == "https://example.com/tokeninfo?access_token=abc"


def test_build_tokeninfo_url_without_endpoint_returns_none():
    provider = DummyProvider()
    provider.tokeninfo_endpoint = None
    assert flow.build_tokeninfo_url(provider, "abc") is None


def test_refresh_session_merges_sources_and_refreshes(tmp_path):
    result_path = tmp_path / ".last.json"
    result_path.write_text(json.dumps({"access_token": "old", "refresh_token": "refresh"}))
    env_path = tmp_path / ".env"
    env_path.write_text("ACCESS_TOKEN=env_old\nREFRESH_TOKEN=env_refresh\n")

    provider = DummyProvider()
    session = flow.refresh_session(
        provider,
        client_id="client",
        client_secret="secret",
        result_path=result_path,
        env_path=env_path,
    )

    assert session == {
        "access_token": "new-access-token",
        "refresh_token": "new-refresh-token",
        "email": "user@example.com",
        "scopes": ["scope.a", "scope.b"],
    }
    # Stored tokens take precedence over env tokens.
    assert provider.refresh_called_with == ("client", "secret", "refresh")
    assert provider.fetch_scopes_called_with == "new-access-token"
    assert provider.fetch_email_called_with == "new-access-token"
    stored = json.loads(result_path.read_text())
    assert stored["access_token"] == "new-access-token"
    assert stored["refresh_token"] == "new-refresh-token"


def test_refresh_session_without_tokens_returns_none(tmp_path):
    result_path = tmp_path / ".last.json"
    env_path = tmp_path / ".env"
    provider = NoopProvider()

    session = flow.refresh_session(
        provider,
        client_id="client",
        client_secret="secret",
        result_path=result_path,
        env_path=env_path,
    )

    assert session is None


def test_fetch_userinfo_invokes_http_client_with_bearer_header():
    http_client = StubHTTPClient()
    response = flow.fetch_userinfo(http_client, "https://example.com/userinfo", "token")

    assert response.status_code == 200
    assert http_client.calls == [
        {
            "url": "https://example.com/userinfo",
            "headers": {"Authorization": "Bearer token"},
            "timeout": 15,
        }
    ]
