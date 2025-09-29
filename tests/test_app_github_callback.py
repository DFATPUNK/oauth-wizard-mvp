import json
from types import SimpleNamespace

import pytest

from app import create_app


class FakeResponse:
    status_code = 200
    text = "access_token=gho123&scope=repo%2Cgist&token_type=bearer"

    def json(self):
        raise ValueError("Not JSON")


@pytest.fixture
def github_provider():
    return SimpleNamespace(
        id="github",
        token_endpoint="https://example.com/token",
        userinfo_endpoint=None,
        token_request_headers={"Accept": "application/json"},
    )


def test_callback_handles_github_form_encoded_response(monkeypatch, tmp_path, github_provider):
    post_calls = {}

    def fake_post(url, data=None, headers=None):
        post_calls["url"] = url
        post_calls["data"] = data
        post_calls["headers"] = headers
        return FakeResponse()

    monkeypatch.setattr("requests.post", fake_post)
    monkeypatch.chdir(tmp_path)

    result_path = tmp_path / "result.json"
    app = create_app(
        github_provider,
        client_id="client",
        client_secret="secret",
        redirect_uri="http://localhost/callback",
        result_path=str(result_path),
    )

    client = app.test_client()
    response = client.get("/callback?code=abc123")

    assert response.status_code == 200
    assert post_calls["url"] == github_provider.token_endpoint
    assert post_calls["headers"] == {"Accept": "application/json"}

    env_contents = (tmp_path / ".env").read_text()
    assert "ACCESS_TOKEN=gho123" in env_contents

    tokens = json.loads(result_path.read_text())
    assert tokens["access_token"] == "gho123"
    assert tokens["token_type"] == "bearer"
    assert tokens["scope"] == "repo,gist"
