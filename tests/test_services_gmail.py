import json
from types import SimpleNamespace

import pytest

from providers.base import ProviderContext
from providers.google import _handle_service_disabled
from services.gmail import (
    GmailServiceDisabledError,
    list_messages,
)


class FakeHTTPClient:
    def __init__(self, responses):
        self._responses = responses
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append({
            "url": url,
            "headers": headers,
            "params": params,
            "timeout": timeout,
        })
        response = self._responses.pop(0)
        return response


class FakeResponse(SimpleNamespace):
    def json(self):
        return self.payload


def make_disabled_response():
    payload = {
        "error": {
            "status": "PERMISSION_DENIED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "SERVICE_DISABLED",
                }
            ],
        }
    }
    return FakeResponse(status_code=403, text=json.dumps(payload), payload={})


def test_list_messages_raises_service_disabled(monkeypatch):
    response = make_disabled_response()
    client = FakeHTTPClient([response])

    with pytest.raises(GmailServiceDisabledError) as exc:
        list_messages(client, "token", "123456789012-abc.apps.googleusercontent.com")

    error = exc.value
    assert error.project == "123456789012"
    assert "gmail.googleapis.com" in error.enable_url


def test_handle_service_disabled_prompts_and_opens_browser(monkeypatch):
    prompts = []
    opened = []
    echoes = []

    ctx = ProviderContext(
        provider=None,
        client_id="123456789012-abc.apps.googleusercontent.com",
        client_secret="secret",
        redirect_uri="http://localhost",
        access_token="token",
        http_client=None,
        prompt=lambda message: prompts.append(message) or "",
        confirm=lambda message: (echoes.append(message), True)[1],
        echo=lambda message: echoes.append(message),
        open_browser=lambda url: opened.append(url),
    )

    error = GmailServiceDisabledError("gmail.googleapis.com", ctx.client_id)
    _handle_service_disabled(ctx, error)

    assert opened == [error.enable_url]
    assert any("enable" in message.lower() for message in echoes)
