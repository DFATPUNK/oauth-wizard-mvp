from types import SimpleNamespace

import pytest

import scopes


class DummyProvider:
    def __init__(self):
        self.discovery_metadata = {
            "ServiceA": {
                "methods": [
                    {
                        "httpMethod": "GET",
                        "path": "/a",
                        "scopes": ["scope.read"],
                    },
                    {
                        "httpMethod": "POST",
                        "path": "/b",
                        "scopes": ["scope.write"],
                    },
                ]
            },
            "ServiceB": {
                "type": "google_discovery",
                "api": "fake",
                "version": "v1",
            },
        }
        self.scope_groups = {
            "ServiceA": {"read": ["scope.read"], "write": ["scope.write"]},
            "ServiceB": {"read": ["scope.extra"], "write": []},
        }

    def userinfo_endpoints(self):  # pragma: no cover - not used here
        return []


@pytest.fixture(autouse=True)
def restore_handlers():
    original = scopes._DISCOVERY_HANDLERS.copy()
    yield
    scopes._DISCOVERY_HANDLERS.clear()
    scopes._DISCOVERY_HANDLERS.update(original)


def test_discover_methods_prefers_inline_definitions():
    provider = DummyProvider()
    methods = scopes.discover_methods_for_service(provider, "ServiceA")
    assert len(methods) == 2
    assert methods[0]["path"] == "/a"


def test_google_discovery_handler_uses_mocked_requests(monkeypatch):
    provider = DummyProvider()

    def fake_get(url, timeout):
        assert url.endswith("/fake/v1/rest")
        doc = {
            "baseUrl": "https://api.example.com/",
            "resources": {
                "widgets": {
                    "methods": {
                        "list": {
                            "httpMethod": "GET",
                            "path": "widgets",
                            "description": "List widgets",
                            "scopes": ["scope.read"],
                        }
                    }
                }
            },
        }
        return SimpleNamespace(status_code=200, json=lambda: doc)

    monkeypatch.setattr(scopes.requests, "get", fake_get)
    methods = scopes.discover_methods_for_service(provider, "ServiceB")
    assert methods == [
        {
            "httpMethod": "GET",
            "path": "widgets",
            "description": "List widgets",
            "scopes": ["scope.read"],
            "baseUrl": "https://api.example.com/",
        }
    ]


def test_filter_methods_by_scopes_allows_intersection():
    provider = DummyProvider()
    methods = scopes.discover_methods_for_service(provider, "ServiceA")
    allowed = scopes.filter_methods_by_scopes(methods, ["scope.read"])
    assert len(allowed) == 1
    assert allowed[0]["path"] == "/a"


def test_count_methods_returns_summary():
    provider = DummyProvider()
    count, preview = scopes.count_methods(provider, "ServiceA", ["scope.read", "scope.write"])
    assert count == 2
    assert len(preview) == 2


def test_analyze_scope_gap_summarizes_missing_scopes():
    provider = DummyProvider()
    summary, missing = scopes.analyze_scope_gap(provider, ["scope.read"])
    assert missing == ["scope.extra", "scope.write"]
    service_a = next(item for item in summary if item["service"] == "ServiceA")
    assert service_a["read_missing"] == []
    assert service_a["write_missing"] == ["scope.write"]
