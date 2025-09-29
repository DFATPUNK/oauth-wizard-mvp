from types import SimpleNamespace

import providers.github as github_module

from providers.github import GitHubProvider


def test_build_authorization_url_encodes_values():
    provider = GitHubProvider()
    url = provider.build_authorization_url("abc", "http://localhost:8000/callback", ["read:user", "user:email"])
    assert "client_id=abc" in url
    assert "redirect_uri=http://localhost:8000/callback" in url
    assert "scope=read:user%20user:email" in url
    assert url.endswith("allow_signup=true")


def test_fetch_token_scopes_reads_header(monkeypatch):
    provider = GitHubProvider()

    def fake_get(url, headers, timeout):
        return SimpleNamespace(status_code=200, headers={"X-OAuth-Scopes": "repo, user:email"})

    monkeypatch.setattr("providers.github.requests.get", fake_get)
    scopes = provider.fetch_token_scopes("token")
    assert scopes == ["repo", "user:email"]


def test_fetch_user_email_returns_value(monkeypatch):
    provider = GitHubProvider()

    def fake_get(url, headers, timeout):
        return SimpleNamespace(status_code=200, json=lambda: {"email": "octocat@example.com"})

    monkeypatch.setattr("providers.github.requests.get", fake_get)
    email = provider.fetch_user_email("token")
    assert email == "octocat@example.com"


def test_sign_in_snippet_mentions_github():
    provider = GitHubProvider()
    snippet = provider.sign_in_snippet("abc", "http://localhost/callback", ["read:user"])
    assert "Sign in with GitHub" in snippet
    assert "client_id=abc" in snippet


def test_menu_action_invokes_repository_listing(monkeypatch, capsys):
    provider = GitHubProvider()

    action = next(a for a in provider.menu_actions() if a.key == "github_repos")

    def fake_list(http_client, access_token):
        return [
            {"name": "octocat/Hello-World", "private": False, "html_url": "", "description": ""}
        ]

    monkeypatch.setattr("providers.github.list_repositories", fake_list)

    context = SimpleNamespace(
        provider=provider,
        client_id="id",
        client_secret="secret",
        redirect_uri="http://localhost/callback",
        access_token="token",
        http_client=None,
        prompt=lambda message: "",
        confirm=lambda message: True,
        echo=lambda message: print(message),
        open_browser=lambda url: None,
    )

    action.handler(context)
    captured = capsys.readouterr()
    assert "octocat/Hello-World" in captured.out


def test_menu_action_handles_rate_limit(monkeypatch, capsys):
    provider = GitHubProvider()

    action = next(a for a in provider.menu_actions() if a.key == "github_repos")

    def fake_list(http_client, access_token):
        raise github_module.GitHubRateLimitError("1700000000")

    monkeypatch.setattr("providers.github.list_repositories", fake_list)

    context = SimpleNamespace(
        provider=provider,
        client_id="id",
        client_secret="secret",
        redirect_uri="http://localhost/callback",
        access_token="token",
        http_client=None,
        prompt=lambda message: "",
        confirm=lambda message: True,
        echo=lambda message: print(message),
        open_browser=lambda url: None,
    )

    action.handler(context)
    captured = capsys.readouterr()
    assert "rate limit" in captured.out.lower()
