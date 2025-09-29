import pytest
from types import SimpleNamespace

from services.github import (
    GitHubRateLimitError,
    GitHubServiceError,
    fetch_primary_email,
    fetch_user_profile,
    list_repositories,
)


def _fake_response(status_code=200, json_data=None, headers=None, text=""):
    if json_data is None:
        json_data = {}
    if headers is None:
        headers = {}
    return SimpleNamespace(
        status_code=status_code,
        json=lambda: json_data,
        headers=headers,
        text=text,
    )


def test_list_repositories_returns_summary():
    responses = [
        _fake_response(
            json_data=[
                {
                    "full_name": "octocat/Hello-World",
                    "private": False,
                    "html_url": "https://github.com/octocat/Hello-World",
                    "description": "A friendly repository",
                },
                {
                    "name": "private-repo",
                    "private": True,
                    "html_url": "https://github.com/octocat/private-repo",
                    "description": None,
                },
            ]
        )
    ]

    def fake_get(url, headers, params, timeout):
        assert url.endswith("/user/repos")
        assert params["per_page"] == 5
        return responses.pop(0)

    http_client = SimpleNamespace(get=fake_get)

    repos = list_repositories(http_client, "token")

    assert repos == [
        {
            "name": "octocat/Hello-World",
            "private": False,
            "html_url": "https://github.com/octocat/Hello-World",
            "description": "A friendly repository",
        },
        {
            "name": "private-repo",
            "private": True,
            "html_url": "https://github.com/octocat/private-repo",
            "description": "",
        },
    ]


def test_list_repositories_raises_on_error():
    response = _fake_response(status_code=500, text="boom")

    def fake_get(url, headers, params, timeout):
        return response

    http_client = SimpleNamespace(get=fake_get)

    with pytest.raises(GitHubServiceError):
        list_repositories(http_client, "token")


def test_fetch_primary_email_prefers_primary_entry():
    response = _fake_response(
        json_data=[
            {"email": "secondary@example.com", "primary": False},
            {"email": "primary@example.com", "primary": True},
        ]
    )

    def fake_get(url, headers, timeout):
        return response

    http_client = SimpleNamespace(get=fake_get)
    email = fetch_primary_email(http_client, "token")
    assert email == "primary@example.com"


def test_fetch_primary_email_handles_rate_limit():
    response = _fake_response(
        status_code=403,
        headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1700000000"},
        text="rate limited",
    )

    def fake_get(url, headers, timeout):
        return response

    http_client = SimpleNamespace(get=fake_get)

    with pytest.raises(GitHubRateLimitError):
        fetch_primary_email(http_client, "token")


def test_fetch_user_profile_returns_payload():
    payload = {"login": "octocat"}
    response = _fake_response(json_data=payload)

    def fake_get(url, headers, timeout):
        return response

    http_client = SimpleNamespace(get=fake_get)
    profile = fetch_user_profile(http_client, "token")
    assert profile == payload
