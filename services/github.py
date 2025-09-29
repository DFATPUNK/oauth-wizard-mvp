"""Helpers for interacting with GitHub APIs via the OAuth wizard."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

API_BASE = "https://api.github.com"
ACCEPT_HEADER = "application/vnd.github+json"


class GitHubServiceError(RuntimeError):
    """Base exception raised for GitHub API errors."""

    def __init__(self, message: str, *, response: Any | None = None) -> None:
        super().__init__(message)
        self.response = response


class GitHubRateLimitError(GitHubServiceError):
    """Raised when the GitHub API rate limit has been exhausted."""

    def __init__(self, reset: Optional[str], *, response: Any | None = None) -> None:
        message = "GitHub API rate limit exceeded."
        if reset:
            message += f" Resets at {reset}."
        super().__init__(message, response=response)
        self.reset = reset


def _headers(access_token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": ACCEPT_HEADER,
    }


def _raise_for_error(response) -> None:
    if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        raise GitHubRateLimitError(response.headers.get("X-RateLimit-Reset"), response=response)
    raise GitHubServiceError(
        f"GitHub API error: {response.status_code} {response.text}", response=response
    )


def list_repositories(
    http_client,
    access_token: str,
    *,
    visibility: str = "all",
    per_page: int = 5,
) -> List[Dict[str, Any]]:
    """Return a summary of the authenticated user's repositories."""

    params = {
        "visibility": visibility,
        "affiliation": "owner,collaborator,organization_member",
        "sort": "updated",
        "direction": "desc",
        "per_page": per_page,
    }
    response = http_client.get(
        f"{API_BASE}/user/repos",
        headers=_headers(access_token),
        params=params,
        timeout=20,
    )
    if response.status_code != 200:
        _raise_for_error(response)

    data = response.json()
    repos: List[Dict[str, Any]] = []
    for item in data:
        repos.append(
            {
                "name": item.get("full_name") or item.get("name"),
                "private": bool(item.get("private")),
                "html_url": item.get("html_url", ""),
                "description": item.get("description") or "",
            }
        )
    return repos


def fetch_primary_email(http_client, access_token: str) -> Optional[str]:
    """Return the primary email address for the authenticated user."""

    response = http_client.get(
        f"{API_BASE}/user/emails",
        headers=_headers(access_token),
        timeout=20,
    )
    if response.status_code != 200:
        _raise_for_error(response)

    emails = response.json()
    if not isinstance(emails, list):
        return None
    primary = next((item for item in emails if item.get("primary")), None)
    if primary:
        return primary.get("email")
    if emails:
        return emails[0].get("email")
    return None


def fetch_user_profile(http_client, access_token: str) -> Dict[str, Any]:
    """Return the authenticated user's profile information."""

    response = http_client.get(
        f"{API_BASE}/user",
        headers=_headers(access_token),
        timeout=20,
    )
    if response.status_code != 200:
        _raise_for_error(response)
    return response.json()
