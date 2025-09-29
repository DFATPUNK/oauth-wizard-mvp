"""GitHub provider implementation for the OAuth wizard."""
from __future__ import annotations

import json
import textwrap
from typing import Dict, Iterable, List, Optional

import requests

from providers.base import EndpointInfo, ProviderAction, ProviderContext
from services.github import (
    GitHubRateLimitError,
    GitHubServiceError,
    fetch_primary_email,
    fetch_user_profile,
    list_repositories,
)
from services.zapier_sync import build_menu_action


class GitHubProvider:
    id = "github"
    name = "GitHub"
    authorize_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    userinfo_endpoint = "https://api.github.com/user"
    tokeninfo_endpoint: Optional[str] = None

    def __init__(self) -> None:
        self.base_scopes = ["read:user", "user:email"]
        self.scope_groups: Dict[str, Dict[str, List[str]]] = {
            "Profile": {"read": ["read:user", "user:email"], "write": []},
            "Repositories": {"read": ["public_repo"], "write": ["repo"]},
            "Organizations": {"read": ["read:org"], "write": ["admin:org"]},
        }
        base_url = "https://api.github.com"
        self.discovery_metadata = {
            "Profile": {
                "methods": [
                    {
                        "httpMethod": "GET",
                        "path": "/user",
                        "description": "Retrieve the authenticated user's profile.",
                        "scopes": ["read:user"],
                        "baseUrl": base_url,
                    },
                    {
                        "httpMethod": "GET",
                        "path": "/user/emails",
                        "description": "List email addresses for the authenticated user.",
                        "scopes": ["user:email"],
                        "baseUrl": base_url,
                    },
                ]
            },
            "Repositories": {
                "methods": [
                    {
                        "httpMethod": "GET",
                        "path": "/user/repos",
                        "description": "List repositories the user can access.",
                        "scopes": ["public_repo"],
                        "baseUrl": base_url,
                    },
                    {
                        "httpMethod": "POST",
                        "path": "/user/repos",
                        "description": "Create a repository for the authenticated user.",
                        "scopes": ["repo"],
                        "baseUrl": base_url,
                    },
                ]
            },
        }

    def build_authorization_url(self, client_id: str, redirect_uri: str, scopes: Iterable[str]) -> str:
        scope_str = "%20".join(sorted(scopes))
        return (
            f"{self.authorize_endpoint}?client_id={client_id}"
            f"&redirect_uri={redirect_uri}&scope={scope_str}&allow_signup=true"
        )

    def refresh_access_token(self, client_id: str, client_secret: str, refresh_token: str) -> Optional[Dict]:
        return None

    def fetch_token_scopes(self, access_token: str) -> List[str]:
        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                timeout=10,
            )
        except Exception:
            return []
        if response.status_code != 200:
            return []
        scopes_header = response.headers.get("X-OAuth-Scopes", "")
        scopes = [scope.strip() for scope in scopes_header.split(",") if scope.strip()]
        return sorted(set(scopes))

    def fetch_user_email(self, access_token: str) -> Optional[str]:
        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                timeout=10,
            )
        except Exception:
            return None
        if response.status_code == 200:
            data = response.json()
            return data.get("email")
        return None

    def userinfo_endpoints(self) -> List[EndpointInfo]:
        return [
            EndpointInfo(
                service="GitHub API",
                method="GET",
                url="https://api.github.com/user",
                requires=["read:user"],
                example="curl -H 'Authorization: Bearer $ACCESS_TOKEN' https://api.github.com/user",
            ),
        ]

    def sign_in_snippet(self, client_id: str, redirect_uri: str, scopes: Iterable[str]) -> str:
        scope_str = "%20".join(sorted(scopes))
        href = (
            f"{self.authorize_endpoint}?client_id={client_id}"
            f"&redirect_uri={redirect_uri}&scope={scope_str}&allow_signup=true"
        )
        template = textwrap.dedent(
            """<a href="{href}">
  <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="Sign in with GitHub" style="height:40px;">
</a>"""
        )
        return template.format(href=href)

    def menu_actions(self) -> List[ProviderAction]:
        def _handle_error(ctx: ProviderContext, exc: GitHubServiceError) -> None:
            if isinstance(exc, GitHubRateLimitError):
                ctx.echo(str(exc))
                return
            ctx.echo(f"⚠️ {exc}")

        def _http_client(ctx: ProviderContext):
            return ctx.http_client or requests

        def show_profile(ctx: ProviderContext) -> None:
            try:
                profile = fetch_user_profile(_http_client(ctx), ctx.access_token)
            except GitHubServiceError as exc:
                _handle_error(ctx, exc)
                return
            ctx.echo(json.dumps(profile, indent=2))

        def show_email(ctx: ProviderContext) -> None:
            try:
                email = fetch_primary_email(_http_client(ctx), ctx.access_token)
            except GitHubServiceError as exc:
                _handle_error(ctx, exc)
                return
            if email:
                ctx.echo(f"📧 Primary email: {email}")
            else:
                ctx.echo("ℹ️ No primary email returned (scope missing or not set).")

        def show_repositories(ctx: ProviderContext) -> None:
            try:
                repos = list_repositories(_http_client(ctx), ctx.access_token)
            except GitHubServiceError as exc:
                _handle_error(ctx, exc)
                return
            if not repos:
                ctx.echo("ℹ️ No repositories returned.")
                return
            ctx.echo("\n📂 Recent repositories:")
            for repo in repos:
                visibility = "private" if repo["private"] else "public"
                line = f"- {repo['name']} ({visibility})"
                if repo["html_url"]:
                    line += f" → {repo['html_url']}"
                ctx.echo(line)
                if repo["description"]:
                    ctx.echo(f"    {repo['description']}")

        actions = [
            ProviderAction(
                key="github_profile",
                label="GitHub: show user profile JSON",
                handler=show_profile,
                requires_any_scopes=["read:user"],
            ),
            ProviderAction(
                key="github_email",
                label="GitHub: show primary email",
                handler=show_email,
                requires_any_scopes=["user:email"],
                missing_scope_message="⚠️ GitHub email scope missing. Add 'user:email' and re-auth.",
            ),
            ProviderAction(
                key="github_repos",
                label="GitHub: list recent repositories",
                handler=show_repositories,
                requires_any_scopes=["repo", "public_repo"],
                missing_scope_message="⚠️ GitHub repo scope missing. Add 'repo' or 'public_repo' and re-auth.",
            ),
        ]

        zapier_action = build_menu_action(self.id)
        if zapier_action:
            actions.append(zapier_action)

        return actions

    def welcome_text(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            """
            👋 Welcome to the GitHub OAuth wizard!
            If you already generated credentials in GitHub Developer Settings, choose option (1) to upload them.
            Otherwise select option (3) and we'll walk you through creating an OAuth app.
            """
        ).strip()

    def manual_entry_instructions(self) -> str:
        return textwrap.dedent(
            """
            ✍️ Paste your GitHub OAuth app credentials below.
            Manage your apps at: https://github.com/settings/developers
            """
        ).strip()

    def app_creation_instructions(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            f"""
            🛠️ Create a new OAuth app at https://github.com/settings/applications/new
            Recommended values:
            • Application name: OAuth Wizard Demo
            • Homepage URL: https://example.com
            • Authorization callback URL: {redirect_uri}
            After creation, copy the Client ID and generate a new Client Secret.
            """
        ).strip()

    def load_credentials_from_file(self, path: str) -> tuple[str, str]:
        with open(path) as fh:
            data = json.load(fh)
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")
        if not client_id or not client_secret:
            raise ValueError("GitHub JSON must contain 'client_id' and 'client_secret'.")
        return client_id, client_secret

    def validate_client_id(self, client_id: str) -> bool:
        return bool(client_id) and len(client_id) == 20

    def validate_client_secret(self, client_secret: str) -> bool:
        return bool(client_secret) and len(client_secret) >= 35


provider = GitHubProvider()
