from __future__ import annotations

import json
import re
import textwrap
from typing import Dict, Iterable, List, Optional

import requests

from providers.base import EndpointInfo, ProviderAction, ProviderContext


_USER_AGENT = "OAuth Wizard CLI (support@example.com)"


def _authorization_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": _USER_AGENT,
    }


class BasecampProvider:
    id = "basecamp"
    name = "Basecamp"
    authorize_endpoint = "https://launchpad.37signals.com/authorization/new"
    token_endpoint = "https://launchpad.37signals.com/authorization/token"
    userinfo_endpoint = "https://launchpad.37signals.com/authorization.json"
    tokeninfo_endpoint: Optional[str] = None
    token_request_headers: Dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    def __init__(self) -> None:
        self.base_scopes = ["openid", "profile", "email"]
        self.scope_groups: Dict[str, Dict[str, List[str]]] = {
            "Identity": {"read": ["openid", "profile", "email"], "write": []},
            "Offline access": {"read": [], "write": ["offline_access"]},
            "Projects": {
                "read": ["projects:read"],
                "write": ["projects:write"],
            },
        }
        self.discovery_metadata = {
            "Identity": {
                "type": "basecamp_catalog",
                "base_url": "https://launchpad.37signals.com",
                "method_map": [
                    {
                        "path": "/authorization.json",
                        "httpMethod": "GET",
                        "description": "Retrieve the authorized accounts and identity profile.",
                        "scopes": ["openid", "profile", "email"],
                    }
                ],
                "docs_url": "https://github.com/basecamp/api/blob/master/sections/authentication.md",
            },
            "Projects": {
                "type": "basecamp_catalog",
                "base_url": "https://3.basecampapi.com",
                "method_map": [
                    {
                        "path": "/{account_id}/projects.json",
                        "httpMethod": "GET",
                        "description": "List projects for the first connected Basecamp account.",
                        "scopes": ["projects:read"],
                    },
                    {
                        "path": "/{account_id}/people.json",
                        "httpMethod": "GET",
                        "description": "List people in the Basecamp account.",
                        "scopes": ["projects:read"],
                    },
                    {
                        "path": "/{account_id}/buckets/{project_id}/todosets.json",
                        "httpMethod": "GET",
                        "description": "Inspect todo sets inside a project bucket.",
                        "scopes": ["projects:write"],
                    },
                ],
                "docs_url": "https://github.com/basecamp/bc3-api",
            },
        }

    # Protocol implementation -------------------------------------------------
    def build_authorization_url(
        self, client_id: str, redirect_uri: str, scopes: Iterable[str]
    ) -> str:
        scope_str = "%20".join(sorted(scopes))
        return (
            f"{self.authorize_endpoint}?type=web_server"
            f"&client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&response_type=code"
            f"&scope={scope_str}"
        )

    def refresh_access_token(
        self, client_id: str, client_secret: str, refresh_token: str
    ) -> Optional[Dict]:
        try:
            response = requests.post(
                self.token_endpoint,
                data={
                    "type": "refresh",
                    "client_id": client_id,
                    "redirect_uri": "oob",
                    "client_secret": client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
                headers=self.token_request_headers,
                timeout=15,
            )
        except Exception:
            return None
        if response.status_code == 200:
            return response.json()
        return None

    def fetch_token_scopes(self, access_token: str) -> List[str]:
        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers=_authorization_headers(access_token),
                timeout=10,
            )
        except Exception:
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        scopes = data.get("scopes") or []
        if isinstance(scopes, str):
            scopes = [scope.strip() for scope in scopes.split() if scope.strip()]
        return sorted(set(scopes))

    def fetch_user_email(self, access_token: str) -> Optional[str]:
        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers=_authorization_headers(access_token),
                timeout=10,
            )
        except Exception:
            return None
        if response.status_code != 200:
            return None
        data = response.json()
        identity = data.get("identity") or {}
        return identity.get("email_address")

    def userinfo_endpoints(self) -> List[EndpointInfo]:
        return [
            EndpointInfo(
                service="Basecamp Authorization",
                method="GET",
                url="https://launchpad.37signals.com/authorization.json",
                requires=["openid", "profile", "email"],
                example=(
                    "curl -H 'Authorization: Bearer $ACCESS_TOKEN' "
                    "https://launchpad.37signals.com/authorization.json"
                ),
            )
        ]

    def sign_in_snippet(
        self, client_id: str, redirect_uri: str, scopes: Iterable[str]
    ) -> str:
        scope_str = "%20".join(sorted(scopes))
        return textwrap.dedent(
            """
            <a href="{href}">
              <button style="padding:10px 16px;background:#2e5bff;color:#fff;border:none;border-radius:4px;">
                Sign in with Basecamp
              </button>
            </a>
            """
        ).strip().format(
            href=(
                f"{self.authorize_endpoint}?type=web_server&client_id={client_id}"
                f"&redirect_uri={redirect_uri}&response_type=code&scope={scope_str}"
            )
        )

    def menu_actions(self) -> List[ProviderAction]:
        def _http(ctx: ProviderContext):
            return ctx.http_client or requests

        def show_accounts(ctx: ProviderContext) -> None:
            http = _http(ctx)
            response = http.get(
                self.userinfo_endpoint,
                headers=_authorization_headers(ctx.access_token),
                timeout=10,
            )
            if response.status_code != 200:
                ctx.echo(f"⚠️ Failed to load accounts: {response.status_code} {response.text}")
                return
            data = response.json()
            accounts = data.get("accounts", [])
            if not accounts:
                ctx.echo("ℹ️ No Basecamp accounts returned for this token.")
                return
            ctx.echo("\n🏢 Connected Basecamp accounts:")
            for account in accounts:
                ctx.echo(f"  • {account.get('name')} (id={account.get('id')})")

        def list_projects(ctx: ProviderContext) -> None:
            http = _http(ctx)
            response = http.get(
                self.userinfo_endpoint,
                headers=_authorization_headers(ctx.access_token),
                timeout=10,
            )
            if response.status_code != 200:
                ctx.echo("⚠️ Unable to determine account information for projects.")
                return
            data = response.json()
            accounts = data.get("accounts") or []
            if not accounts:
                ctx.echo("ℹ️ No accounts available to list projects from.")
                return
            account_id = accounts[0].get("id")
            if not account_id:
                ctx.echo("⚠️ Account identifier missing in response.")
                return
            url = f"https://3.basecampapi.com/{account_id}/projects.json"
            response = http.get(
                url,
                headers={**_authorization_headers(ctx.access_token), "Accept": "application/json"},
                timeout=10,
            )
            if response.status_code != 200:
                ctx.echo(f"⚠️ Could not list projects: {response.status_code} {response.text}")
                return
            projects = response.json()
            if not projects:
                ctx.echo("ℹ️ No projects returned.")
                return
            ctx.echo("\n📋 Recent projects:")
            for project in projects[:5]:
                ctx.echo(f"  • {project.get('name')} → {project.get('app_url')}")

        return [
            ProviderAction(
                key="basecamp_accounts",
                label="Basecamp: list connected accounts",
                handler=show_accounts,
                requires_any_scopes=["openid", "profile"],
                missing_scope_message="⚠️ Identity scopes missing. Re-auth with openid/profile/email.",
            ),
            ProviderAction(
                key="basecamp_projects",
                label="Basecamp: list first account projects",
                handler=list_projects,
                requires_any_scopes=["projects:read", "offline_access"],
                missing_scope_message="⚠️ Add 'projects:read' (and optionally offline_access) to browse projects.",
            ),
        ]

    def welcome_text(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            """
            👋 Welcome to the Basecamp OAuth wizard!
            Upload an existing Launchpad client file or let us guide you to the Basecamp developer console.
            """
        ).strip()

    def manual_entry_instructions(self) -> str:
        return textwrap.dedent(
            """
            ✍️ Paste the Client ID and Secret from your Basecamp Launchpad application.
            Manage credentials at https://integrate.37signals.com/apps.
            """
        ).strip()

    def app_creation_instructions(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            f"""
            🛠️ Create a new OAuth application at https://integrate.37signals.com/apps.
            Recommended values:
            • Redirect URI: {redirect_uri}
            • Default scopes: openid profile email offline_access projects:read
            After saving, copy the Client ID and Secret so we can finish the flow.
            """
        ).strip()

    def load_credentials_from_file(self, path: str) -> tuple[str, str]:
        with open(path) as fh:
            data = json.load(fh)
        client_id = data.get("client_id") or data.get("app_id")
        client_secret = data.get("client_secret") or data.get("secret")
        if not client_id or not client_secret:
            raise ValueError(
                "Basecamp client JSON must include 'client_id' and 'client_secret'."
            )
        return client_id, client_secret

    def validate_client_id(self, client_id: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-f]{32}", client_id))

    def validate_client_secret(self, client_secret: str) -> bool:
        return bool(client_secret) and len(client_secret) >= 32


provider = BasecampProvider()
