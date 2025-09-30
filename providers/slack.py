from __future__ import annotations

import json
import re
import textwrap
from typing import Dict, Iterable, List, Optional

import requests

from providers.base import EndpointInfo, ProviderAction, ProviderContext


def _auth_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json;charset=utf-8",
    }


class SlackProvider:
    id = "slack"
    name = "Slack"
    authorize_endpoint = "https://slack.com/oauth/v2/authorize"
    token_endpoint = "https://slack.com/api/oauth.v2.access"
    userinfo_endpoint = "https://slack.com/api/users.profile.get"
    tokeninfo_endpoint: Optional[str] = None
    token_request_headers: Dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    def __init__(self) -> None:
        self.base_scopes = ["users:read"]
        self.scope_groups: Dict[str, Dict[str, List[str]]] = {
            "Workspace": {
                "read": ["team:read"],
                "write": ["team:write"],
            },
            "Users": {
                "read": ["users:read", "users:read.email"],
                "write": ["users.profile:write"],
            },
            "Channels": {
                "read": ["channels:read", "groups:read", "conversations:read"],
                "write": ["channels:manage", "chat:write", "chat:write.public"],
            },
        }
        self.discovery_metadata = {
            "Workspace": {
                "type": "slack_web_api",
                "base_url": "https://slack.com/api",
                "method_map": [
                    {
                        "path": "/team.info",
                        "httpMethod": "GET",
                        "description": "Get information about the current workspace.",
                        "scopes": ["team:read"],
                    },
                    {
                        "path": "/apps.connections.open",
                        "httpMethod": "POST",
                        "description": "Open an app-level websocket connection.",
                        "scopes": ["team:write"],
                    },
                ],
                "docs_url": "https://api.slack.com/methods/team.info",
            },
            "Users": {
                "type": "slack_web_api",
                "base_url": "https://slack.com/api",
                "method_map": [
                    {
                        "path": "/users.profile.get",
                        "httpMethod": "GET",
                        "description": "Fetch a user's profile, including email when permitted.",
                        "scopes": ["users:read", "users:read.email"],
                    },
                    {
                        "path": "/users.list",
                        "httpMethod": "GET",
                        "description": "List users in the workspace.",
                        "scopes": ["users:read"],
                    },
                    {
                        "path": "/users.profile.set",
                        "httpMethod": "POST",
                        "description": "Update profile fields for the authed user.",
                        "scopes": ["users.profile:write"],
                    },
                ],
                "docs_url": "https://api.slack.com/methods/users.profile.get",
            },
            "Channels": {
                "type": "slack_web_api",
                "base_url": "https://slack.com/api",
                "method_map": [
                    {
                        "path": "/conversations.list",
                        "httpMethod": "GET",
                        "description": "List public and private channels.",
                        "scopes": ["conversations:read", "channels:read"],
                    },
                    {
                        "path": "/chat.postMessage",
                        "httpMethod": "POST",
                        "description": "Send a message into a channel.",
                        "scopes": ["chat:write", "chat:write.public"],
                    },
                ],
                "docs_url": "https://api.slack.com/methods/conversations.list",
            },
        }

    # Protocol implementation -------------------------------------------------
    def build_authorization_url(
        self, client_id: str, redirect_uri: str, scopes: Iterable[str]
    ) -> str:
        scope_str = "%20".join(sorted(scopes))
        return (
            f"{self.authorize_endpoint}?client_id={client_id}"
            f"&redirect_uri={redirect_uri}&scope={scope_str}&user_scope={scope_str}"
        )

    def refresh_access_token(
        self, client_id: str, client_secret: str, refresh_token: str
    ) -> Optional[Dict]:
        try:
            response = requests.post(
                self.token_endpoint,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
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
                "https://slack.com/api/apps.permissions.scopes.list",
                headers=_auth_headers(access_token),
                timeout=10,
            )
        except Exception:
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        if not data.get("ok"):
            return []
        scopes: List[str] = []
        for section in data.get("scopes", {}).values():
            if isinstance(section, dict):
                for values in section.values():
                    if isinstance(values, list):
                        scopes.extend(values)
            elif isinstance(section, list):
                scopes.extend(section)
        return sorted(set(scopes))

    def fetch_user_email(self, access_token: str) -> Optional[str]:
        http = requests
        try:
            auth_response = http.get(
                "https://slack.com/api/auth.test",
                headers=_auth_headers(access_token),
                timeout=10,
            )
        except Exception:
            return None
        if auth_response.status_code != 200:
            return None
        payload = auth_response.json()
        if not payload.get("ok"):
            return None
        user_id = payload.get("user_id")
        if not user_id:
            return None
        try:
            profile_response = http.get(
                self.userinfo_endpoint,
                headers=_auth_headers(access_token),
                params={"user": user_id},
                timeout=10,
            )
        except Exception:
            return None
        if profile_response.status_code != 200:
            return None
        profile_payload = profile_response.json()
        if not profile_payload.get("ok"):
            return None
        profile = profile_payload.get("profile") or {}
        return profile.get("email")

    def userinfo_endpoints(self) -> List[EndpointInfo]:
        return [
            EndpointInfo(
                service="Slack Web API",
                method="GET",
                url="https://slack.com/api/auth.test",
                requires=["users:read"],
                example="curl -H 'Authorization: Bearer $ACCESS_TOKEN' https://slack.com/api/auth.test",
            ),
            EndpointInfo(
                service="Slack Web API",
                method="GET",
                url="https://slack.com/api/users.profile.get?user=$USER_ID",
                requires=["users:read"],
                example="curl -H 'Authorization: Bearer $ACCESS_TOKEN' 'https://slack.com/api/users.profile.get?user=$USER_ID'",
            ),
        ]

    def sign_in_snippet(
        self, client_id: str, redirect_uri: str, scopes: Iterable[str]
    ) -> str:
        scope_str = "%20".join(sorted(scopes))
        href = (
            f"{self.authorize_endpoint}?client_id={client_id}"
            f"&redirect_uri={redirect_uri}&scope={scope_str}&user_scope={scope_str}"
        )
        return textwrap.dedent(
            """
            <a href="{href}">
              <img src="https://a.slack-edge.com/80588/marketing/img/icons/icon_slack_hash_colored.png" alt="Sign in with Slack" style="height:40px;">
            </a>
            """
        ).strip().format(href=href)

    def menu_actions(self) -> List[ProviderAction]:
        def _http(ctx: ProviderContext):
            return ctx.http_client or requests

        def show_workspace(ctx: ProviderContext) -> None:
            http = _http(ctx)
            response = http.get(
                "https://slack.com/api/team.info",
                headers=_auth_headers(ctx.access_token),
                timeout=10,
            )
            data = response.json() if response.status_code == 200 else {"ok": False}
            if not data.get("ok"):
                ctx.echo("⚠️ Unable to fetch workspace info. Add 'team:read' scope and retry.")
                return
            team = data.get("team", {})
            ctx.echo("\n🏢 Workspace info:")
            ctx.echo(f"  • Name: {team.get('name')}")
            ctx.echo(f"  • Domain: {team.get('domain')}.slack.com")

        def list_channels(ctx: ProviderContext) -> None:
            http = _http(ctx)
            response = http.get(
                "https://slack.com/api/conversations.list",
                headers=_auth_headers(ctx.access_token),
                params={"limit": 5},
                timeout=10,
            )
            data = response.json() if response.status_code == 200 else {"ok": False}
            if not data.get("ok"):
                ctx.echo(
                    "⚠️ Unable to list channels. Ensure 'conversations:read' or 'channels:read' scope is granted."
                )
                return
            channels = data.get("channels", [])
            if not channels:
                ctx.echo("ℹ️ No channels returned.")
                return
            ctx.echo("\n#️⃣ Sample channels:")
            for channel in channels:
                ctx.echo(f"  • #{channel.get('name')} (id={channel.get('id')})")

        def post_message_stub(ctx: ProviderContext) -> None:
            ctx.echo(
                "✉️ Use chat.postMessage with 'chat:write' scope to send messages."
                " Provide a channel ID when running tests outside the wizard."
            )

        return [
            ProviderAction(
                key="slack_workspace_info",
                label="Slack: show workspace info",
                handler=show_workspace,
                requires_any_scopes=["team:read"],
                missing_scope_message="⚠️ Slack workspace scope missing. Add 'team:read'.",
            ),
            ProviderAction(
                key="slack_list_channels",
                label="Slack: list channels",
                handler=list_channels,
                requires_any_scopes=["conversations:read", "channels:read"],
                missing_scope_message="⚠️ Grant 'conversations:read' or 'channels:read' to list channels.",
            ),
            ProviderAction(
                key="slack_post_message",
                label="Slack: how to post a message",
                handler=post_message_stub,
                requires_any_scopes=["chat:write"],
                missing_scope_message="⚠️ Add 'chat:write' to send messages via the API.",
            ),
        ]

    def welcome_text(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            """
            👋 Welcome to the Slack OAuth wizard!
            We'll help you reuse an existing Slack app or walk you through creating a new one.
            """
        ).strip()

    def manual_entry_instructions(self) -> str:
        return textwrap.dedent(
            """
            ✍️ Paste your Slack App's Client ID and Client Secret below.
            Manage your apps at https://api.slack.com/apps.
            """
        ).strip()

    def app_creation_instructions(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            f"""
            🛠️ Create a Slack app at https://api.slack.com/apps.
            1. Choose "Create New App" → "From scratch".
            2. Add OAuth scopes under "OAuth & Permissions" (start with users:read, team:read).
            3. Add the Redirect URL: {redirect_uri}
            Save changes then copy the Client ID and Secret from "Basic Information".
            """
        ).strip()

    def load_credentials_from_file(self, path: str) -> tuple[str, str]:
        with open(path) as fh:
            data = json.load(fh)
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")
        if not client_id or not client_secret:
            raise ValueError("Slack JSON must contain 'client_id' and 'client_secret'.")
        return client_id, client_secret

    def validate_client_id(self, client_id: str) -> bool:
        return bool(re.fullmatch(r"\d+\.\d+", client_id))

    def validate_client_secret(self, client_secret: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9]{20,}", client_secret))


provider = SlackProvider()
