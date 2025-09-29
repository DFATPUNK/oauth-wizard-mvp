from __future__ import annotations

import json
import re
import textwrap
from typing import Dict, Iterable, List, Optional

import requests

from providers.base import EndpointInfo, ProviderAction, ProviderContext


def _trello_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


class TrelloProvider:
    id = "trello"
    name = "Trello"
    authorize_endpoint = "https://trello.com/1/authorize"
    token_endpoint = "https://api.trello.com/1/oauth2/token"
    userinfo_endpoint = "https://api.trello.com/1/members/me"
    tokeninfo_endpoint: Optional[str] = None
    token_request_headers: Dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    def __init__(self) -> None:
        self.base_scopes = ["read"]
        self.scope_groups: Dict[str, Dict[str, List[str]]] = {
            "Boards": {"read": ["read"], "write": ["write"]},
            "Cards": {"read": ["read"], "write": ["write"]},
            "Account": {"read": ["account"], "write": []},
        }
        self.discovery_metadata = {
            "Boards": {
                "type": "trello_catalog",
                "base_url": "https://api.trello.com/1",
                "method_map": [
                    {
                        "path": "/members/me/boards",
                        "httpMethod": "GET",
                        "description": "List boards accessible to the authorized user.",
                        "scopes": ["read"],
                    },
                    {
                        "path": "/boards/{board_id}/lists",
                        "httpMethod": "GET",
                        "description": "List lists on a board.",
                        "scopes": ["read"],
                    },
                    {
                        "path": "/boards",
                        "httpMethod": "POST",
                        "description": "Create a new board.",
                        "scopes": ["write"],
                    },
                ],
                "docs_url": "https://developer.atlassian.com/cloud/trello/rest/api-group-boards/",
            },
            "Cards": {
                "type": "trello_catalog",
                "base_url": "https://api.trello.com/1",
                "method_map": [
                    {
                        "path": "/cards",
                        "httpMethod": "POST",
                        "description": "Create a card on a list.",
                        "scopes": ["write"],
                    },
                    {
                        "path": "/cards/{card_id}",
                        "httpMethod": "GET",
                        "description": "Retrieve a card.",
                        "scopes": ["read"],
                    },
                ],
                "docs_url": "https://developer.atlassian.com/cloud/trello/rest/api-group-cards/",
            },
            "Account": {
                "type": "trello_catalog",
                "base_url": "https://api.trello.com/1",
                "method_map": [
                    {
                        "path": "/members/me",
                        "httpMethod": "GET",
                        "description": "Fetch account profile information.",
                        "scopes": ["read", "account"],
                    },
                ],
                "docs_url": "https://developer.atlassian.com/cloud/trello/rest/api-group-members/",
            },
        }

    # Protocol implementation -------------------------------------------------
    def build_authorization_url(
        self, client_id: str, redirect_uri: str, scopes: Iterable[str]
    ) -> str:
        scope_str = ",".join(sorted(scopes))
        return (
            f"{self.authorize_endpoint}?response_type=code"
            f"&client_id={client_id}"
            f"&scope={scope_str}"
            f"&redirect_uri={redirect_uri}"
            f"&expiration=30days"
            f"&name=OAuth%20Wizard"
        )

    def refresh_access_token(
        self, client_id: str, client_secret: str, refresh_token: str
    ) -> Optional[Dict]:
        try:
            response = requests.post(
                self.token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "client_secret": client_secret,
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
                "https://api.trello.com/1/members/me",
                headers=_trello_headers(access_token),
                params={"fields": "id,username,fullName"},
                timeout=10,
            )
        except Exception:
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        scopes = data.get("grantedScopes") or []
        if isinstance(scopes, list):
            return sorted(set(scopes))
        if isinstance(scopes, str):
            return sorted({scope.strip() for scope in scopes.split(" ") if scope.strip()})
        return []

    def fetch_user_email(self, access_token: str) -> Optional[str]:
        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers=_trello_headers(access_token),
                params={"fields": "username,fullName,email"},
                timeout=10,
            )
        except Exception:
            return None
        if response.status_code != 200:
            return None
        data = response.json()
        return data.get("email")

    def userinfo_endpoints(self) -> List[EndpointInfo]:
        return [
            EndpointInfo(
                service="Trello API",
                method="GET",
                url="https://api.trello.com/1/members/me",
                requires=["read"],
                example="curl -H 'Authorization: Bearer $ACCESS_TOKEN' https://api.trello.com/1/members/me",
            )
        ]

    def sign_in_snippet(
        self, client_id: str, redirect_uri: str, scopes: Iterable[str]
    ) -> str:
        scope_str = ",".join(sorted(scopes))
        href = (
            f"{self.authorize_endpoint}?response_type=code&client_id={client_id}"
            f"&scope={scope_str}&redirect_uri={redirect_uri}&expiration=30days&name=OAuth%20Wizard"
        )
        return textwrap.dedent(
            """
            <a href="{href}">
              <button style="padding:10px 16px;background:#026aa7;color:#fff;border:none;border-radius:4px;">
                Sign in with Trello
              </button>
            </a>
            """
        ).strip().format(href=href)

    def menu_actions(self) -> List[ProviderAction]:
        def _http(ctx: ProviderContext):
            return ctx.http_client or requests

        def list_boards(ctx: ProviderContext) -> None:
            http = _http(ctx)
            response = http.get(
                "https://api.trello.com/1/members/me/boards",
                headers=_trello_headers(ctx.access_token),
                params={"limit": 5, "fields": "name,url"},
                timeout=10,
            )
            if response.status_code != 200:
                ctx.echo("⚠️ Unable to list boards. Ensure the 'read' scope is granted.")
                return
            boards = response.json()
            if not boards:
                ctx.echo("ℹ️ No boards returned for this account.")
                return
            ctx.echo("\n📋 Boards:")
            for board in boards:
                ctx.echo(f"  • {board.get('name')} → {board.get('url')}")

        def show_profile(ctx: ProviderContext) -> None:
            http = _http(ctx)
            response = http.get(
                self.userinfo_endpoint,
                headers=_trello_headers(ctx.access_token),
                params={"fields": "username,fullName,email"},
                timeout=10,
            )
            if response.status_code != 200:
                ctx.echo("⚠️ Unable to fetch member profile. Add the 'account' scope for email access.")
                return
            ctx.echo(json.dumps(response.json(), indent=2))

        def card_creation_stub(ctx: ProviderContext) -> None:
            ctx.echo(
                "🗒️ Ready to create cards? Call POST /1/cards with 'write' scope and list id."
            )

        return [
            ProviderAction(
                key="trello_boards",
                label="Trello: list boards",
                handler=list_boards,
                requires_any_scopes=["read"],
                missing_scope_message="⚠️ Add the 'read' scope to access boards.",
            ),
            ProviderAction(
                key="trello_profile",
                label="Trello: show member profile JSON",
                handler=show_profile,
                requires_any_scopes=["account", "read"],
                missing_scope_message="⚠️ Add 'account' scope to fetch profile details including email.",
            ),
            ProviderAction(
                key="trello_cards_stub",
                label="Trello: card creation tips",
                handler=card_creation_stub,
                requires_any_scopes=["write"],
                missing_scope_message="⚠️ Grant the 'write' scope to create cards via the API.",
            ),
        ]

    def welcome_text(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            """
            👋 Welcome to the Trello OAuth wizard!
            We'll reuse an existing Trello OAuth 2.0 client or help you grab the keys you need.
            """
        ).strip()

    def manual_entry_instructions(self) -> str:
        return textwrap.dedent(
            """
            ✍️ Paste your Trello OAuth client ID (API key) and client secret below.
            Manage credentials at https://trello.com/app-key.
            """
        ).strip()

    def app_creation_instructions(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            f"""
            🛠️ Visit https://trello.com/app-key and click "Token" to enable OAuth 2.0.
            Add the redirect URL {redirect_uri} under OAuth 2 redirect URLs.
            Request scopes like read, write, and account depending on your needs.
            Copy the API key (Client ID) and generate a new secret for the wizard.
            """
        ).strip()

    def load_credentials_from_file(self, path: str) -> tuple[str, str]:
        with open(path) as fh:
            data = json.load(fh)
        client_id = data.get("client_id") or data.get("api_key")
        client_secret = data.get("client_secret") or data.get("secret")
        if not client_id or not client_secret:
            raise ValueError(
                "Trello credential JSON must include 'client_id' and 'client_secret'."
            )
        return client_id, client_secret

    def validate_client_id(self, client_id: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-f]{32}", client_id))

    def validate_client_secret(self, client_secret: str) -> bool:
        return bool(client_secret) and len(client_secret) >= 32


provider = TrelloProvider()
