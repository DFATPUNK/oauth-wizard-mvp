from __future__ import annotations

import base64
import json
import re
import textwrap
from typing import Dict, Iterable, List, Optional

import requests

from providers.base import EndpointInfo, ProviderAction, ProviderContext


NOTION_VERSION = "2022-06-28"


def _notion_headers(token: str, *, content_type: Optional[str] = None) -> Dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Notion-Version": NOTION_VERSION,
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


class NotionProvider:
    id = "notion"
    name = "Notion"
    authorize_endpoint = "https://api.notion.com/v1/oauth/authorize"
    token_endpoint = "https://api.notion.com/v1/oauth/token"
    userinfo_endpoint = "https://api.notion.com/v1/users/me"
    tokeninfo_endpoint: Optional[str] = None
    token_request_headers: Dict[str, str] = {}

    def __init__(self) -> None:
        self.base_scopes = ["read:content"]
        self.scope_groups: Dict[str, Dict[str, List[str]]] = {
            "Content": {
                "read": ["read:content", "databases:read"],
                "write": ["update:content", "insert:content", "delete:content"],
            },
            "Users": {"read": ["read:user"], "write": ["write:user"]},
            "Comments": {"read": ["read:comment"], "write": ["write:comment"]},
        }
        self.discovery_metadata = {
            "Content": {
                "type": "notion_catalog",
                "base_url": "https://api.notion.com/v1",
                "method_map": [
                    {
                        "path": "/search",
                        "httpMethod": "POST",
                        "description": "Search pages and databases accessible to the integration.",
                        "scopes": ["read:content"],
                    },
                    {
                        "path": "/databases",
                        "httpMethod": "GET",
                        "description": "List databases shared with the integration.",
                        "scopes": ["databases:read"],
                    },
                    {
                        "path": "/pages",
                        "httpMethod": "POST",
                        "description": "Create a new page.",
                        "scopes": ["insert:content"],
                    },
                ],
                "docs_url": "https://developers.notion.com/reference/intro",
            },
            "Users": {
                "type": "notion_catalog",
                "base_url": "https://api.notion.com/v1",
                "method_map": [
                    {
                        "path": "/users",
                        "httpMethod": "GET",
                        "description": "List users in the workspace.",
                        "scopes": ["read:user"],
                    },
                    {
                        "path": "/users/{user_id}",
                        "httpMethod": "GET",
                        "description": "Retrieve a user's details.",
                        "scopes": ["read:user"],
                    },
                ],
                "docs_url": "https://developers.notion.com/reference/get-users",
            },
            "Comments": {
                "type": "notion_catalog",
                "base_url": "https://api.notion.com/v1",
                "method_map": [
                    {
                        "path": "/comments",
                        "httpMethod": "POST",
                        "description": "Create a comment on a page or block.",
                        "scopes": ["write:comment"],
                    },
                    {
                        "path": "/comments",
                        "httpMethod": "GET",
                        "description": "List comments for a block.",
                        "scopes": ["read:comment"],
                    },
                ],
                "docs_url": "https://developers.notion.com/reference/post-comment",
            },
        }

    # Protocol implementation -------------------------------------------------
    def build_authorization_url(
        self, client_id: str, redirect_uri: str, scopes: Iterable[str]
    ) -> str:
        scope_str = "%20".join(sorted(scopes))
        return (
            f"{self.authorize_endpoint}?client_id={client_id}"
            f"&redirect_uri={redirect_uri}&response_type=code&owner=user&scope={scope_str}"
        )

    def refresh_access_token(
        self, client_id: str, client_secret: str, refresh_token: str
    ) -> Optional[Dict]:
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(
                self.token_endpoint,
                headers=headers,
                json={"grant_type": "refresh_token", "refresh_token": refresh_token},
                timeout=15,
            )
        except Exception:
            return None
        if response.status_code == 200:
            return response.json()
        return None

    def fetch_token_scopes(self, access_token: str) -> List[str]:
        # Notion does not expose an introspection endpoint; rely on granted scopes.
        return []

    def fetch_user_email(self, access_token: str) -> Optional[str]:
        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers=_notion_headers(access_token),
                timeout=10,
            )
        except Exception:
            return None
        if response.status_code != 200:
            return None
        data = response.json()
        person = (data.get("person") or {}) if isinstance(data, dict) else {}
        return person.get("email")

    def userinfo_endpoints(self) -> List[EndpointInfo]:
        return [
            EndpointInfo(
                service="Notion API",
                method="GET",
                url="https://api.notion.com/v1/users/me",
                requires=["read:user"],
                example=(
                    "curl -H 'Authorization: Bearer $ACCESS_TOKEN' "
                    "-H 'Notion-Version: 2022-06-28' https://api.notion.com/v1/users/me"
                ),
            )
        ]

    def sign_in_snippet(
        self, client_id: str, redirect_uri: str, scopes: Iterable[str]
    ) -> str:
        scope_str = "%20".join(sorted(scopes))
        href = (
            f"{self.authorize_endpoint}?client_id={client_id}&redirect_uri={redirect_uri}"
            f"&response_type=code&owner=user&scope={scope_str}"
        )
        return textwrap.dedent(
            """
            <a href="{href}">
              <button style="padding:10px 16px;background:#1f1f1f;color:#fff;border:none;border-radius:4px;">
                Sign in with Notion
              </button>
            </a>
            """
        ).strip().format(href=href)

    def menu_actions(self) -> List[ProviderAction]:
        def _http(ctx: ProviderContext):
            return ctx.http_client or requests

        def search_workspace(ctx: ProviderContext) -> None:
            http = _http(ctx)
            response = http.post(
                "https://api.notion.com/v1/search",
                headers=_notion_headers(ctx.access_token, content_type="application/json"),
                json={"page_size": 5},
                timeout=10,
            )
            if response.status_code != 200:
                ctx.echo("⚠️ Unable to search workspace. Ensure 'read:content' is granted.")
                return
            results = response.json().get("results", [])
            if not results:
                ctx.echo("ℹ️ No results returned. Share a page or database with the integration first.")
                return
            ctx.echo("\n📚 Search results:")
            for item in results:
                item_type = item.get("object")
                title = "Unnamed"
                if item_type == "page":
                    properties = item.get("properties", {})
                    for prop in properties.values():
                        title = next(
                            (
                                rich_text.get("plain_text")
                                for rich_text in prop.get("title", [])
                                if rich_text.get("plain_text")
                            ),
                            title,
                        )
                        if title != "Unnamed":
                            break
                ctx.echo(f"  • {item_type}: {title}")

        def list_users(ctx: ProviderContext) -> None:
            http = _http(ctx)
            response = http.get(
                "https://api.notion.com/v1/users",
                headers=_notion_headers(ctx.access_token),
                params={"page_size": 5},
                timeout=10,
            )
            if response.status_code != 200:
                ctx.echo("⚠️ Unable to list users. Add the 'read:user' scope and re-authenticate.")
                return
            data = response.json()
            for user in data.get("results", [])[:5]:
                ctx.echo(f"  • {user.get('name')} ({user.get('type')})")

        def create_page_stub(ctx: ProviderContext) -> None:
            ctx.echo(
                "🧱 Use POST /v1/pages with 'insert:content' and a parent database or page to create content."
            )

        return [
            ProviderAction(
                key="notion_search",
                label="Notion: search workspace",
                handler=search_workspace,
                requires_any_scopes=["read:content"],
                missing_scope_message="⚠️ Add 'read:content' to search pages and databases.",
            ),
            ProviderAction(
                key="notion_list_users",
                label="Notion: list users",
                handler=list_users,
                requires_any_scopes=["read:user"],
                missing_scope_message="⚠️ Grant the 'read:user' scope to browse workspace members.",
            ),
            ProviderAction(
                key="notion_create_page_stub",
                label="Notion: page creation tips",
                handler=create_page_stub,
                requires_any_scopes=["insert:content"],
                missing_scope_message="⚠️ Add 'insert:content' to create new Notion pages via API.",
            ),
        ]

    def welcome_text(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            """
            👋 Welcome to the Notion OAuth wizard!
            Bring an existing internal integration or let us show you how to create one.
            """
        ).strip()

    def manual_entry_instructions(self) -> str:
        return textwrap.dedent(
            """
            ✍️ Paste the Client ID and Client Secret from your Notion integration settings.
            Manage integrations at https://www.notion.so/my-integrations.
            """
        ).strip()

    def app_creation_instructions(self, redirect_uri: str) -> str:
        return textwrap.dedent(
            f"""
            🛠️ Create an internal integration at https://www.notion.so/my-integrations.
            1. Click "+ New integration" and give it a name.
            2. Add the redirect URI {redirect_uri} under OAuth 2.0 settings.
            3. Choose scopes such as read:content, insert:content, and read:user as needed.
            Save and copy the Client ID and Secret to continue.
            """
        ).strip()

    def load_credentials_from_file(self, path: str) -> tuple[str, str]:
        with open(path) as fh:
            data = json.load(fh)
        client_id = data.get("client_id") or data.get("notion_client_id")
        client_secret = data.get("client_secret") or data.get("notion_client_secret")
        if not client_id or not client_secret:
            raise ValueError(
                "Notion credential JSON must include 'client_id' and 'client_secret'."
            )
        return client_id, client_secret

    def validate_client_id(self, client_id: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", client_id))

    def validate_client_secret(self, client_secret: str) -> bool:
        return bool(client_secret) and len(client_secret) >= 32


provider = NotionProvider()
