from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional

import requests

from providers.base import EndpointInfo, ProviderAction, ProviderContext
from services.gmail import (
    GmailServiceDisabledError,
    GmailServiceError,
    get_message as gmail_get_message,
    list_messages as gmail_list_messages,
    send_email as gmail_send_email,
)


def _handle_service_disabled(ctx: ProviderContext, exc: GmailServiceDisabledError) -> None:
    project = exc.project or "this project"
    ctx.echo(f"\n⚙️  The Gmail API is disabled for {project}.")
    ctx.echo(f"👉 Enable it here:\n   {exc.enable_url}\n")
    if ctx.confirm("Open the enable page in your browser now?"):
        ctx.open_browser(exc.enable_url)
        ctx.echo("⏳ Wait ~1 minute after enabling, then retry the action.")


def _require_http_client(ctx: ProviderContext):
    if ctx.http_client is None:
        raise RuntimeError("ProviderContext.http_client is required for Gmail actions.")
    return ctx.http_client


class GoogleProvider:
    id = "google"
    name = "Google"
    authorize_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"
    userinfo_endpoint = "https://www.googleapis.com/oauth2/v2/userinfo"
    tokeninfo_endpoint = "https://www.googleapis.com/oauth2/v3/tokeninfo"

    def __init__(self) -> None:
        self.base_scopes = ["openid", "email", "profile"]
        self.scope_groups: Dict[str, Dict[str, List[str]]] = {
            "Gmail": {
                "read": ["https://www.googleapis.com/auth/gmail.readonly"],
                "write": ["https://www.googleapis.com/auth/gmail.send"],
            },
            "Calendar": {
                "read": ["https://www.googleapis.com/auth/calendar.events.readonly"],
                "write": ["https://www.googleapis.com/auth/calendar.events"],
            },
            "Drive": {
                "read": ["https://www.googleapis.com/auth/drive.readonly"],
                "write": ["https://www.googleapis.com/auth/drive.file"],
            },
            "Sheets": {
                "read": ["https://www.googleapis.com/auth/spreadsheets.readonly"],
                "write": ["https://www.googleapis.com/auth/spreadsheets"],
            },
        }
        self.discovery_metadata = {
            "Gmail": {
                "type": "google_discovery",
                "api": "gmail",
                "version": "v1",
                "docs_url": "https://developers.google.com/gmail/api/reference/rest",
            },
            "Calendar": {
                "type": "google_discovery",
                "api": "calendar",
                "version": "v3",
                "docs_url": "https://developers.google.com/calendar/api/v3/reference",
            },
            "Drive": {
                "type": "google_discovery",
                "api": "drive",
                "version": "v3",
                "docs_url": "https://developers.google.com/drive/api/v3/reference",
            },
            "Sheets": {
                "type": "google_discovery",
                "api": "sheets",
                "version": "v4",
                "docs_url": "https://developers.google.com/sheets/api/reference/rest",
            },
        }

    # Protocol implementation -------------------------------------------------
    def build_authorization_url(self, client_id: str, redirect_uri: str, scopes: Iterable[str]) -> str:
        scope_str = " ".join(sorted(scopes))
        return (
            f"{self.authorize_endpoint}"
            f"?client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&response_type=code"
            f"&scope={scope_str}"
            f"&access_type=offline"
            f"&prompt=consent"
            f"&include_granted_scopes=true"
        )

    def refresh_access_token(self, client_id: str, client_secret: str, refresh_token: str) -> Optional[Dict]:
        try:
            response = requests.post(
                self.token_endpoint,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
                timeout=15,
            )
        except Exception:
            return None
        if response.status_code == 200:
            return response.json()
        return None

    def fetch_token_scopes(self, access_token: str) -> List[str]:
        if not self.tokeninfo_endpoint:
            return []
        try:
            response = requests.get(
                self.tokeninfo_endpoint,
                params={"access_token": access_token},
                timeout=10,
            )
        except Exception:
            return []
        if response.status_code == 200:
            scope_str = response.json().get("scope", "")
            return sorted([s for s in scope_str.split() if s])
        return []

    def fetch_user_email(self, access_token: str) -> Optional[str]:
        if not self.userinfo_endpoint:
            return None
        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
        except Exception:
            return None
        if response.status_code == 200:
            return response.json().get("email")
        return None

    def userinfo_endpoints(self) -> List[EndpointInfo]:
        return [
            EndpointInfo(
                service="Google OAuth2",
                method="GET",
                url="https://www.googleapis.com/oauth2/v2/userinfo",
                requires=[
                    "https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email",
                ],
                example="curl -H 'Authorization: Bearer $ACCESS_TOKEN' https://www.googleapis.com/oauth2/v2/userinfo",
            ),
            EndpointInfo(
                service="Google OAuth2",
                method="GET",
                url="https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=$ACCESS_TOKEN",
                requires=[],
                example="curl 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=$ACCESS_TOKEN'",
            ),
        ]

    def sign_in_snippet(self, client_id: str, redirect_uri: str, scopes: Iterable[str]) -> str:
        scope_str = " ".join(sorted(scopes))
        return (
            "<a "
            f"href=\"{self.authorize_endpoint}?client_id={client_id}&redirect_uri={redirect_uri}"
            "&response_type=code&scope="
            f"{scope_str}&access_type=offline&prompt=consent&include_granted_scopes=true\">\n"
            "  <img src=\"https://developers.google.com/identity/images/btn_google_signin_dark_normal_web.png\" "
            "alt=\"Sign in with Google\" style=\"height:40px;\">\n"
            "</a>"
        )

    def menu_actions(self) -> List[ProviderAction]:
        gmail_read_scopes = self.scope_groups["Gmail"]["read"]
        gmail_send_scopes = self.scope_groups["Gmail"]["write"]

        def list_messages(ctx: ProviderContext) -> None:
            http_client = _require_http_client(ctx)
            try:
                items = gmail_list_messages(http_client, ctx.access_token, ctx.client_id, max_results=5)
            except GmailServiceDisabledError as exc:
                _handle_service_disabled(ctx, exc)
                return
            except GmailServiceError as exc:
                ctx.echo(str(exc))
                return
            if not items:
                ctx.echo("No messages found.")
                return
            ctx.echo("\n📬 Last messages:")
            for item in items:
                ctx.echo(
                    "- id={id}\n  From: {from}\n  Subject: {subject}\n  Date: {date}\n  Snippet: {snippet}\n".format(**item)
                )

        def read_message(ctx: ProviderContext) -> None:
            message_id = ctx.prompt("Enter Gmail message id to fetch")
            if not message_id:
                ctx.echo("⚠️ Missing id.")
                return
            http_client = _require_http_client(ctx)
            try:
                message = gmail_get_message(http_client, ctx.access_token, ctx.client_id, message_id)
            except GmailServiceDisabledError as exc:
                _handle_service_disabled(ctx, exc)
                return
            except GmailServiceError as exc:
                ctx.echo(str(exc))
                return
            ctx.echo(json.dumps(message, indent=2))

        def send_email(ctx: ProviderContext) -> None:
            to_addr = ctx.prompt("To")
            subject = ctx.prompt("Subject")
            body = ctx.prompt("Body")
            if not to_addr:
                ctx.echo("⚠️ Missing recipient email address.")
                return
            http_client = _require_http_client(ctx)
            try:
                response = gmail_send_email(
                    http_client,
                    ctx.access_token,
                    ctx.client_id,
                    to_addr,
                    subject,
                    body,
                )
            except GmailServiceDisabledError as exc:
                _handle_service_disabled(ctx, exc)
                return
            except GmailServiceError as exc:
                ctx.echo(str(exc))
                return
            message_id = response.get("id")
            if message_id:
                ctx.echo(f"✅ Email sent. Gmail message id: {message_id}")
            else:
                ctx.echo("✅ Email sent.")

        return [
            ProviderAction(
                key="gmail_list",
                label="Gmail: list last 5 messages",
                handler=list_messages,
                requires_any_scopes=gmail_read_scopes,
                missing_scope_message="⚠️ Gmail READ scope missing. Use an 'Add READ' option above to re-auth.",
            ),
            ProviderAction(
                key="gmail_read",
                label="Gmail: read a message by ID",
                handler=read_message,
                requires_any_scopes=gmail_read_scopes,
                missing_scope_message="⚠️ Gmail READ scope missing. Use an 'Add READ' option above to re-auth.",
            ),
            ProviderAction(
                key="gmail_send",
                label="Gmail: send a test email",
                handler=send_email,
                requires_any_scopes=gmail_send_scopes,
                missing_scope_message="⚠️ Gmail SEND scope missing. Use an 'Add WRITE' option above to re-auth.",
            ),
        ]

    def welcome_text(self, redirect_uri: str) -> str:
        return (
            "\n🚀 Welcome to OAuth Wizard MVP for Google\n\n"
            "⭐ RECOMMENDED WAY ⭐\n"
            "Upload your 'client_secrets.json' file from Google.\n"
            "It's the easiest and most error-proof way.\n\n"
            "⚠️ IMPORTANT: Before closing the Google pop-up that shows your Client ID and Secret, click 'Download JSON'!\n"
            "This will save a file like 'OAuth Client ID ... .json' on your computer.\n\n"
            "If you already closed it, no worries:\n"
            "👉 Go back to Google Console ➔ 'APIs & Services' ➔ 'Credentials'\n"
            "   and click the ✏️ pencil icon next to your OAuth app,\n"
            "   then click 'Download JSON' at the top.\n\n"
            "🎯 Google Console: https://console.cloud.google.com/apis/credentials\n"
        )

    def manual_entry_instructions(self) -> str:
        return (
            "\n🔎 Enter your credentials manually below.\n"
            "If you need to go to your Google Console, here's the link just in case:\n"
            "   https://console.cloud.google.com/apis/credentials\n"
        )

    def app_creation_instructions(self, redirect_uri: str) -> str:
        return (
            "\n👉 Go directly to create your OAuth App here:\n"
            "   https://console.cloud.google.com/auth/clients/create\n"
            f"\nFill out:\n• Application type: Web application\n• Name: MyApp-OAuth (or any name)\n• Authorized redirect URIs:\n   - Click 'Add URI' and enter: {redirect_uri}\n"
            "\n✅ Then click 'Create' and download the JSON immediately.\n\n"
            "⭐ IMPORTANT:\nYou will only see your client secret ONCE — when you first create your OAuth client.\n"
            "Make sure you download the JSON or copy your secret right away.\n\n"
            "If you lost it or closed the pop-up:\n"
            "👉 Go to your OAuth app in Google Console and click '+ Add Secret' to generate a new one.\n\n"
            "⭐ Tip: after you have your JSON, you can drag & drop it right here or choose option (1) to upload it, or (2) to paste manually.\n"
        )

    def load_credentials_from_file(self, path: str) -> tuple[str, str]:
        with open(path) as f:
            data = json.load(f)
        client_id = data["web"]["client_id"]
        client_secret = data["web"]["client_secret"]
        return client_id, client_secret

    def validate_client_id(self, client_id: str) -> bool:
        return bool(re.match(r"^\d{12,}-[a-z0-9\-]+\.apps\.googleusercontent\.com$", client_id))

    def validate_client_secret(self, client_secret: str) -> bool:
        return len(client_secret) > 10


provider = GoogleProvider()
