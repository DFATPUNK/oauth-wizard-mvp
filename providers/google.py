from __future__ import annotations

import base64
import json
import re
import webbrowser
from email.mime.text import MIMEText
from typing import Dict, Iterable, List, Optional

import requests

from .base import EndpointInfo, ProviderAction, ProviderContext


def _parse_project_number(client_id: str) -> Optional[str]:
    if "-" in client_id:
        prefix = client_id.split("-", 1)[0]
        if prefix.isdigit():
            return prefix
    return None


def _open_enable_api_link(api_name: str, client_id: str):
    project = _parse_project_number(client_id) or ""
    url = f"https://console.developers.google.com/apis/api/{api_name}/overview?project={project}"
    print(f"\n⚙️  This API is disabled for project {project}.")
    print(f"👉 Enable it here:\n   {url}\n")
    input("Press Enter to open the enable page…")
    webbrowser.open(url)
    print("⏳ Wait ~1 minute after enabling, then retry the action.")


def _maybe_handle_service_disabled(resp_text: str, client_id: str, api_name: str) -> bool:
    try:
        data = json.loads(resp_text)
        err = data.get("error", {})
        status = err.get("status")
        details = err.get("details", [])
        if status == "PERMISSION_DENIED":
            for detail in details:
                if detail.get("@type", "").endswith("ErrorInfo") and detail.get("reason") == "SERVICE_DISABLED":
                    _open_enable_api_link(api_name, client_id)
                    return True
    except Exception:
        pass
    return False


def _gmail_list_messages(context: ProviderContext, max_results: int = 5, query: str | None = None):
    params: Dict[str, str] = {"maxResults": str(max_results)}
    if query:
        params["q"] = query
    response = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers={"Authorization": f"Bearer {context.access_token}"},
        params=params,
        timeout=20,
    )
    if response.status_code != 200:
        if response.status_code == 403 and _maybe_handle_service_disabled(response.text, context.client_id, "gmail.googleapis.com"):
            return None
        print(f"❌ Gmail list error: {response.status_code} {response.text}")
        return []

    message_ids = [m.get("id") for m in response.json().get("messages", []) if m.get("id")]
    results = []
    for message_id in message_ids:
        detail = requests.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
            headers={"Authorization": f"Bearer {context.access_token}"},
            params={
                "format": "metadata",
                "metadataHeaders": ["From", "Subject", "Date"],
            },
            timeout=20,
        )
        if detail.status_code == 200:
            meta = detail.json()
            headers = {h.get("name"): h.get("value") for h in meta.get("payload", {}).get("headers", [])}
            results.append(
                {
                    "id": message_id,
                    "from": headers.get("From", ""),
                    "subject": headers.get("Subject", ""),
                    "date": headers.get("Date", ""),
                    "snippet": meta.get("snippet", ""),
                }
            )
        elif detail.status_code == 403 and _maybe_handle_service_disabled(detail.text, context.client_id, "gmail.googleapis.com"):
            return None
    return results


def _gmail_get_message(context: ProviderContext, message_id: str):
    response = requests.get(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
        headers={"Authorization": f"Bearer {context.access_token}"},
        params={"format": "full"},
        timeout=20,
    )
    if response.status_code == 200:
        return response.json()
    if response.status_code == 403 and _maybe_handle_service_disabled(response.text, context.client_id, "gmail.googleapis.com"):
        return None
    print(f"❌ Gmail get error: {response.status_code} {response.text}")
    return None


def _gmail_send_email(context: ProviderContext, to_addr: str, subject: str, body: str):
    mime = MIMEText(body)
    mime["to"] = to_addr
    mime["subject"] = subject
    raw = base64.urlsafe_b64encode(mime.as_bytes()).decode("utf-8")
    payload = {"raw": raw}
    response = requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers={
            "Authorization": f"Bearer {context.access_token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )
    if response.status_code in (200, 202):
        data = response.json()
        print(f"✅ Email sent. Gmail message id: {data.get('id')}")
        return data
    if response.status_code == 403 and _maybe_handle_service_disabled(response.text, context.client_id, "gmail.googleapis.com"):
        return None
    print(f"❌ Gmail send error: {response.status_code} {response.text}")
    return None


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
            "Gmail": {"type": "google_discovery", "api": "gmail", "version": "v1"},
            "Calendar": {"type": "google_discovery", "api": "calendar", "version": "v3"},
            "Drive": {"type": "google_discovery", "api": "drive", "version": "v3"},
            "Sheets": {"type": "google_discovery", "api": "sheets", "version": "v4"},
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
            items = _gmail_list_messages(ctx, max_results=5)
            if items is None:
                input("After enabling Gmail API, press Enter to retry listing…")
                items = _gmail_list_messages(ctx, max_results=5)
            if not items:
                print("No messages found.")
                return
            print("\n📬 Last messages:")
            for item in items:
                print(
                    f"- id={item['id']}\n  From: {item['from']}\n  Subject: {item['subject']}\n  "
                    f"Date: {item['date']}\n  Snippet: {item['snippet']}\n"
                )

        def read_message(ctx: ProviderContext) -> None:
            message_id = input("Enter Gmail message id to fetch ➔ ").strip()
            if not message_id:
                print("⚠️ Missing id.")
                return
            message = _gmail_get_message(ctx, message_id)
            if message is None:
                input("After enabling Gmail API (if needed), press Enter to retry…")
                message = _gmail_get_message(ctx, message_id)
            if message:
                print(json.dumps(message, indent=2))

        def send_email(ctx: ProviderContext) -> None:
            to_addr = input("To ➔ ").strip()
            subject = input("Subject ➔ ").strip()
            body = input("Body ➔ ").strip()
            response = _gmail_send_email(ctx, to_addr, subject, body)
            if response is None:
                input("After enabling Gmail API (if needed), press Enter to retry send…")
                _gmail_send_email(ctx, to_addr, subject, body)

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
