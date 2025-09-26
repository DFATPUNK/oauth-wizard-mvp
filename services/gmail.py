"""Gmail service helpers that operate on HTTP clients."""
from __future__ import annotations

import base64
import json
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional


API_BASE = "https://gmail.googleapis.com/gmail/v1"
MESSAGES_ENDPOINT = f"{API_BASE}/users/me/messages"
SEND_ENDPOINT = f"{MESSAGES_ENDPOINT}/send"


class GmailServiceError(RuntimeError):
    """Base exception for Gmail service interactions."""

    def __init__(self, message: str, response: Any | None = None) -> None:
        super().__init__(message)
        self.response = response


class GmailServiceDisabledError(GmailServiceError):
    """Raised when the Gmail API reports the service is disabled for a project."""

    def __init__(self, api_name: str, client_id: str, response: Any | None = None) -> None:
        project = _parse_project_number(client_id) or ""
        enable_url = build_enable_api_url(api_name, project)
        super().__init__(
            "The Gmail API appears to be disabled for this Google Cloud project.",
            response=response,
        )
        self.enable_url = enable_url
        self.project = project


def _parse_project_number(client_id: str) -> Optional[str]:
    if "-" in client_id:
        prefix = client_id.split("-", 1)[0]
        if prefix.isdigit():
            return prefix
    return None


def build_enable_api_url(api_name: str, project: str) -> str:
    return f"https://console.developers.google.com/apis/api/{api_name}/overview?project={project}"


def _is_service_disabled(resp_text: str) -> bool:
    try:
        data = json.loads(resp_text)
        err = data.get("error", {})
        details = err.get("details", [])
        status = err.get("status")
        if status != "PERMISSION_DENIED":
            return False
        for detail in details:
            if detail.get("@type", "").endswith("ErrorInfo") and detail.get("reason") == "SERVICE_DISABLED":
                return True
    except Exception:
        return False
    return False


def list_messages(
    http_client,
    access_token: str,
    client_id: str,
    max_results: int = 5,
    query: str | None = None,
) -> List[Dict[str, str]]:
    params: Dict[str, str] = {"maxResults": str(max_results)}
    if query:
        params["q"] = query
    response = http_client.get(
        MESSAGES_ENDPOINT,
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        timeout=20,
    )
    if response.status_code != 200:
        if response.status_code == 403 and _is_service_disabled(response.text):
            raise GmailServiceDisabledError("gmail.googleapis.com", client_id, response=response)
        raise GmailServiceError(
            f"Gmail list error: {response.status_code} {response.text}",
            response=response,
        )

    message_ids = [m.get("id") for m in response.json().get("messages", []) if m.get("id")]
    results: List[Dict[str, str]] = []
    for message_id in message_ids:
        detail = http_client.get(
            f"{MESSAGES_ENDPOINT}/{message_id}",
            headers={"Authorization": f"Bearer {access_token}"},
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
        elif detail.status_code == 403 and _is_service_disabled(detail.text):
            raise GmailServiceDisabledError("gmail.googleapis.com", client_id, response=detail)
        else:
            raise GmailServiceError(
                f"Gmail message fetch error: {detail.status_code} {detail.text}",
                response=detail,
            )
    return results


def get_message(http_client, access_token: str, client_id: str, message_id: str) -> Dict[str, Any]:
    response = http_client.get(
        f"{MESSAGES_ENDPOINT}/{message_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"format": "full"},
        timeout=20,
    )
    if response.status_code == 200:
        return response.json()
    if response.status_code == 403 and _is_service_disabled(response.text):
        raise GmailServiceDisabledError("gmail.googleapis.com", client_id, response=response)
    raise GmailServiceError(
        f"Gmail get error: {response.status_code} {response.text}",
        response=response,
    )


def send_email(
    http_client,
    access_token: str,
    client_id: str,
    to_addr: str,
    subject: str,
    body: str,
) -> Dict[str, Any]:
    mime = MIMEText(body)
    mime["to"] = to_addr
    mime["subject"] = subject
    raw = base64.urlsafe_b64encode(mime.as_bytes()).decode("utf-8")
    payload = {"raw": raw}
    response = http_client.post(
        SEND_ENDPOINT,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )
    if response.status_code in (200, 202):
        return response.json()
    if response.status_code == 403 and _is_service_disabled(response.text):
        raise GmailServiceDisabledError("gmail.googleapis.com", client_id, response=response)
    raise GmailServiceError(
        f"Gmail send error: {response.status_code} {response.text}",
        response=response,
    )
