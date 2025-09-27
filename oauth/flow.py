"""Utilities for running the OAuth consent flow and inspecting tokens."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Callable, Iterable, Optional, Tuple

import webbrowser
from werkzeug.serving import make_server

from app import create_app

DEFAULT_REDIRECT_URI = "http://localhost:5000/callback"
RESULT_PATH = Path(".last_oauth.json")
ENV_PATH = Path(".env")


class OAuthFlowError(RuntimeError):
    """Base exception for OAuth flow failures."""


class OAuthResultNotFoundError(OAuthFlowError):
    """Raised when the local callback never produced a result file."""


class AccessTokenMissingError(OAuthFlowError):
    """Raised when the OAuth result payload does not contain an access token."""


class ServerThread(threading.Thread):
    """Background thread running the local Flask server."""

    def __init__(self, flask_app, host: str = "127.0.0.1", port: int = 5000) -> None:
        super().__init__(daemon=True)
        self.server = make_server(host, port, flask_app)
        self.ctx = flask_app.app_context()
        self.ctx.push()

    def run(self) -> None:  # pragma: no cover - simple thread wrapper
        self.server.serve_forever()

    def shutdown(self) -> None:
        self.server.shutdown()


def safe_mask(token: str) -> str:
    """Return a partially masked token suitable for logs."""
    if not token:
        return ""
    if len(token) <= 12:
        return token
    return token[:12] + "…" + token[-6:]


def perform_oauth_flow(
    provider,
    client_id: str,
    client_secret: str,
    requested_scopes: Iterable[str],
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    result_path: Path = RESULT_PATH,
    browser_opener: Callable[[str], None] = webbrowser.open,
    app_factory: Callable[..., object] = create_app,
    echo: Callable[[str], None] | None = None,
    wait_timeout: int = 300,
) -> Tuple[dict, str, str]:
    """Run the OAuth browser consent flow and return the resulting tokens.

    The function returns a tuple of ``(tokens, access_token, authorization_url)``.
    The ``echo`` callable can be overridden to capture status messages during tests.
    """

    auth_url = provider.build_authorization_url(client_id, redirect_uri, requested_scopes)
    if echo:
        echo(f"Generating {provider.name} OAuth consent URL…")
        echo(auth_url)
    browser_opener(auth_url)

    done = threading.Event()
    flask_app = app_factory(
        provider,
        client_id,
        client_secret,
        redirect_uri,
        done_event=done,
        result_path=str(result_path),
    )
    server = ServerThread(flask_app)
    server.start()
    done.wait(timeout=wait_timeout)
    server.shutdown()

    if not result_path.exists():
        raise OAuthResultNotFoundError("No OAuth result found. Try again.")

    with result_path.open() as fh:
        tokens = json.load(fh)

    access_token = tokens.get("access_token")
    if not access_token:
        raise AccessTokenMissingError("No access token in OAuth result.")

    try:
        os.chmod(result_path, 0o600)
    except OSError:
        # Best effort – ignore permission errors on platforms that don't support it.
        pass

    return tokens, access_token, auth_url


def _load_json_lines(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open() as fh:
            return json.load(fh)
    except Exception:
        return {}


def _load_env_tokens(env_path: Path) -> dict:
    if not env_path.exists():
        return {}
    tokens: dict[str, str] = {}
    try:
        with env_path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                value = value.strip().strip('"').strip("'")
                if key in {"ACCESS_TOKEN", "REFRESH_TOKEN", "ID_TOKEN"}:
                    tokens[key.lower()] = value
    except Exception:
        return {}
    return tokens


def refresh_session(
    provider,
    client_id: str,
    client_secret: str,
    result_path: Path = RESULT_PATH,
    env_path: Path = ENV_PATH,
) -> Optional[dict]:
    """Attempt to load and refresh a previously stored OAuth session."""

    stored_tokens = _load_json_lines(result_path)
    env_tokens = _load_env_tokens(env_path)
    tokens = {**env_tokens, **stored_tokens}

    refresh_token = tokens.get("refresh_token")
    access_token = tokens.get("access_token")

    if refresh_token:
        refreshed = provider.refresh_access_token(client_id, client_secret, refresh_token)
        if refreshed and refreshed.get("access_token"):
            tokens.update(refreshed)
            access_token = refreshed.get("access_token")
            with result_path.open("w") as fh:
                json.dump(tokens, fh)
            try:
                os.chmod(result_path, 0o600)
            except OSError:
                pass

    if access_token:
        scopes = provider.fetch_token_scopes(access_token) or []
        email = provider.fetch_user_email(access_token)
        return {
            "access_token": access_token,
            "refresh_token": tokens.get("refresh_token"),
            "email": email,
            "scopes": scopes,
        }
    return None


def build_tokeninfo_url(provider, access_token: str) -> Optional[str]:
    """Return a browser-friendly token inspection URL if supported."""
    if not provider.tokeninfo_endpoint:
        return None
    return f"{provider.tokeninfo_endpoint}?access_token={access_token}"


def fetch_userinfo(http_client, endpoint: str, access_token: str):
    """Fetch user information using the provided HTTP client."""
    response = http_client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    return response


def sign_in_snippet(provider, client_id: str, redirect_uri: str, scopes: Iterable[str]) -> str:
    """Return an embeddable HTML sign-in button snippet."""
    return provider.sign_in_snippet(client_id, redirect_uri, scopes)
