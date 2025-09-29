from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol


def _default_prompt(message: str) -> str:
    return input(f"{message} ➔ ")


def _default_confirm(message: str) -> bool:
    answer = input(f"{message} [Y/n] ➔ ").strip().lower()
    if not answer:
        return True
    return answer.startswith("y")


@dataclass
class EndpointInfo:
    service: str
    method: str
    url: str
    requires: List[str]
    example: str


@dataclass
class ProviderAction:
    key: str
    label: str
    handler: Callable[["ProviderContext"], None]
    requires_any_scopes: List[str] = field(default_factory=list)
    missing_scope_message: Optional[str] = None

    def is_available(self, current_scopes: Iterable[str]) -> bool:
        if not self.requires_any_scopes:
            return True
        current = set(current_scopes)
        for scope in self.requires_any_scopes:
            if scope in current:
                return True
        return False


@dataclass
class ProviderContext:
    provider: "OAuthProvider"
    client_id: str
    client_secret: str
    redirect_uri: str
    access_token: str
    http_client: Any = None
    prompt: Callable[[str], str] = _default_prompt
    confirm: Callable[[str], bool] = _default_confirm
    echo: Callable[[str], None] = print
    open_browser: Callable[[str], None] = lambda _url: None


class OAuthProvider(Protocol):
    id: str
    name: str
    base_scopes: List[str]
    authorize_endpoint: str
    token_endpoint: str
    userinfo_endpoint: Optional[str]
    tokeninfo_endpoint: Optional[str]
    token_request_headers: Dict[str, str]
    scope_groups: Dict[str, Dict[str, List[str]]]
    discovery_metadata: Dict[str, Dict]

    def build_authorization_url(self, client_id: str, redirect_uri: str, scopes: Iterable[str]) -> str:
        ...

    def refresh_access_token(self, client_id: str, client_secret: str, refresh_token: str) -> Optional[Dict]:
        ...

    def fetch_token_scopes(self, access_token: str) -> List[str]:
        ...

    def fetch_user_email(self, access_token: str) -> Optional[str]:
        ...

    def userinfo_endpoints(self) -> List[EndpointInfo]:
        ...

    def sign_in_snippet(self, client_id: str, redirect_uri: str, scopes: Iterable[str]) -> str:
        ...

    def menu_actions(self) -> List[ProviderAction]:
        ...

    def welcome_text(self, redirect_uri: str) -> str:
        ...

    def manual_entry_instructions(self) -> str:
        ...

    def app_creation_instructions(self, redirect_uri: str) -> str:
        ...

    def load_credentials_from_file(self, path: str) -> tuple[str, str]:
        ...

    def validate_client_id(self, client_id: str) -> bool:
        ...

    def validate_client_secret(self, client_secret: str) -> bool:
        ...

