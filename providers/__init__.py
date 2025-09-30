from __future__ import annotations

from typing import Dict, List

from .base import EndpointInfo, OAuthProvider, ProviderAction, ProviderContext
from .google import provider as google_provider
from .github import provider as github_provider
from .basecamp import provider as basecamp_provider
from .slack import provider as slack_provider
from .trello import provider as trello_provider
from .notion import provider as notion_provider

_PROVIDERS: Dict[str, OAuthProvider] = {
    google_provider.id: google_provider,
    github_provider.id: github_provider,
    basecamp_provider.id: basecamp_provider,
    slack_provider.id: slack_provider,
    trello_provider.id: trello_provider,
    notion_provider.id: notion_provider,
}


def list_providers() -> List[OAuthProvider]:
    return list(_PROVIDERS.values())


def get_provider(provider_id: str) -> OAuthProvider:
    return _PROVIDERS[provider_id]

