from __future__ import annotations

from typing import Dict, List

from .base import EndpointInfo, OAuthProvider, ProviderAction, ProviderContext
from .google import provider as google_provider
from .github import provider as github_provider

_PROVIDERS: Dict[str, OAuthProvider] = {
    google_provider.id: google_provider,
    github_provider.id: github_provider,
}


def list_providers() -> List[OAuthProvider]:
    return list(_PROVIDERS.values())


def get_provider(provider_id: str) -> OAuthProvider:
    return _PROVIDERS[provider_id]

