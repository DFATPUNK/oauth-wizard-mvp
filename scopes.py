"""Utilities for working with OAuth scopes and discovery catalogs."""
from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Tuple

import requests

from providers.base import OAuthProvider

DiscoveryHandler = Callable[[Dict], List[Dict]]

_DISCOVERY_HANDLERS: Dict[str, DiscoveryHandler] = {}


def register_discovery_handler(name: str, handler: DiscoveryHandler) -> None:
    _DISCOVERY_HANDLERS[name] = handler


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


def _fetch_discovery_rest(api_name: str, version: str) -> Dict | None:
    url = f"https://www.googleapis.com/discovery/v1/apis/{api_name}/{version}/rest"
    response = requests.get(url, timeout=15)
    if response.status_code == 200:
        return response.json()
    return None


def _extract_methods(doc: Dict) -> List[Dict]:
    methods: List[Dict] = []
    base_url = doc.get("baseUrl") or "".join(
        part for part in [doc.get("rootUrl", ""), doc.get("servicePath", "")] if part
    )

    def walk(resources: Dict) -> None:
        if not resources:
            return
        for _, resource in resources.items():
            if "methods" in resource:
                for _, method in resource["methods"].items():
                    methods.append(
                        {
                            "httpMethod": method.get("httpMethod", "GET"),
                            "path": method.get("path", ""),
                            "description": method.get("description", ""),
                            "scopes": method.get("scopes", []),
                            "baseUrl": base_url,
                        }
                    )
            if "resources" in resource:
                walk(resource["resources"])

    walk(doc.get("resources", {}))
    return methods


def _google_discovery_handler(config: Dict) -> List[Dict]:
    api = config.get("api")
    version = config.get("version")
    if not api or not version:
        return []
    doc = _fetch_discovery_rest(api, version)
    if not doc:
        return []
    return _extract_methods(doc)


register_discovery_handler("google_discovery", _google_discovery_handler)


def discover_methods_for_service(provider: OAuthProvider, service: str) -> List[Dict]:
    meta = provider.discovery_metadata.get(service)
    if not meta:
        return []
    if "methods" in meta and isinstance(meta["methods"], list):
        return meta["methods"]
    handler_name = meta.get("type")
    if handler_name and handler_name in _DISCOVERY_HANDLERS:
        return _DISCOVERY_HANDLERS[handler_name](meta)
    handler = meta.get("handler")
    if callable(handler):
        return handler(meta)
    return []


def filter_methods_by_scopes(methods: List[Dict], candidate_scopes: Iterable[str]) -> List[Dict]:
    allowed: List[Dict] = []
    candidate_set = set(candidate_scopes)
    for method in methods:
        required = set(method.get("scopes", []))
        if not required or required & candidate_set:
            allowed.append(method)
    return allowed


def count_methods(provider: OAuthProvider, service: str, candidate_scopes: Iterable[str]) -> Tuple[int, List[Dict]]:
    methods = discover_methods_for_service(provider, service)
    allowed = filter_methods_by_scopes(methods, candidate_scopes)
    return len(allowed), allowed[:10]


# ---------------------------------------------------------------------------
# Scope analysis
# ---------------------------------------------------------------------------


def get_token_scopes(provider: OAuthProvider, access_token: str) -> List[str]:
    return provider.fetch_token_scopes(access_token)


def analyze_scope_gap(provider: OAuthProvider, current_scopes: Iterable[str]):
    results = []
    missing_all: List[str] = []
    current = set(current_scopes)

    for service, groups in provider.scope_groups.items():
        read_scopes = groups.get("read", [])
        write_scopes = groups.get("write", [])

        read_missing = [scope for scope in read_scopes if scope not in current]
        write_missing = [scope for scope in write_scopes if scope not in current]

        if read_missing:
            missing_all.extend(read_missing)
        if write_missing:
            missing_all.extend(write_missing)

        results.append(
            {
                "service": service,
                "read_missing": read_missing,
                "write_missing": write_missing,
                "both_missing": sorted(set(read_missing + write_missing)),
            }
        )

    return results, sorted(set(missing_all))


def generate_reauth_url(provider: OAuthProvider, client_id: str, redirect_uri: str, scopes: Iterable[str]) -> str:
    return provider.build_authorization_url(client_id, redirect_uri, scopes)


def oauth2_userinfo_endpoints(provider: OAuthProvider):
    return provider.userinfo_endpoints()

