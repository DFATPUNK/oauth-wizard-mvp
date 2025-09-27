"""Command line interface entrypoint powered by Typer."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import requests
import typer

from oauth.flow import (
    AccessTokenMissingError,
    DEFAULT_REDIRECT_URI,
    OAuthResultNotFoundError,
    RESULT_PATH,
    build_tokeninfo_url,
    fetch_userinfo,
    perform_oauth_flow,
    refresh_session,
    safe_mask,
    sign_in_snippet,
)
from providers import list_providers
from providers.base import OAuthProvider, ProviderAction, ProviderContext
from scopes import (
    analyze_scope_gap,
    count_methods,
    discover_methods_for_service,
    filter_methods_by_scopes,
    get_token_scopes,
    oauth2_userinfo_endpoints,
)

app = typer.Typer(help="Run the interactive OAuth wizard", invoke_without_command=True)


def _prompt_choice(prompt: str, minimum: int, maximum: int) -> int:
    while True:
        choice = typer.prompt(prompt, type=int)
        if minimum <= choice <= maximum:
            return choice
        typer.echo(f"⚠️ Please choose a value between {minimum} and {maximum}.")


def _prompt_file_path(prompt: str) -> Path:
    while True:
        raw = typer.prompt(prompt).strip().strip("'\"")
        path = Path(raw)
        if path.exists():
            return path
        typer.echo(f"⚠️ File '{raw}' not found. Try again.")


def _prompt_json_input(message: str, expect_object: bool = False):
    while True:
        raw = typer.prompt(message, default="").strip()
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            typer.echo(f"⚠️ Invalid JSON: {exc}")
            continue
        if expect_object and not isinstance(data, dict):
            typer.echo("⚠️ Please enter a JSON object (e.g. {\"foo\": \"bar\"}).")
            continue
        return data


def _build_browser_opener(auto_open_browser: bool):
    if auto_open_browser:
        return typer.launch
    return lambda url: typer.echo(f"Open this URL in your browser: {url}")


def _bootstrap_session(
    provider: OAuthProvider,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    auto_open_browser: bool,
) -> Tuple[str, List[str]]:
    resume = refresh_session(provider, client_id, client_secret, result_path=RESULT_PATH)
    access_token: Optional[str] = None
    current_scopes: List[str] = []

    if resume:
        access_token = resume["access_token"]
        current_scopes = resume["scopes"]
        email = resume.get("email") or "unknown"
        typer.echo("\n🔁 Existing session detected!")
        typer.echo(f"   • Email: {email}")
        typer.echo(f"   • Scopes: {len(current_scopes)} scopes")
        if typer.confirm("Use this session without opening the browser?", default=True):
            typer.echo("\n✅ Reused existing session. Back in CLI.")
        else:
            access_token = None
            current_scopes = []

    if not access_token:
        browser_opener = _build_browser_opener(auto_open_browser)
        try:
            _, access_token, _ = perform_oauth_flow(
                provider,
                client_id,
                client_secret,
                provider.base_scopes,
                redirect_uri=redirect_uri,
                browser_opener=browser_opener,
                echo=typer.echo,
            )
        except OAuthResultNotFoundError as exc:
            raise typer.Exit(str(exc))
        except AccessTokenMissingError as exc:
            raise typer.Exit(str(exc))
        current_scopes = get_token_scopes(provider, access_token)
        typer.echo("\n🎉 OAuth success. Back in CLI.")

    typer.echo(f"Service: {provider.name}")
    return access_token, current_scopes


def _reauth_with_scopes(
    provider: OAuthProvider,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    current_scopes: Iterable[str],
    required_scopes: Iterable[str],
    browser_opener,
) -> Tuple[Optional[str], Optional[List[str]]]:
    requested = sorted(set(current_scopes) | set(required_scopes))
    try:
        _, access_token, _ = perform_oauth_flow(
            provider,
            client_id,
            client_secret,
            requested,
            redirect_uri=redirect_uri,
            browser_opener=browser_opener,
            echo=typer.echo,
        )
    except OAuthResultNotFoundError as exc:
        typer.echo(str(exc))
        return None, None
    except AccessTokenMissingError as exc:
        typer.echo(str(exc))
        return None, None
    new_scopes = get_token_scopes(provider, access_token)
    typer.echo("\n✅ Re-auth complete. Updated scopes loaded.")
    return access_token, new_scopes


def _list_discovered_services(provider: OAuthProvider) -> List[Tuple[str, List[Dict], Dict]]:
    services: List[Tuple[str, List[Dict], Dict]] = []
    for service, meta in provider.discovery_metadata.items():
        methods = discover_methods_for_service(provider, service)
        if methods:
            services.append((service, methods, meta))
    return services


def _choose_discovered_service(
    provider: OAuthProvider,
    current_scopes: Iterable[str],
    services: Optional[List[Tuple[str, List[Dict], Dict]]] = None,
) -> Optional[Tuple[str, List[Dict], Dict]]:
    if services is None:
        services = _list_discovered_services(provider)
    if not services:
        return None

    typer.echo("\n📚 Discovered API services:")
    for idx, (service, methods, _meta) in enumerate(services, start=1):
        allowed = filter_methods_by_scopes(methods, current_scopes)
        typer.echo(
            f"  ({idx}) {service} — {len(allowed)}/{len(methods)} endpoints usable with current scopes"
        )
    typer.echo("  (0) Enter a custom URL")

    choice = _prompt_choice("Select a service (0 for custom)", 0, len(services))
    if choice == 0:
        return None
    return services[choice - 1]


def _normalize_full_url(base_url: str, path: str) -> str:
    base = base_url or ""
    path = path or ""
    if not base:
        return path
    if base.endswith("/") and path.startswith("/"):
        return base + path[1:]
    if not base.endswith("/") and path and not path.startswith("/"):
        return f"{base}/{path}"
    return f"{base}{path}"


def _choose_discovered_method(
    service: str, methods: List[Dict], current_scopes: Iterable[str]
) -> Optional[Dict]:
    filter_term = ""
    current = set(current_scopes)

    while True:
        filtered = [
            method
            for method in methods
            if not filter_term
            or filter_term.lower() in method.get("path", "").lower()
            or filter_term.lower() in method.get("description", "").lower()
        ]

        if not filtered:
            typer.echo("⚠️ No endpoints matched that keyword. Try again.")
            filter_term = typer.prompt("Keyword (blank for all)", default="").strip()
            continue

        shown = filtered[:10]
        typer.echo(
            f"\n🔎 {service} endpoints (showing {len(shown)} of {len(filtered)} matches)"
        )
        for idx, method in enumerate(shown, start=1):
            full_url = _normalize_full_url(method.get("baseUrl", ""), method.get("path", ""))
            missing = sorted(set(method.get("scopes", [])) - current)
            summary = method.get("description", "").strip()
            if summary and len(summary) > 100:
                summary = summary[:97] + "…"
            typer.echo(f"  ({idx}) {method.get('httpMethod', 'GET')} {full_url}")
            if summary:
                typer.echo(f"        {summary}")
            if missing:
                typer.echo(f"        Missing scopes: {', '.join(missing)}")

        typer.echo("  (0) Search with a different keyword")
        typer.echo(f"  ({len(shown) + 1}) Enter a custom endpoint")
        choice = _prompt_choice("Pick an endpoint", 0, len(shown) + 1)
        if choice == 0:
            filter_term = typer.prompt("Keyword (blank for all)", default="").strip()
            continue
        if choice == len(shown) + 1:
            return None
        return shown[choice - 1]


def _perform_endpoint_request(
    method: str,
    url: str,
    access_token: str,
    params: Optional[Dict],
    json_body,
):
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=30,
        )
    except requests.RequestException as exc:
        typer.echo(f"❌ Request failed: {exc}")
        return None

    typer.echo(f"\nHTTP {response.status_code} {response.reason}")
    typer.echo("Headers:")
    for key, value in response.headers.items():
        typer.echo(f"  {key}: {value}")

    typer.echo("Body:")
    try:
        payload = response.json()
    except ValueError:
        text = response.text or "(empty body)"
        typer.echo(text)
    else:
        typer.echo(json.dumps(payload, indent=2))

    return response


def _run_endpoint_tester(
    provider: OAuthProvider,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    access_token: str,
    current_scopes: List[str],
    browser_opener,
) -> Tuple[str, List[str]]:
    typer.echo("\n🧪 API endpoint tester")
    services = _list_discovered_services(provider)
    if not services:
        typer.echo("ℹ️ No discovery catalog found for this provider. Enter endpoints manually.")

    while True:
        selection = _choose_discovered_service(provider, current_scopes, services)
        docs_url: Optional[str] = None
        chosen_method: Optional[Dict] = None
        required_scopes: List[str] = []
        default_method = "GET"
        default_url = ""

        if selection:
            service, methods, meta = selection
            docs_url = meta.get("docs_url")
            chosen_method = _choose_discovered_method(service, methods, current_scopes)
            if chosen_method:
                required_scopes = chosen_method.get("scopes", [])
                default_method = chosen_method.get("httpMethod", "GET")
                default_url = _normalize_full_url(
                    chosen_method.get("baseUrl", ""), chosen_method.get("path", "")
                )
            else:
                default_url = methods[0].get("baseUrl", "") if methods else ""
        else:
            typer.echo("\nCustom endpoint selected.")

        if chosen_method is None and not default_url:
            default_url = ""

        missing_scopes = [scope for scope in required_scopes if scope not in current_scopes]
        if missing_scopes:
            typer.echo("\n⚠️ This endpoint requires additional scopes:")
            for scope in missing_scopes:
                typer.echo(f"   • {scope}")
            if typer.confirm("Re-run consent flow to add them?", default=True):
                result = _reauth_with_scopes(
                    provider,
                    client_id,
                    client_secret,
                    redirect_uri,
                    current_scopes,
                    missing_scopes,
                    browser_opener,
                )
                if result[0] and result[1]:
                    access_token, current_scopes = result  # type: ignore[assignment]
                else:
                    typer.echo("⚠️ Continuing with existing scopes.")
            else:
                typer.echo("Proceeding without requesting new scopes.")

        method_default = default_method or "GET"
        method_choice = typer.prompt("HTTP method", default=method_default).strip().upper()
        if not method_choice:
            method_choice = method_default.upper()

        while True:
            url_choice = typer.prompt("Request URL", default=default_url).strip()
            if url_choice:
                break
            typer.echo("⚠️ URL is required.")

        params = _prompt_json_input("Query parameters as JSON (blank for none)", expect_object=True)
        body = _prompt_json_input("JSON body (blank for none)")

        response = _perform_endpoint_request(
            method_choice,
            url_choice,
            access_token,
            params,
            body,
        )

        if response is not None and response.status_code in {401, 403}:
            typer.echo("\n⚠️ Authentication or authorization error detected.")
            if docs_url and typer.confirm("Open the provider docs for troubleshooting?", default=True):
                browser_opener(docs_url)

        if not typer.confirm("Test another endpoint?", default=False):
            break

    return access_token, current_scopes


def _choose_provider(provider_id: str | None) -> OAuthProvider:
    providers = list_providers()
    if not providers:
        raise typer.Exit(code=1)

    if provider_id:
        for provider in providers:
            if provider.id == provider_id:
                return provider
        raise typer.BadParameter(f"Unknown provider id '{provider_id}'.")

    typer.echo("\nAvailable OAuth providers:")
    for idx, provider in enumerate(providers, start=1):
        typer.echo(f"  ({idx}) {provider.name}")

    choice = _prompt_choice("Pick a provider by number", 1, len(providers))
    return providers[choice - 1]


def _prompt_credentials(provider: OAuthProvider, redirect_uri: str) -> Tuple[str, str]:
    typer.echo(provider.welcome_text(redirect_uri))

    choice = _prompt_choice(
        "How would you like to provide credentials?\n(1) Upload JSON file  (2) Enter manually  (3) I don't have an app yet",
        1,
        3,
    )

    if choice == 3:
        typer.echo(provider.app_creation_instructions(redirect_uri))
        choice = _prompt_choice("Ready to provide credentials? (1) Upload JSON  (2) Enter manually", 1, 2)

    if choice == 1:
        typer.echo("\n📁 Tip: drag & drop your JSON file here (macOS pastes the path with single quotes).")
        path = _prompt_file_path("Enter path to your downloaded client secrets file")
        try:
            client_id, client_secret = provider.load_credentials_from_file(str(path))
        except Exception as exc:  # pragma: no cover - defensive guard
            raise typer.BadParameter(f"Error parsing JSON: {exc}") from exc
        typer.echo("\n✅ Successfully loaded your Client ID and Secret from JSON.")
        return client_id, client_secret

    typer.echo(provider.manual_entry_instructions())
    while True:
        client_id = typer.prompt(f"Paste your {provider.name} Client ID").strip()
        if provider.validate_client_id(client_id):
            break
        typer.echo("⚠️ That doesn't look like a valid Client ID. Try again.")

    while True:
        client_secret = typer.prompt(f"Paste your {provider.name} Client Secret").strip()
        if provider.validate_client_secret(client_secret):
            break
        typer.echo("⚠️ That doesn't look like a valid secret. Try again.")

    return client_id, client_secret


def _display_capabilities(provider: OAuthProvider, current_scopes: Iterable[str]) -> None:
    typer.echo("\n🔐 Current scopes:")
    for scope in sorted(current_scopes):
        typer.echo(f"  • {scope}")

    typer.echo("\n📚 Endpoints you can call NOW with your current scopes:")
    for endpoint in oauth2_userinfo_endpoints(provider):
        typer.echo(f"  [✓] {endpoint.method} {endpoint.url}")
        typer.echo(f"      e.g. {endpoint.example}")


def _render_menu(provider: OAuthProvider, current_scopes: List[str]) -> List[Tuple]:
    gap_summary, _ = analyze_scope_gap(provider, current_scopes)
    menu: List[Tuple] = []
    idx = 1

    for item in gap_summary:
        service = item["service"]
        read_missing = item["read_missing"]
        write_missing = item["write_missing"]
        both_missing = item["both_missing"]

        typer.echo(f"\n▶ {service}")

        if read_missing:
            read_count, _ = count_methods(provider, service, read_missing)
            typer.echo(
                f"  [{idx}] Add READ scopes ({len(read_missing)}) → unlock ≈ {read_count} endpoints"
            )
            menu.append(("reauth", service, "read", read_missing))
            idx += 1
        else:
            typer.echo("  ✓ READ access already present (or not applicable)")

        if write_missing:
            write_count, _ = count_methods(provider, service, write_missing)
            typer.echo(
                f"  [{idx}] Add WRITE scopes ({len(write_missing)}) → unlock ≈ {write_count} endpoints"
            )
            menu.append(("reauth", service, "write", write_missing))
            idx += 1
        else:
            typer.echo("  ✓ WRITE access already present (or not applicable)")

        if both_missing:
            both_count, _ = count_methods(provider, service, both_missing)
            typer.echo(
                f"  [{idx}] Add READ & WRITE together ({len(both_missing)}) → unlock ≈ {both_count} endpoints"
            )
            menu.append(("reauth", service, "both", both_missing))
            idx += 1

    typer.echo(f"\n[{idx}] Call userinfo now")
    menu.append(("userinfo",))
    idx += 1

    typer.echo(f"[{idx}] Open token inspection in browser")
    menu.append(("tokeninfo",))
    idx += 1

    typer.echo(f"[{idx}] Show 'Sign in with {provider.name}' button snippet")
    menu.append(("snippet",))
    idx += 1

    typer.echo(f"[{idx}] Test an API endpoint")
    menu.append(("test_endpoint",))
    idx += 1

    for action in provider.menu_actions():
        typer.echo(f"[{idx}] {action.label}")
        menu.append(("provider_action", action))
        idx += 1

    typer.echo(f"[{idx}] Exit")
    menu.append(("exit",))

    return menu


def _run_provider_action(
    action: ProviderAction,
    provider: OAuthProvider,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    access_token: str,
    current_scopes: Iterable[str],
    browser_opener,
) -> None:
    context = ProviderContext(
        provider=provider,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        access_token=access_token,
        http_client=requests,
        prompt=lambda message: typer.prompt(message).strip(),
        confirm=lambda message: typer.confirm(message, default=True),
        echo=typer.echo,
        open_browser=browser_opener,
    )
    if not action.is_available(current_scopes):
        message = action.missing_scope_message or "⚠️ Required scopes are missing. Re-auth with additional scopes first."
        typer.echo(message)
        return
    action.handler(context)


def _execute_wizard(
    provider_id: str | None,
    redirect_uri: str,
    auto_open_browser: bool,
) -> None:
    """Run the interactive OAuth wizard CLI."""

    provider: OAuthProvider = _choose_provider(provider_id)
    client_id, client_secret = _prompt_credentials(provider, redirect_uri)

    access_token, current_scopes = _bootstrap_session(
        provider,
        client_id,
        client_secret,
        redirect_uri,
        auto_open_browser,
    )

    _display_capabilities(provider, current_scopes)

    browser_opener = _build_browser_opener(auto_open_browser)

    while True:
        menu = _render_menu(provider, current_scopes)
        choice = _prompt_choice("Pick an action by number", 1, len(menu))
        action = menu[choice - 1]

        if action[0] == "exit":
            typer.echo("\n👋 Bye!")
            break

        if action[0] == "userinfo":
            if not provider.userinfo_endpoint:
                typer.echo("⚠️ This provider does not expose a userinfo endpoint.")
                continue
            response = fetch_userinfo(requests, provider.userinfo_endpoint, access_token)
            if response.status_code == 200:
                typer.echo(json.dumps(response.json(), indent=2))
            else:
                typer.echo(f"❌ Error: {response.status_code} {response.text}")
            continue

        if action[0] == "tokeninfo":
            url = build_tokeninfo_url(provider, access_token)
            if not url:
                typer.echo("⚠️ This provider does not expose a token inspection endpoint.")
                continue
            typer.echo(f"\n🔐 Opening token info with your access token (masked): {safe_mask(access_token)}")
            browser_opener(url)
            continue

        if action[0] == "snippet":
            snippet = sign_in_snippet(provider, client_id, redirect_uri, current_scopes)
            typer.echo("\n🔘 Sign in with {name} — HTML snippet:\n".format(name=provider.name))
            typer.echo(snippet)
            typer.echo("\n(Use this on your site; handle the /callback on your backend.)")
            continue

        if action[0] == "test_endpoint":
            access_token, current_scopes = _run_endpoint_tester(
                provider,
                client_id,
                client_secret,
                redirect_uri,
                access_token,
                current_scopes,
                browser_opener,
            )
            continue

        if action[0] == "provider_action":
            provider_action: ProviderAction = action[1]
            _run_provider_action(
                provider_action,
                provider,
                client_id,
                client_secret,
                redirect_uri,
                access_token,
                current_scopes,
                browser_opener,
            )
            continue

        if action[0] == "reauth":
            _, service, mode, missing_scopes = action
            typer.echo(f"\nRe-auth for {service} ({mode}) …")
            requested = sorted(set(current_scopes) | set(missing_scopes))
            try:
                _, access_token, _ = perform_oauth_flow(
                    provider,
                    client_id,
                    client_secret,
                    requested,
                    redirect_uri=redirect_uri,
                    browser_opener=browser_opener,
                    echo=typer.echo,
                )
            except OAuthResultNotFoundError as exc:
                typer.echo(str(exc))
                continue
            except AccessTokenMissingError as exc:
                typer.echo(str(exc))
                continue
            current_scopes = get_token_scopes(provider, access_token)
            typer.echo("\n✅ Re-auth complete. Updated scopes loaded.")
            _display_capabilities(provider, current_scopes)
            continue


@app.command()
def wizard(
    provider_id: str = typer.Option(None, "--provider", "-p", help="Provider id to use."),
    redirect_uri: str = typer.Option(DEFAULT_REDIRECT_URI, help="Redirect URI to register with the provider."),
    auto_open_browser: bool = typer.Option(True, "--open-browser/--no-open-browser", help="Automatically open URLs in the browser."),
) -> None:
    """Explicit command to run the wizard."""

    _execute_wizard(
        provider_id=provider_id,
        redirect_uri=redirect_uri,
        auto_open_browser=auto_open_browser,
    )


@app.command("test-endpoint")
def test_endpoint(
    provider_id: str = typer.Option(None, "--provider", "-p", help="Provider id to use."),
    redirect_uri: str = typer.Option(DEFAULT_REDIRECT_URI, help="Redirect URI to register with the provider."),
    auto_open_browser: bool = typer.Option(True, "--open-browser/--no-open-browser", help="Automatically open URLs in the browser."),
) -> None:
    """Obtain an access token and invoke provider APIs interactively."""

    provider: OAuthProvider = _choose_provider(provider_id)
    client_id, client_secret = _prompt_credentials(provider, redirect_uri)
    access_token, current_scopes = _bootstrap_session(
        provider,
        client_id,
        client_secret,
        redirect_uri,
        auto_open_browser,
    )
    browser_opener = _build_browser_opener(auto_open_browser)
    _run_endpoint_tester(
        provider,
        client_id,
        client_secret,
        redirect_uri,
        access_token,
        current_scopes,
        browser_opener,
    )


@app.callback()
def main(
    ctx: typer.Context,
    provider_id: str = typer.Option(None, "--provider", "-p", help="Provider id to use."),
    redirect_uri: str = typer.Option(DEFAULT_REDIRECT_URI, help="Redirect URI to register with the provider."),
    auto_open_browser: bool = typer.Option(True, "--open-browser/--no-open-browser", help="Automatically open URLs in the browser."),
) -> None:
    """Invoke the wizard when no explicit sub-command is provided."""

    if ctx.invoked_subcommand is None:
        _execute_wizard(
            provider_id=provider_id,
            redirect_uri=redirect_uri,
            auto_open_browser=auto_open_browser,
        )


if __name__ == "__main__":
    app()
