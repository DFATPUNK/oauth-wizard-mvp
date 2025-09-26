import json
import os
import threading
import webbrowser

import requests
from werkzeug.serving import make_server

from app import create_app
from providers import list_providers
from providers.base import ProviderContext
from scopes import (
    analyze_scope_gap,
    count_methods,
    get_token_scopes,
    oauth2_userinfo_endpoints,
)

redirect_uri = "http://localhost:5000/callback"
RESULT_PATH = ".last_oauth.json"
ENV_PATH = ".env"


# ---------------- Utils ----------------

def safe_mask(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 12:
        return token
    return token[:12] + "…" + token[-6:]


class ServerThread(threading.Thread):
    def __init__(self, flask_app):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", 5000, flask_app)
        self.ctx = flask_app.app_context()
        self.ctx.push()

    def run(self):
        print("\n🚀 Waiting for the callback at /callback ...")
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


# ---------------- Provider orchestration ----------------


def perform_oauth_flow(provider, client_id: str, client_secret: str, requested_scopes):
    auth_url = provider.build_authorization_url(client_id, redirect_uri, requested_scopes)
    print(f"\n✅ Generating {provider.name} OAuth consent URL...\n")
    print(f"🌐 {auth_url}\n")
    input("Press Enter to open it in your browser...")
    webbrowser.open(auth_url)

    done = threading.Event()
    app = create_app(provider, client_id, client_secret, redirect_uri, done_event=done, result_path=RESULT_PATH)
    srv = ServerThread(app)
    srv.start()
    done.wait(timeout=300)
    srv.shutdown()

    if not os.path.exists(RESULT_PATH):
        print("❌ No OAuth result found. Try again.")
        raise SystemExit(1)
    with open(RESULT_PATH) as f:
        tokens = json.load(f)
    access_token = tokens.get("access_token")
    if not access_token:
        print("❌ No access token in OAuth result.")
        raise SystemExit(1)
    try:
        os.chmod(RESULT_PATH, 0o600)
    except Exception:
        pass
    return tokens, access_token


def try_load_env_tokens():
    if not os.path.exists(ENV_PATH):
        return {}
    out = {}
    try:
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip().strip('"').strip("'")
                if k in ("ACCESS_TOKEN", "REFRESH_TOKEN", "ID_TOKEN"):
                    out[k.lower()] = v
    except Exception:
        pass
    return out


def refresh_if_possible(provider, client_id: str, client_secret: str):
    tokens = {}
    if os.path.exists(RESULT_PATH):
        try:
            with open(RESULT_PATH) as f:
                tokens = json.load(f)
        except Exception:
            tokens = {}

    env_tokens = try_load_env_tokens()
    tokens = {**env_tokens, **tokens}

    refresh_token = tokens.get("refresh_token")
    access_token = tokens.get("access_token")

    if refresh_token:
        refreshed = provider.refresh_access_token(client_id, client_secret, refresh_token)
        if refreshed and refreshed.get("access_token"):
            access_token = refreshed["access_token"]
            tokens["access_token"] = access_token
            with open(RESULT_PATH, "w") as f:
                json.dump(tokens, f)
            try:
                os.chmod(RESULT_PATH, 0o600)
            except Exception:
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


def show_current_capabilities(provider, current_scopes: list[str]):
    print("\n🔐 Current scopes:")
    for scope in sorted(current_scopes):
        print(f"  • {scope}")

    print("\n📚 Endpoints you can call NOW with your current scopes:")
    for endpoint in oauth2_userinfo_endpoints(provider):
        print(f"  [✓] {endpoint.method} {endpoint.url}")
        print(f"      e.g. {endpoint.example}")


def call_userinfo(provider, access_token: str):
    if not provider.userinfo_endpoint:
        print("⚠️ This provider does not expose a userinfo endpoint.")
        return
    print(f"\n🔎 Calling userinfo at {provider.userinfo_endpoint} ...")
    response = requests.get(
        provider.userinfo_endpoint,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    if response.status_code == 200:
        print(json.dumps(response.json(), indent=2))
    else:
        print(f"❌ Error: {response.status_code} {response.text}")


def open_tokeninfo_in_browser(provider, access_token: str):
    if not provider.tokeninfo_endpoint:
        print("⚠️ This provider does not expose a token inspection endpoint.")
        return
    url = f"{provider.tokeninfo_endpoint}?access_token={access_token}"
    print(f"\n🔐 Opening token info with your access token (masked): {safe_mask(access_token)}")
    webbrowser.open(url)


def print_signin_button_snippet(provider, client_id: str, redirect_uri: str, scopes: list[str]):
    snippet = provider.sign_in_snippet(client_id, redirect_uri, scopes)
    print(f"\n🔘 Sign in with {provider.name} — HTML snippet:\n")
    print(snippet)
    print("\n(Use this on your site; handle the /callback on your backend.)")


def build_menu(provider, current_scopes: list[str]):
    gap_summary, _ = analyze_scope_gap(provider, current_scopes)
    menu = []
    idx = 1

    for item in gap_summary:
        service = item["service"]
        read_missing = item["read_missing"]
        write_missing = item["write_missing"]
        both_missing = item["both_missing"]

        print(f"\n▶ {service}")

        if read_missing:
            read_count, _ = count_methods(provider, service, read_missing)
            print(f"  [{idx}] Add READ scopes ({len(read_missing)}) → unlock ≈ {read_count} endpoints")
            menu.append(("reauth", service, "read", read_missing))
            idx += 1
        else:
            print("  ✓ READ access already present (or not applicable)")

        if write_missing:
            write_count, _ = count_methods(provider, service, write_missing)
            print(f"  [{idx}] Add WRITE scopes ({len(write_missing)}) → unlock ≈ {write_count} endpoints")
            menu.append(("reauth", service, "write", write_missing))
            idx += 1
        else:
            print("  ✓ WRITE access already present (or not applicable)")

        if both_missing:
            both_count, _ = count_methods(provider, service, both_missing)
            print(f"  [{idx}] Add READ & WRITE together ({len(both_missing)}) → unlock ≈ {both_count} endpoints")
            menu.append(("reauth", service, "both", both_missing))
            idx += 1

    print(f"\n[{idx}] Call userinfo now")
    menu.append(("userinfo",))
    idx += 1

    print(f"[{idx}] Open token inspection in browser")
    menu.append(("tokeninfo",))
    idx += 1

    print(f"[{idx}] Show 'Sign in with {provider.name}' button snippet")
    menu.append(("snippet",))
    idx += 1

    for action in provider.menu_actions():
        print(f"[{idx}] {action.label}")
        menu.append(("provider_action", action))
        idx += 1

    print(f"[{idx}] Exit")
    menu.append(("exit",))

    return menu


def choose_provider():
    providers = list_providers()
    if not providers:
        raise SystemExit("No OAuth providers are registered.")

    print("\nAvailable OAuth providers:")
    for idx, provider in enumerate(providers, start=1):
        print(f"  ({idx}) {provider.name}")

    while True:
        choice = input("\nPick a provider by number ➔ ").strip()
        if choice.isdigit():
            num = int(choice)
            if 1 <= num <= len(providers):
                return providers[num - 1]
        print("⚠️ Invalid choice. Try again.")


def load_credentials(provider):
    print(provider.welcome_text(redirect_uri))

    while True:
        choice = input("\n(1) Upload JSON file  (2) Enter manually  (3) I don't have an app yet ➔ guide me ➔ Your choice or drag & drop JSON here ➔ ").strip()
        if choice.startswith("'") and choice.endswith("'"):
            choice_path = choice.strip("'")
            if os.path.exists(choice_path):
                choice = "1"
                path = choice_path
                break
            print(f"⚠️ File {choice_path} not found. Try again.")
        elif os.path.exists(choice):
            choice = "1"
            path = choice
            break
        elif choice in {"1", "2", "3"}:
            break
        else:
            print("⚠️ Invalid choice. Try again.")

    if choice == "3":
        print(provider.app_creation_instructions(redirect_uri))
        while True:
            choice = input("\n(1) Upload JSON file  (2) Enter manually ➔ Your choice or drag & drop JSON here ➔ ").strip()
            if choice.startswith("'") and choice.endswith("'"):
                choice_path = choice.strip("'")
                if os.path.exists(choice_path):
                    choice = "1"
                    path = choice_path
                    break
                print(f"⚠️ File {choice_path} not found. Try again.")
            elif os.path.exists(choice):
                choice = "1"
                path = choice
                break
            elif choice in {"1", "2"}:
                break
            else:
                print("⚠️ Invalid choice. Try again.")

    if choice == "1":
        if 'path' not in locals():
            print("\n📁 Tip: drag & drop your JSON file here (macOS pastes the path with single quotes).")
            while True:
                path = input("\nEnter path to your downloaded client secrets file: ").strip().strip("'")
                if os.path.exists(path):
                    break
                print("⚠️ File not found. Try again.")
        try:
            client_id, client_secret = provider.load_credentials_from_file(path)
            print("\n✅ Successfully loaded your Client ID and Secret from JSON.")
        except Exception as exc:
            print(f"⚠️ Error parsing JSON: {exc}")
            raise SystemExit(1)
    else:
        print(provider.manual_entry_instructions())
        while True:
            client_id = input(f"\n🔎 Paste your {provider.name} Client ID here: ").strip()
            if provider.validate_client_id(client_id):
                break
            print("⚠️ That doesn't look like a valid Client ID. Try again.")
        while True:
            client_secret = input(f"\n🔑 Paste your {provider.name} Client Secret here: ").strip()
            if provider.validate_client_secret(client_secret):
                break
            print("⚠️ That doesn't look like a valid secret. Try again.")

    return client_id, client_secret


# ---------------- Entry point ----------------

provider = choose_provider()
client_id, client_secret = load_credentials(provider)

resume = refresh_if_possible(provider, client_id, client_secret)
use_existing = False
access_token = None
current_scopes: list[str] = []

if resume:
    access_token = resume["access_token"]
    current_scopes = resume["scopes"]
    email = resume.get("email") or "unknown"
    print("\n🔁 Existing session detected!")
    print(f"   • Email: {email}")
    print(f"   • Scopes: {len(current_scopes)} scopes")
    ans = input("Use this session without opening the browser? (Y/n) ➔ ").strip().lower() or "y"
    if ans.startswith("y"):
        use_existing = True

if not use_existing:
    tokens, access_token = perform_oauth_flow(provider, client_id, client_secret, provider.base_scopes)
    current_scopes = get_token_scopes(provider, access_token)
    print("\n🎉 OAuth success. Back in CLI.")
    print(f"Service: {provider.name}")
else:
    print("\n✅ Reused existing session. Back in CLI.")
    print(f"Service: {provider.name}")

show_current_capabilities(provider, current_scopes)

while True:
    menu = build_menu(provider, current_scopes)
    choice = input("\nPick an action by number ➔ ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(menu):
        print("⚠️ Invalid choice. Try again.")
        continue

    action = menu[int(choice) - 1]

    if action[0] == "exit":
        print("\n👋 Bye!")
        break

    elif action[0] == "userinfo":
        call_userinfo(provider, access_token)

    elif action[0] == "tokeninfo":
        open_tokeninfo_in_browser(provider, access_token)

    elif action[0] == "snippet":
        print_signin_button_snippet(provider, client_id, redirect_uri, current_scopes)

    elif action[0] == "provider_action":
        provider_action = action[1]
        if not provider_action.is_available(current_scopes):
            message = provider_action.missing_scope_message or "⚠️ Required scopes are missing. Re-auth with additional scopes first."
            print(message)
            continue
        context = ProviderContext(
            provider=provider,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            access_token=access_token,
        )
        provider_action.handler(context)

    elif action[0] == "reauth":
        _, service, mode, missing_scopes = action
        print(f"\nRe-auth for {service} ({mode}) …")
        requested = sorted(set(current_scopes) | set(missing_scopes))
        tokens, access_token = perform_oauth_flow(provider, client_id, client_secret, requested)
        current_scopes = get_token_scopes(provider, access_token)
        print("\n✅ Re-auth complete. Updated scopes loaded.")
        show_current_capabilities(provider, current_scopes)

