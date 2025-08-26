import base64
import json
import os
import re
import threading
import time
import webbrowser
from email.mime.text import MIMEText

import requests
from werkzeug.serving import make_server

from app import create_app
from scopes import (
    get_token_scopes, analyze_scope_gap, generate_reauth_url,
    oauth2_userinfo_endpoints, SCOPE_GROUPS, count_methods
)

redirect_uri = "http://localhost:5000/callback"
BASE_SCOPE = "openid email profile"
RESULT_PATH = ".last_oauth.json"
ENV_PATH = ".env"


# ---------------- Utils ----------------

def safe_mask(token: str) -> str:
    if not token:
        return ""
    return token[:12] + "…" + token[-6:]


def parse_project_number(client_id: str) -> str | None:
    # ex: 694912225334-abc.apps.googleusercontent.com  -> "694912225334"
    if "-" in client_id:
        prefix = client_id.split("-", 1)[0]
        if prefix.isdigit():
            return prefix
    return None


def open_enable_api_link(api_name: str, client_id: str):
    project = parse_project_number(client_id) or ""
    url = f"https://console.developers.google.com/apis/api/{api_name}/overview?project={project}"
    print(f"\n⚙️  This API is disabled for project {project}.")
    print(f"👉 Enable it here:\n   {url}\n")
    input("Press Enter to open the enable page…")
    webbrowser.open(url)
    print("⏳ Wait ~1 minute after enabling, then retry the action.")


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


def perform_oauth_flow(client_id: str, client_secret: str, requested_scopes: str):
    # 1) Open Google consent
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope={requested_scopes}"
        f"&access_type=offline"
        f"&prompt=consent"
        f"&include_granted_scopes=true"
    )
    print("\n✅ Generating Google OAuth Consent URL...\n")
    print(f"🌐 {auth_url}\n")
    input("Press Enter to open it in your browser...")
    webbrowser.open(auth_url)

    # 2) Start Flask in background & wait for callback
    done = threading.Event()
    app = create_app(client_id, client_secret, redirect_uri, done_event=done, result_path=RESULT_PATH)
    srv = ServerThread(app)
    srv.start()
    done.wait(timeout=300)  # 5 minutes
    srv.shutdown()

    # 3) Read tokens
    if not os.path.exists(RESULT_PATH):
        print("❌ No OAuth result found. Try again.")
        raise SystemExit(1)
    with open(RESULT_PATH) as f:
        tokens = json.load(f)
    at = tokens.get("access_token")
    if not at:
        print("❌ No access token in OAuth result.")
        raise SystemExit(1)
    # secure perms
    try:
        os.chmod(RESULT_PATH, 0o600)
    except Exception:
        pass
    return tokens, at


def try_load_env_tokens():
    """Fallback: read ACCESS_TOKEN / REFRESH_TOKEN from .env if present."""
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


def refresh_if_possible(client_id: str, client_secret: str):
    """Try to resume a session: refresh token -> access token, scopes, email."""
    tokens = {}
    # 1) Prefer .last_oauth.json
    if os.path.exists(RESULT_PATH):
        try:
            with open(RESULT_PATH) as f:
                tokens = json.load(f)
        except Exception:
            tokens = {}

    # 2) Fallback to .env
    env_toks = try_load_env_tokens()
    tokens = {**env_toks, **tokens}  # prefer .last_oauth.json values

    rt = tokens.get("refresh_token")
    at = tokens.get("access_token")

    def tokeninfo_scopes(ax):
        try:
            r = requests.get(
                "https://www.googleapis.com/oauth2/v3/tokeninfo",
                params={"access_token": ax},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                scope_str = data.get("scope", "")
                scopes = sorted(s for s in scope_str.split() if s)
                return scopes
        except Exception:
            pass
        return []

    # If we have refresh token -> refresh to get fresh AT
    if rt:
        try:
            rr = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "refresh_token": rt,
                    "grant_type": "refresh_token",
                },
                timeout=15,
            )
            if rr.status_code == 200:
                newt = rr.json()
                at = newt.get("access_token")
                if at:
                    tokens["access_token"] = at
                    # persist back
                    with open(RESULT_PATH, "w") as f:
                        json.dump(tokens, f)
                    try:
                        os.chmod(RESULT_PATH, 0o600)
                    except Exception:
                        pass
        except Exception:
            pass

    # If we have any AT, try to compute scopes & email
    if at:
        scopes = tokeninfo_scopes(at)
        email = None
        try:
            r = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {at}"},
                timeout=10,
            )
            if r.status_code == 200:
                email = r.json().get("email")
        except Exception:
            pass

        if scopes:
            return {"access_token": at, "refresh_token": tokens.get("refresh_token"), "email": email, "scopes": scopes}

    return None


def show_current_capabilities(current_scopes: list[str]):
    print("\n🔐 Current scopes:")
    for s in sorted(current_scopes):
        print(f"  • {s}")

    print("\n📚 Endpoints you can call NOW with your current scopes:")
    for ep in oauth2_userinfo_endpoints():
        print(f"  [✓] {ep['method']} {ep['url']}")
        print(f"      e.g. {ep['example']}")


def call_userinfo(access_token: str):
    print("\n🔎 Calling Google /userinfo ...")
    r = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    if r.status_code == 200:
        print(json.dumps(r.json(), indent=2))
    else:
        print(f"❌ Error: {r.status_code} {r.text}")


def open_tokeninfo_in_browser(access_token: str):
    url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={access_token}"
    print(f"\n🔐 Opening tokeninfo with your access token (masked): {safe_mask(access_token)}")
    webbrowser.open(url)


# ---------------- Gmail helpers ----------------

def gmail_has_read(scopes: list[str]) -> bool:
    need = set(SCOPE_GROUPS["Gmail"]["read"])
    return bool(set(scopes) & need)

def gmail_has_send(scopes: list[str]) -> bool:
    need = set(SCOPE_GROUPS["Gmail"]["write"])
    return bool(set(scopes) & need)

def maybe_handle_service_disabled(resp_text: str, client_id: str, api_name: str) -> bool:
    try:
        data = json.loads(resp_text)
        err = data.get("error", {})
        status = err.get("status")
        details = err.get("details", [])
        if status == "PERMISSION_DENIED":
            # Look for SERVICE_DISABLED
            for d in details:
                if d.get("@type", "").endswith("ErrorInfo") and d.get("reason") == "SERVICE_DISABLED":
                    open_enable_api_link(api_name, client_id)
                    return True
    except Exception:
        pass
    return False

def gmail_list_messages(access_token: str, client_id: str, max_results: int = 5, query: str = None):
    params = {"maxResults": max_results}
    if query:
        params["q"] = query
    r = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        timeout=20,
    )
    if r.status_code != 200:
        if r.status_code == 403 and maybe_handle_service_disabled(r.text, client_id, "gmail.googleapis.com"):
            return None  # signal caller to retry if user enabled API
        print(f"❌ Gmail list error: {r.status_code} {r.text}")
        return []

    ids = [m["id"] for m in r.json().get("messages", [])]
    results = []
    for mid in ids:
        rr = requests.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}",
            headers={"Authorization": f"Bearer {access_token}"},
            params={
                "format": "metadata",
                "metadataHeaders": ["From", "Subject", "Date"],
            },
            timeout=20,
        )
        if rr.status_code == 200:
            meta = rr.json()
            headers = {h["name"]: h["value"] for h in meta.get("payload", {}).get("headers", [])}
            results.append(
                {
                    "id": mid,
                    "from": headers.get("From", ""),
                    "subject": headers.get("Subject", ""),
                    "date": headers.get("Date", ""),
                    "snippet": meta.get("snippet", ""),
                }
            )
        elif rr.status_code == 403 and maybe_handle_service_disabled(rr.text, client_id, "gmail.googleapis.com"):
            return None
    return results

def gmail_get_message(access_token: str, client_id: str, message_id: str):
    r = requests.get(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"format": "full"},
        timeout=20,
    )
    if r.status_code == 200:
        return r.json()
    if r.status_code == 403 and maybe_handle_service_disabled(r.text, client_id, "gmail.googleapis.com"):
        return None
    print(f"❌ Gmail get error: {r.status_code} {r.text}")
    return None

def gmail_send_email(access_token: str, client_id: str, to_addr: str, subject: str, body: str):
    mime = MIMEText(body)
    mime["to"] = to_addr
    mime["subject"] = subject
    raw = base64.urlsafe_b64encode(mime.as_bytes()).decode("utf-8")
    payload = {"raw": raw}
    r = requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )
    if r.status_code in (200, 202):
        resp = r.json()
        print(f"✅ Email sent. Gmail message id: {resp.get('id')}")
        return resp
    if r.status_code == 403 and maybe_handle_service_disabled(r.text, client_id, "gmail.googleapis.com"):
        return None
    print(f"❌ Gmail send error: {r.status_code} {r.text}")
    return None


def show_upgrade_suggestions(client_id: str, current_scopes: list[str]):
    print("\n🚀 Suggestions to unlock more:")
    gap_summary, _ = analyze_scope_gap(current_scopes)
    menu = []
    idx = 1

    for item in gap_summary:
        svc = item["service"]
        read_missing = item["read_missing"]
        write_missing = item["write_missing"]
        both_missing = item["both_missing"]

        print(f"\n▶ {svc}")

        # READ
        if read_missing:
            read_count, _ = count_methods(svc, read_missing)
            print(f"  [{idx}] Add READ scopes ({len(read_missing)}) → unlock ≈ {read_count} endpoints")
            menu.append(("reauth", svc, "read", read_missing))
            idx += 1
        else:
            print("  ✓ READ access already present (or not applicable)")

        # WRITE
        if write_missing:
            write_count, _ = count_methods(svc, write_missing)
            print(f"  [{idx}] Add WRITE scopes ({len(write_missing)}) → unlock ≈ {write_count} endpoints")
            menu.append(("reauth", svc, "write", write_missing))
            idx += 1
        else:
            print("  ✓ WRITE access already present (or not applicable)")

        # BOTH
        if both_missing:
            both_count, _ = count_methods(svc, both_missing)
            print(f"  [{idx}] Add READ & WRITE together ({len(both_missing)}) → unlock ≈ {both_count} endpoints")
            menu.append(("reauth", svc, "both", both_missing))
            idx += 1

    # Utility actions
    print(f"\n[{idx}] Call Google /userinfo now")
    menu.append(("userinfo",))
    idx += 1
    print(f"[{idx}] Open tokeninfo in browser (token auto-inserted)")
    menu.append(("tokeninfo",))
    idx += 1
    print(f"[{idx}] Gmail: list last 5 messages")
    menu.append(("gmail_list",))
    idx += 1
    print(f"[{idx}] Gmail: read a message by ID")
    menu.append(("gmail_read",))
    idx += 1
    print(f"[{idx}] Gmail: send a test email")
    menu.append(("gmail_send",))
    idx += 1
    print(f"[{idx}] Show 'Sign in with Google' button snippet")
    menu.append(("snippet",))
    idx += 1
    print(f"[{idx}] Exit")
    menu.append(("exit",))

    return menu


def print_signin_button_snippet(client_id: str, redirect_uri: str, scopes: list[str]):
    scopes_str = " ".join(sorted(scopes))
    print("\n🔘 Sign in with Google — HTML snippet:\n")
    print(f"""<a href="https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={scopes_str}&access_type=offline&prompt=consent&include_granted_scopes=true">
  <img src="https://developers.google.com/identity/images/btn_google_signin_dark_normal_web.png" alt="Sign in with Google" style="height:40px;">
</a>""")
    print("\n(Use this on your site; handle the /callback on your backend.)")


# ---------------- Entry point (existing UX + auto-resume) ----------------

print("\n🚀 Welcome to OAuth Wizard MVP for Google\n")

print("""
⭐ RECOMMENDED WAY ⭐
Upload your 'client_secrets.json' file from Google.
It's the easiest and most error-proof way.

⚠️ IMPORTANT: Before closing the Google pop-up that shows your Client ID and Secret, click 'Download JSON'!
This will save a file like 'OAuth Client ID ... .json' on your computer.

If you already closed it, no worries:
👉 Go back to Google Console ➔ 'APIs & Services' ➔ 'Credentials'
   and click the ✏️ pencil icon next to your OAuth app,
   then click 'Download JSON' at the top.

🎯 Google Console: https://console.cloud.google.com/apis/credentials
""")

# ---------- Credentials ----------
while True:
    choice = input("\n(1) Upload JSON file  (2) Enter manually  (3) I don't have an app yet ➔ guide me ➔ Your choice or drag & drop JSON here ➔ ").strip()
    if choice.startswith("'") and choice.endswith("'"):
        choice_path = choice.strip("'")
        if os.path.exists(choice_path):
            choice = "1"; path = choice_path; break
        else:
            print(f"⚠️ File {choice_path} not found. Try again.")
    elif os.path.exists(choice):
        choice = "1"; path = choice; break
    elif choice in ("1", "2", "3"):
        break
    else:
        print("⚠️ Invalid choice. Try again.")

if choice == "3":
    print("\n👉 Go directly to create your OAuth App here:")
    print("   https://console.cloud.google.com/auth/clients/create")
    print(f"""
Fill out:
• Application type: Web application
• Name: MyApp-OAuth (or any name)
• Authorized redirect URIs:
   - Click 'Add URI' and enter: {redirect_uri}

✅ Then click 'Create' and download the JSON immediately.

⭐ IMPORTANT:
You will only see your client secret ONCE — when you first create your OAuth client.
Make sure you download the JSON or copy your secret right away.

If you lost it or closed the pop-up:
👉 Go to your OAuth app in Google Console and click '+ Add Secret' to generate a new one.

⭐ Tip: after you have your JSON, you can drag & drop it right here or choose option (1) to upload it, or (2) to paste manually.
""")
    while True:
        choice = input("\n(1) Upload JSON file  (2) Enter manually ➔ Your choice or drag & drop JSON here ➔ ").strip()
        if choice.startswith("'") and choice.endswith("'"):
            choice_path = choice.strip("'")
            if os.path.exists(choice_path):
                choice = "1"; path = choice_path; break
            else:
                print(f"⚠️ File {choice_path} not found. Try again.")
        elif os.path.exists(choice):
            choice = "1"; path = choice; break
        elif choice in ("1", "2"):
            break
        else:
            print("⚠️ Invalid choice. Try again.")

if choice == "1":
    if 'path' not in locals():
        print("\n📁 Tip: drag & drop your JSON file here (macOS pastes the path with single quotes).")
        while True:
            path = input("\nEnter path to your downloaded 'client_secrets.json': ").strip().strip("'")
            if os.path.exists(path):
                break
            print("⚠️ File not found. Try again.")
    try:
        with open(path) as f:
            data = json.load(f)
        client_id = data["web"]["client_id"]
        client_secret = data["web"]["client_secret"]
        print("\n✅ Successfully loaded your Client ID and Secret from JSON.")
    except Exception as e:
        print(f"⚠️ Error parsing JSON: {e}")
        raise SystemExit(1)
else:
    print("\n🔎 Enter your credentials manually below.")
    print("If you need to go to your Google Console, here's the link just in case:")
    print("   https://console.cloud.google.com/apis/credentials")
    while True:
        client_id = input("\n🔎 Paste your Google Client ID here: ").strip()
        if re.match(r"^\d{12,}-[a-z0-9\-]+\.apps\.googleusercontent\.com$", client_id):
            break
        print("⚠️ That doesn't look like a valid Google Client ID. Try again.")
    while True:
        client_secret = input("\n🔑 Paste your Google Client Secret here: ").strip()
        if len(client_secret) > 10:
            break
        print("⚠️ That doesn't look like a valid secret. Try again.")

# ---------- NEW: Try to resume an existing session ----------
resume = refresh_if_possible(client_id, client_secret)
use_existing = False
access_token = None
current_scopes = []

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

# ---------- First OAuth with base scopes (if not using existing) ----------
if not use_existing:
    tokens, access_token = perform_oauth_flow(client_id, client_secret, BASE_SCOPE)
    current_scopes = get_token_scopes(access_token)
    print("\n🎉 OAuth success. Back in CLI.")
    print("Service: Google")
else:
    print("\n✅ Reused existing session. Back in CLI.")
    print("Service: Google")

show_current_capabilities(current_scopes)

# ---------- Interactive menu loop ----------
while True:
    menu = show_upgrade_suggestions(client_id, current_scopes)
    choice = input("\nPick an action by number ➔ ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(menu):
        print("⚠️ Invalid choice. Try again.")
        continue

    action = menu[int(choice) - 1]

    if action[0] == "exit":
        print("\n👋 Bye!")
        break

    elif action[0] == "userinfo":
        call_userinfo(access_token)

    elif action[0] == "tokeninfo":
        open_tokeninfo_in_browser(access_token)

    elif action[0] == "snippet":
        print_signin_button_snippet(client_id, redirect_uri, current_scopes)

    elif action[0] == "gmail_list":
        if not gmail_has_read(current_scopes):
            print("⚠️ Gmail READ scope missing. Use an 'Add READ' option above to re-auth.")
            continue
        items = gmail_list_messages(access_token, client_id, max_results=5)
        if items is None:
            # user probably enabled API; give them a quick retry path
            input("After enabling Gmail API, press Enter to retry listing…")
            items = gmail_list_messages(access_token, client_id, max_results=5)
        if not items:
            print("No messages found.")
            continue
        print("\n📬 Last messages:")
        for it in items:
            print(f"- id={it['id']}\n  From: {it['from']}\n  Subject: {it['subject']}\n  Date: {it['date']}\n  Snippet: {it['snippet']}\n")

    elif action[0] == "gmail_read":
        if not gmail_has_read(current_scopes):
            print("⚠️ Gmail READ scope missing. Use an 'Add READ' option above to re-auth.")
            continue
        mid = input("Enter Gmail message id to fetch ➔ ").strip()
        if not mid:
            print("⚠️ Missing id.")
            continue
        msg = gmail_get_message(access_token, client_id, mid)
        if msg is None:
            input("After enabling Gmail API (if needed), press Enter to retry…")
            msg = gmail_get_message(access_token, client_id, mid)
        if msg:
            print(json.dumps(msg, indent=2))

    elif action[0] == "gmail_send":
        if not gmail_has_send(current_scopes):
            print("⚠️ Gmail SEND scope missing. Use an 'Add WRITE' option above to re-auth.")
            continue
        to_addr = input("To ➔ ").strip()
        subject = input("Subject ➔ ").strip()
        body = input("Body ➔ ").strip()
        resp = gmail_send_email(access_token, client_id, to_addr, subject, body)
        if resp is None:
            input("After enabling Gmail API (if needed), press Enter to retry send…")
            gmail_send_email(access_token, client_id, to_addr, subject, body)

    elif action[0] == "reauth":
        _, svc, mode, missing_scopes = action
        print(f"\nRe-auth for {svc} ({mode}) …")
        requested = sorted(set(current_scopes) | set(missing_scopes))
        requested_str = " ".join(requested)
        tokens, access_token = perform_oauth_flow(client_id, client_secret, requested_str)
        current_scopes = get_token_scopes(access_token)
        print("\n✅ Re-auth complete. Updated scopes loaded.")
        show_current_capabilities(current_scopes)
