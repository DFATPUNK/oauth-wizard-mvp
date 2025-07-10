import json
import os
import re
import webbrowser
from app import create_app

redirect_uri = "http://localhost:5000/callback"
scope = "openid email profile"

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

while True:
    choice = input("\n(1) Upload JSON file  (2) Enter manually  (3) I don't have an app yet ➔ guide me ➔ Your choice or drag & drop JSON here ➔ ").strip()
    
    if choice.startswith("'") and choice.endswith("'"):
        choice_path = choice.strip("'")
        if os.path.exists(choice_path):
            choice = "1"
            path = choice_path
            break
        else:
            print(f"⚠️ File {choice_path} not found. Try again.")
    elif os.path.exists(choice):
        choice = "1"
        path = choice
        break
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
                choice = "1"
                path = choice_path
                break
            else:
                print(f"⚠️ File {choice_path} not found. Try again.")
        elif os.path.exists(choice):
            choice = "1"
            path = choice
            break
        elif choice in ("1", "2"):
            break
        else:
            print("⚠️ Invalid choice. Try again.")

if choice == "1":
    if not 'path' in locals():
        print("\n📁 Tip: on Mac, you can drag & drop your JSON file into this Terminal window. It will paste the full path with single quotes.")
        while True:
            path = input("\nEnter path to your downloaded 'client_secrets.json': ").strip().strip("'")
            if os.path.exists(path):
                break
            else:
                print("⚠️ File not found. Try again.")
    try:
        with open(path) as f:
            data = json.load(f)
        client_id = data["web"]["client_id"]
        client_secret = data["web"]["client_secret"]
        print("\n✅ Successfully loaded your Client ID and Secret from JSON.")
    except Exception as e:
        print(f"⚠️ Error parsing JSON: {e}")
        exit(1)
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

# --- OAuth URL ---
print("\n✅ Thanks! Generating your Google OAuth Consent URL...\n")
auth_url = (
    f"https://accounts.google.com/o/oauth2/v2/auth"
    f"?client_id={client_id}"
    f"&redirect_uri={redirect_uri}"
    f"&response_type=code"
    f"&scope={scope}"
)

print(f"🌐 Open this URL to start the OAuth flow:\n{auth_url}\n")
input("Press Enter to open it in your browser...")
webbrowser.open(auth_url)

# --- Start Flask and conclude there ---
print("\n🚀 Now starting Flask server to wait for the callback on /callback ...")
print("   (Press CTRL+C to quit anytime)")
app = create_app(client_id, client_secret, redirect_uri)
app.run(port=5000)
