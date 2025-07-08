import json
import os
import re
import webbrowser
from app import create_app

try:
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename
except ImportError:
    Tk = None  # fallback si tkinter non dispo

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
""")

# Choice
while True:
    choice = input("\n(1) Upload JSON file  (2) Enter manually  ➔ Your choice: ").strip()
    if choice in ("1", "2"):
        break

if choice == "1":
    print("\n📁 Tip: on Mac, you can drag & drop your JSON file into this Terminal window, it will paste the full path.")
    while True:
        path = input("\nEnter path to your downloaded 'client_secrets.json': ").strip()
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                client_id = data["web"]["client_id"]
                client_secret = data["web"]["client_secret"]
                print("\n✅ Successfully loaded your Client ID and Secret from JSON.")
                break
            except Exception as e:
                print(f"⚠️ Error parsing JSON: {e}")
        else:
            print("⚠️ File not found. Try again.")
else:
    print("\n👉 Open your Google Cloud Console here:")
    print("   https://console.cloud.google.com/apis/credentials")
    input("Press Enter to open it in your browser...")
    webbrowser.open("https://console.cloud.google.com/apis/credentials")

    print(f"""
🛠️ SETUP STEPS:

1️⃣ Click '+ CREATE CREDENTIALS' ➔ 'OAuth client ID'
2️⃣ ⚠️ If first OAuth app, set up consent screen.
3️⃣ On 'Create OAuth client ID':
   - Type: Web application
   - Leave 'Authorized JavaScript origins' EMPTY
   - Authorized redirect URI: {redirect_uri}
4️⃣ On the pop-up, click 'Download JSON' BEFORE closing.
""")

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

# Generate URL
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

# Start Flask with your creds
print("\n🚀 Now starting Flask server to wait for the callback on /callback ...")
app = create_app(client_id, client_secret, redirect_uri)
app.run(port=5000)
