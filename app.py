from flask import Flask, request
import requests

app = Flask(__name__)

client_id = None
client_secret = None
redirect_uri = "http://localhost:5000/callback"

@app.route("/callback")
def callback():
    global client_id, client_secret
    code = request.args.get("code")
    if not code:
        return "No code found in request.", 400

    print(f"Received code: {code}")
    # Exchange code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }

    r = requests.post(token_url, data=data)
    if r.status_code == 200:
        tokens = r.json()
        print("\n✅ Access Token flow successful!")
        print(tokens)
        return f"<pre>{tokens}</pre>"
    else:
        print(f"❌ Failed to get token: {r.text}")
        return f"Error: {r.text}", 400

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        client_id = sys.argv[1]
        client_secret = sys.argv[2]
    else:
        client_id = input("Client ID again (for Flask): ").strip()
        client_secret = input("Client Secret again (for Flask): ").strip()

    app.run(port=5000)