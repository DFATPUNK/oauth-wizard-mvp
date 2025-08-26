# app.py
from flask import Flask, request, send_file
import requests, json, os

def create_app(client_id, client_secret, redirect_uri, done_event=None, result_path=".last_oauth.json"):
    app = Flask(__name__)
    latest_access_token = None

    @app.route("/callback")
    def callback():
        nonlocal latest_access_token
        code = request.args.get("code")
        if not code:
            return "No code found in request.", 400

        print(f"\nReceived code: {code}")
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
            print(json.dumps(tokens, indent=2))
            latest_access_token = tokens.get("access_token")

            # Persist .env
            with open(".env", "w") as f:
                f.write(f"GOOGLE_CLIENT_ID={client_id}\n")
                f.write(f"GOOGLE_CLIENT_SECRET={client_secret}\n")
                f.write(f"ACCESS_TOKEN={latest_access_token}\n")

            # Persist raw tokens for the CLI step
            try:
                os.chmod(".env", 0o600)
            except Exception:
                pass

            if result_path:
                with open(result_path, "w") as f:
                    json.dump(tokens, f)
                try:
                    os.chmod(result_path, 0o600)
                except Exception:
                    pass

            html = f"""
<h2>✅ OAuth Success!</h2>
<p>You can now return to the Terminal. We saved your credentials in <code>.env</code> and analysis will continue there.</p>
<ul>
  <li><a href="/download_env" download=".env">📥 Download your .env file</a></li>
  <li><a href="/userinfo">🔎 Try calling Google API now</a></li>
</ul>
"""
            # signal the CLI to continue
            if done_event:
                try:
                    done_event.set()
                except Exception:
                    pass

            return html
        else:
            print(f"❌ Failed to get token: {r.text}")
            return f"Error: {r.text}", 400

    @app.route("/download_env")
    def download_env():
        return send_file(".env", as_attachment=True)

    @app.route("/userinfo")
    def userinfo():
        if not latest_access_token:
            return "No access token available. Complete OAuth first.", 400
        headers = {"Authorization": f"Bearer {latest_access_token}"}
        r = requests.get("https://www.googleapis.com/oauth2/v2/userinfo", headers=headers)
        if r.status_code == 200:
            userinfo = r.json()
            return f"<h2>🎉 Your Google Profile:</h2><pre>{json.dumps(userinfo, indent=2)}</pre>"
        else:
            return f"Error calling Google API: {r.text}", 400

    return app
