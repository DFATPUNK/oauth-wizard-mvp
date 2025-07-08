import webbrowser

print("Welcome to OAuth Wizard MVP for Google")

client_id = input("Enter your Google Client ID: ").strip()
client_secret = input("Enter your Google Client Secret: ").strip()
redirect_uri = "http://localhost:5000/callback"
scope = "openid email profile"

auth_url = (
    f"https://accounts.google.com/o/oauth2/v2/auth"
    f"?client_id={client_id}"
    f"&redirect_uri={redirect_uri}"
    f"&response_type=code"
    f"&scope={scope}"
)

print("\nGenerated Google Consent URL:")
print(auth_url)

input("\nPress Enter to open in your browser...")
webbrowser.open(auth_url)

print("\nWaiting for the callback on /callback ...")
import app  # démarre Flask qui écoute sur /callback
