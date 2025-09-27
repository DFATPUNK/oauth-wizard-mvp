# OAuth Wizard MVP - Google OAuth2

🚀 Minimal MVP to validate OAuth2 Authorization Code Flow with Google.

## Usage

```bash
pip install -r requirements.txt
python run.py  # launches the interactive wizard
```

The CLI is powered by [Typer](https://typer.tiangolo.com/). Use `--help` to explore options:

```bash
python run.py --help
python run.py wizard --help
```

You can also invoke the module directly:

```bash
python -m cli.main --provider google
```

Pass `--no-open-browser` if you prefer to open consent URLs manually.

### Test authenticated API endpoints

After completing the OAuth flow you can explore provider APIs without leaving the terminal:

```bash
python run.py test-endpoint --provider google
```

The tester lists documented endpoints from the provider discovery catalog, injects your current access token, and shows status codes, headers, and JSON bodies. When discovery data is unavailable, you can enter custom methods and URLs.
