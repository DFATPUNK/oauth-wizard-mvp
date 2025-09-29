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

## Testing

Run the unit test suite with [pytest](https://docs.pytest.org/) to validate OAuth helpers, scope analysis, and CLI routing logic. Keeping these tests green helps ensure we don’t regress the interactive workflows.

```bash
pytest
```

### Test authenticated API endpoints

After completing the OAuth flow you can explore provider APIs without leaving the terminal:

```bash
python run.py test-endpoint --provider google
```

The tester lists documented endpoints from the provider discovery catalog, injects your current access token, and shows status codes, headers, and JSON bodies. When discovery data is unavailable, you can enter custom methods and URLs.

### Sync Zapier integrations

Provider-specific Zapier metadata lives in `integrations/zapier.yml` (JSON/YAML). Each entry describes where the Zapier app source lives (`app_dir`) and which actions or triggers should exist for that provider. The included Google example maps to files under `integrations/zapier/apps/google`.

To scaffold missing triggers/actions and push the Zapier app, install the Zapier CLI and authenticate once:

```bash
npm install -g zapier-platform-cli
zapier login
```

Then run the sync command:

```bash
python run.py sync-zapier --provider google
```

Pass `--dry-run` to preview work without executing the Zapier CLI. The wizard’s interactive menu also exposes the same “Sync Zapier actions” workflow when a provider has Zapier metadata configured.
