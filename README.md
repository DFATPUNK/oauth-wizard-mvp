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
