"""Compatibility launcher that delegates to the Typer CLI app."""
from cli.main import app

if __name__ == "__main__":
    app()
