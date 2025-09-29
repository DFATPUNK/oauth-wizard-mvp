from typer.testing import CliRunner

from cli import main as cli_main


runner = CliRunner()


def test_cli_invokes_wizard_when_no_command(monkeypatch):
    calls = []

    def fake_execute(provider_id, redirect_uri, auto_open_browser):
        calls.append((provider_id, redirect_uri, auto_open_browser))

    monkeypatch.setattr(cli_main, "_execute_wizard", fake_execute)
    result = runner.invoke(cli_main.app, [])

    assert result.exit_code == 0
    assert calls == [(None, cli_main.DEFAULT_REDIRECT_URI, True)]


def test_wizard_command_routes_to_executor(monkeypatch):
    calls = []

    def fake_execute(provider_id, redirect_uri, auto_open_browser):
        calls.append((provider_id, redirect_uri, auto_open_browser))

    monkeypatch.setattr(cli_main, "_execute_wizard", fake_execute)
    result = runner.invoke(
        cli_main.app,
        [
            "wizard",
            "--provider",
            "google",
            "--redirect-uri",
            "http://localhost:9999/callback",
            "--no-open-browser",
        ],
    )

    assert result.exit_code == 0
    assert calls == [("google", "http://localhost:9999/callback", False)]


def test_sync_zapier_command_invokes_sync(monkeypatch):
    provider = type("Provider", (), {"id": "google"})()

    def fake_choose(provider_id):
        assert provider_id == "google"
        return provider

    calls = []

    def fake_sync(provider_id, dry_run, echo):
        calls.append((provider_id, dry_run))

    monkeypatch.setattr(cli_main, "_choose_provider", fake_choose)
    monkeypatch.setattr(cli_main, "sync_provider_by_id", fake_sync)

    result = runner.invoke(
        cli_main.app,
        [
            "sync-zapier",
            "--provider",
            "google",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert calls == [("google", True)]


def test_test_endpoint_command_bootstraps_and_runs(monkeypatch):
    selected_provider = object()

    def fake_choose(provider_id):
        assert provider_id is None
        return selected_provider

    def fake_prompt_credentials(provider, redirect_uri):
        assert provider is selected_provider
        assert redirect_uri == cli_main.DEFAULT_REDIRECT_URI
        return "client", "secret"

    def fake_bootstrap(provider, client_id, client_secret, redirect_uri, auto_open_browser):
        assert (provider, client_id, client_secret, redirect_uri, auto_open_browser) == (
            selected_provider,
            "client",
            "secret",
            cli_main.DEFAULT_REDIRECT_URI,
            False,
        )
        return "token", ["scope1"]

    def fake_build_browser_opener(auto_open_browser):
        assert auto_open_browser is False
        return "browser-opener"

    calls = []

    def fake_run(provider, client_id, client_secret, redirect_uri, access_token, current_scopes, browser_opener):
        calls.append((provider, client_id, client_secret, redirect_uri, access_token, current_scopes, browser_opener))
        return "new-token", ["scope1"]

    monkeypatch.setattr(cli_main, "_choose_provider", fake_choose)
    monkeypatch.setattr(cli_main, "_prompt_credentials", fake_prompt_credentials)
    monkeypatch.setattr(cli_main, "_bootstrap_session", fake_bootstrap)
    monkeypatch.setattr(cli_main, "_build_browser_opener", fake_build_browser_opener)
    monkeypatch.setattr(cli_main, "_run_endpoint_tester", fake_run)

    result = runner.invoke(
        cli_main.app,
        [
            "test-endpoint",
            "--no-open-browser",
        ],
    )

    assert result.exit_code == 0
    assert calls == [
        (
            selected_provider,
            "client",
            "secret",
            cli_main.DEFAULT_REDIRECT_URI,
            "token",
            ["scope1"],
            "browser-opener",
        )
    ]
