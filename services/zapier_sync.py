from __future__ import annotations

import json

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore[assignment]

from providers.base import ProviderAction, ProviderContext

CONFIG_PATH = Path("integrations/zapier.yml")


class ZapierConfigError(RuntimeError):
    """Raised when the Zapier integration configuration is invalid."""


class ZapierNotConfiguredError(RuntimeError):
    """Raised when no Zapier configuration exists for a provider."""


class ZapierCLIUnavailableError(RuntimeError):
    """Raised when the Zapier CLI binary is not available."""


class ZapierCommandError(RuntimeError):
    """Raised when an underlying Zapier CLI command fails."""

    def __init__(self, command: List[str], returncode: int, stdout: str, stderr: str) -> None:
        super().__init__(
            "Zapier command failed with exit code"
            f" {returncode}: {' '.join(command)}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        )
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@dataclass
class ZapierComponent:
    key: str
    type: str
    path: Optional[str] = None
    description: Optional[str] = None

    def expected_path(self, base_dir: Path) -> Optional[Path]:
        if not self.path:
            return None
        return base_dir / self.path


@dataclass
class ZapierProviderConfig:
    provider_id: str
    app_dir: Path
    description: Optional[str] = None
    push: bool = True
    components: List[ZapierComponent] = field(default_factory=list)


_config_cache: Dict[str, ZapierProviderConfig] | None = None


def _load_raw_config() -> Dict:
    if not CONFIG_PATH.exists():
        return {}

    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        content = handle.read()

    if yaml is not None:
        try:
            return yaml.safe_load(content) or {}
        except yaml.YAMLError as exc:  # pragma: no cover - defensive guard
            raise ZapierConfigError(f"Unable to parse {CONFIG_PATH}: {exc}") from exc

    if not content.strip():
        return {}

    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ZapierConfigError(
            f"Unable to parse {CONFIG_PATH} without PyYAML. Install 'pyyaml' to use YAML syntax."
        ) from exc


def _normalize_provider_config(provider_id: str, data: Dict) -> ZapierProviderConfig:
    if "app_dir" not in data:
        raise ZapierConfigError(f"Provider '{provider_id}' is missing required key 'app_dir'.")

    app_dir = Path(data["app_dir"]).expanduser()
    description = data.get("description")
    push = bool(data.get("push", True))
    components: List[ZapierComponent] = []

    for entry in data.get("components", []):
        if "key" not in entry or "type" not in entry:
            raise ZapierConfigError(
                f"Provider '{provider_id}' Zapier component is missing 'key' or 'type'."
            )
        components.append(
            ZapierComponent(
                key=str(entry["key"]),
                type=str(entry["type"]),
                path=entry.get("path"),
                description=entry.get("description"),
            )
        )

    return ZapierProviderConfig(
        provider_id=provider_id,
        app_dir=app_dir,
        description=description,
        push=push,
        components=components,
    )


def load_config() -> Dict[str, ZapierProviderConfig]:
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    raw = _load_raw_config()
    providers: Dict[str, ZapierProviderConfig] = {}
    for provider_id, payload in (raw.get("providers") or {}).items():
        providers[provider_id] = _normalize_provider_config(provider_id, payload or {})

    _config_cache = providers
    return providers


def get_provider_config(provider_id: str) -> Optional[ZapierProviderConfig]:
    config = load_config()
    return config.get(provider_id)


def _ensure_zapier_cli_available() -> None:
    if shutil.which("zapier") is None:
        raise ZapierCLIUnavailableError(
            "Zapier CLI not found. Install it with 'npm install -g zapier-platform-cli' "
            "and run 'zapier login' before syncing."
        )


def _run_zapier_command(args: Iterable[str], *, cwd: Path) -> subprocess.CompletedProcess:
    command = ["zapier", *list(args)]
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ZapierCommandError(command, exc.returncode, exc.stdout or "", exc.stderr or "") from exc
    return completed


def sync_provider(provider_config: ZapierProviderConfig, *, dry_run: bool = False, echo: Callable[[str], None] = print) -> None:
    if not provider_config.app_dir.exists():
        raise ZapierConfigError(
            f"Zapier app directory '{provider_config.app_dir}' for provider '{provider_config.provider_id}' does not exist."
        )

    if dry_run:
        if shutil.which("zapier") is None:
            echo("⚠️ Zapier CLI not found. Running in dry-run mode; no commands will be executed.")
    else:
        _ensure_zapier_cli_available()

    if provider_config.description:
        echo(f"\n🔌 Syncing Zapier app: {provider_config.description}")

    missing_components: List[ZapierComponent] = []
    for component in provider_config.components:
        expected = component.expected_path(provider_config.app_dir)
        if expected is not None and not expected.exists():
            missing_components.append(component)

    if missing_components:
        echo("📦 Missing Zapier components detected. Scaffolding...")
    for component in missing_components:
        echo(f"  • {component.type} {component.key}")
        if dry_run:
            continue
        _run_zapier_command(["scaffold", component.type, component.key], cwd=provider_config.app_dir)

    if provider_config.push:
        echo("\n☁️  Pushing Zapier app")
        if dry_run:
            echo("(dry-run) Skipping 'zapier push'.")
        else:
            _run_zapier_command(["push"], cwd=provider_config.app_dir)
    else:
        echo("Push disabled for this provider; skipping.")

    echo("\n✅ Zapier sync complete.")


def sync_provider_by_id(provider_id: str, *, dry_run: bool = False, echo: Callable[[str], None] = print) -> None:
    provider_config = get_provider_config(provider_id)
    if not provider_config:
        raise ZapierNotConfiguredError(
            f"Provider '{provider_id}' does not have a Zapier integration mapping configured."
        )
    sync_provider(provider_config, dry_run=dry_run, echo=echo)


def build_menu_action(provider_id: str) -> Optional[ProviderAction]:
    provider_config = get_provider_config(provider_id)
    if not provider_config:
        return None

    def handler(ctx: ProviderContext) -> None:
        try:
            sync_provider_by_id(ctx.provider.id, echo=ctx.echo)
        except ZapierCLIUnavailableError as exc:
            ctx.echo(str(exc))
        except ZapierConfigError as exc:
            ctx.echo(f"⚠️ {exc}")
        except ZapierCommandError as exc:
            ctx.echo(str(exc))

    label = "Sync Zapier actions"
    if provider_config.description:
        label = f"Sync Zapier actions ({provider_config.description})"

    return ProviderAction(key="zapier_sync", label=label, handler=handler)
