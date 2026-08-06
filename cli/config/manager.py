"""
DevSecure360 CLI — Config Manager
====================================
Reads and writes .devsecure.toml in the workspace root.
"""

from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Any, Optional

# tomllib is built-in for Python 3.11+; tomli as fallback
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            tomllib = None  # type: ignore

try:
    import tomli_w
except ImportError:
    tomli_w = None


CONFIG_FILENAME = ".devsecure.toml"

DEFAULT_CONFIG = {
    "workspace": {
        "name":    "DevSecure360",
        "root":    ".",
        "version": "1.0.0",
    },
    "scan": {
        "exclude_dirs": ["node_modules", "venv", ".venv", "__pycache__", ".git",
                         "dist", "build", ".next", "coverage"],
        "max_file_size_mb": 2,
        "parallel_workers": 8,
    },
    "ai": {
        "provider": "ollama",
        "model":    "deepseek-coder:6.7b",
        "base_url": "http://127.0.0.1:11434",
        "timeout":  300,
    },
    "report": {
        "output_dir": "cli/reports",
        "default_format": "json",
    },
}


class ConfigManager:
    """
    Manages the .devsecure.toml configuration file.
    Falls back to DEFAULT_CONFIG if the file does not exist.
    """

    def __init__(self, workspace: str = None):
        self.workspace = workspace or os.getcwd()
        self.config_path = Path(self.workspace) / CONFIG_FILENAME
        self._config: Optional[dict] = None

    def load(self) -> dict:
        """Load config from .devsecure.toml, returning defaults if absent."""
        if self._config is not None:
            return self._config

        if self.config_path.exists() and tomllib is not None:
            try:
                with open(self.config_path, "rb") as f:
                    user_cfg = tomllib.load(f)
                # Deep-merge user config over defaults
                self._config = _deep_merge(DEFAULT_CONFIG.copy(), user_cfg)
            except Exception:
                self._config = DEFAULT_CONFIG.copy()
        else:
            self._config = DEFAULT_CONFIG.copy()

        return self._config

    def save(self, config: dict = None) -> bool:
        """Write config to .devsecure.toml. Returns True on success."""
        if tomli_w is None:
            return False
        cfg = config or self._config or DEFAULT_CONFIG.copy()
        try:
            with open(self.config_path, "wb") as f:
                tomli_w.dump(cfg, f)
            self._config = cfg
            return True
        except Exception:
            return False

    def init_workspace(self, name: str = None) -> bool:
        """Create a new .devsecure.toml in the workspace."""
        cfg = DEFAULT_CONFIG.copy()
        if name:
            cfg["workspace"]["name"] = name
        return self.save(cfg)

    def get(self, *keys, default=None) -> Any:
        """Get a nested config value: get('scan', 'exclude_dirs')"""
        cfg = self.load()
        for key in keys:
            if not isinstance(cfg, dict):
                return default
            cfg = cfg.get(key, default)
            if cfg is None:
                return default
        return cfg

    def set(self, *keys_and_value) -> bool:
        """Set a nested config value: set('scan', 'parallel_workers', 4)"""
        *keys, value = keys_and_value
        cfg = self.load()
        target = cfg
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = value
        return self.save(cfg)

    @property
    def exists(self) -> bool:
        return self.config_path.exists()

    @property
    def project_name(self) -> str:
        return self.get("workspace", "name", default="DevSecure360")

    @property
    def scan_excludes(self) -> list:
        return self.get("scan", "exclude_dirs", default=DEFAULT_CONFIG["scan"]["exclude_dirs"])

    @property
    def ai_model(self) -> str:
        return self.get("ai", "model", default="deepseek-coder:6.7b")

    @property
    def report_output_dir(self) -> str:
        return self.get("report", "output_dir", default="cli/reports")


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (override wins on conflicts)."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ── Module-level singleton ────────────────────────────────────────────────────
_cfg = ConfigManager()

def get_config(workspace: str = None) -> ConfigManager:
    """Returns the config manager for the given workspace (or cwd)."""
    if workspace:
        return ConfigManager(workspace)
    return _cfg
