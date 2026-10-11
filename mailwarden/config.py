"""Application configuration (optional TOML file; sensible defaults otherwise)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .errors import InputError


@dataclass(slots=True)
class DnsConfig:
    timeout: float = 4.0
    nameservers: list[str] = field(default_factory=list)  # empty = system resolver
    dkim_selectors: list[str] = field(default_factory=lambda: ["google"])


@dataclass(slots=True)
class ApiConfig:
    lookback_days: int = 30
    page_size: int = 500
    max_retries: int = 4


@dataclass(slots=True)
class AppConfig:
    output_dir: str = "mailwarden-output"
    log_level: str = "INFO"
    relay_baseline_dir: Path | None = None
    dns: DnsConfig = field(default_factory=DnsConfig)
    api: ApiConfig = field(default_factory=ApiConfig)

    @classmethod
    def load(cls, path: Path | None) -> "AppConfig":
        cfg = cls()
        if path is None:
            return cfg
        try:
            data = tomllib.loads(Path(path).read_text())
        except FileNotFoundError as e:
            raise InputError(f"config file not found: {path}") from e
        except tomllib.TOMLDecodeError as e:
            raise InputError(f"config file is not valid TOML: {e}") from e
        _apply(cfg, data)
        return cfg


def _apply(obj: Any, data: dict[str, Any]) -> None:
    names = {f.name for f in fields(obj)}
    for k, v in data.items():
        if k not in names:
            raise InputError(f"unknown config key: {k}")
        cur = getattr(obj, k)
        if hasattr(cur, "__dataclass_fields__") and isinstance(v, dict):
            _apply(cur, v)
        elif k == "relay_baseline_dir":
            setattr(obj, k, Path(v) if v else None)
        else:
            setattr(obj, k, v)
