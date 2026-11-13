"""Strata configuration loader.

Reads from (highest priority first):
  1. Environment variables: STRATA_<KEY>
  2. ~/.config/strata/config.toml
  3. .strata.toml in the current working directory

API keys are always optional — engines degrade gracefully when absent.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ApiKeys:
    virustotal: str | None = None      # STRATA_VIRUSTOTAL_KEY
    securitytrails: str | None = None  # STRATA_SECURITYTRAILS_KEY
    shodan: str | None = None          # STRATA_SHODAN_KEY
    censys_id: str | None = None       # STRATA_CENSYS_ID
    censys_secret: str | None = None   # STRATA_CENSYS_SECRET


@dataclass
class PassiveDnsConfig:
    """Controls which passive DNS sources are queried."""
    crtsh: bool = True          # free, no key
    hackertarget: bool = True   # free tier, no key
    rapiddns: bool = True       # free, no key
    alienvault: bool = True     # free tier, no key
    virustotal: bool = True     # requires api.virustotal key
    securitytrails: bool = True # requires securitytrails key


@dataclass
class TransportConfig:
    user_agents: list[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "strata/0.2 (+https://github.com/vulnquest58/strata)",
    ])
    per_host_delay: float = 0.3   # seconds between requests to the same host
    proxy: str | None = None      # http://user:pass@host:port or socks5://...
    timeout: float = 10.0
    max_retries: int = 2


@dataclass
class StrataConfig:
    keys: ApiKeys = field(default_factory=ApiKeys)
    passive_dns: PassiveDnsConfig = field(default_factory=PassiveDnsConfig)
    transport: TransportConfig = field(default_factory=TransportConfig)

    # ------------------------------------------------------------------ #
    # Loaders                                                              #
    # ------------------------------------------------------------------ #

    @classmethod
    def load(cls) -> StrataConfig:
        """Load config from files, then overlay environment variables."""
        cfg = cls()
        for path in _config_paths():
            if path.exists():
                _apply_toml(cfg, path)
                break
        _apply_env(cfg)
        return cfg


# ------------------------------------------------------------------ #
# Private helpers                                                      #
# ------------------------------------------------------------------ #

def _config_paths() -> list[Path]:
    return [
        Path.cwd() / ".strata.toml",
        Path.home() / ".config" / "strata" / "config.toml",
    ]


def _apply_toml(cfg: StrataConfig, path: Path) -> None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return
    keys = data.get("keys", {})
    if isinstance(keys, dict):
        for attr in ("virustotal", "securitytrails", "shodan", "censys_id", "censys_secret"):
            if attr in keys:
                setattr(cfg.keys, attr, str(keys[attr]))
    transport = data.get("transport", {})
    if isinstance(transport, dict):
        for attr in ("per_host_delay", "proxy", "timeout", "max_retries"):
            if attr in transport:
                setattr(cfg.transport, attr, transport[attr])
        if "user_agents" in transport and isinstance(transport["user_agents"], list):
            cfg.transport.user_agents = [str(u) for u in transport["user_agents"]]
    passive = data.get("passive_dns", {})
    if isinstance(passive, dict):
        for attr in ("crtsh", "hackertarget", "rapiddns", "alienvault",
                     "virustotal", "securitytrails"):
            if attr in passive:
                setattr(cfg.passive_dns, attr, bool(passive[attr]))


def _apply_env(cfg: StrataConfig) -> None:
    def _env_str(k: str) -> str | None:
        return os.environ.get(f"STRATA_{k}")
    for attr, env_suffix in [
        ("virustotal", "VIRUSTOTAL_KEY"),
        ("securitytrails", "SECURITYTRAILS_KEY"),
        ("shodan", "SHODAN_KEY"),
        ("censys_id", "CENSYS_ID"),
        ("censys_secret", "CENSYS_SECRET"),
    ]:
        v = _env_str(env_suffix)
        if v:
            setattr(cfg.keys, attr, v)
    proxy = _env_str("PROXY")
    if proxy:
        cfg.transport.proxy = proxy


# Singleton — loaded once per process
_instance: StrataConfig | None = None


def get_config() -> StrataConfig:
    global _instance
    if _instance is None:
        _instance = StrataConfig.load()
    return _instance


__all__ = [
    "ApiKeys",
    "PassiveDnsConfig",
    "StrataConfig",
    "TransportConfig",
    "get_config",
]

