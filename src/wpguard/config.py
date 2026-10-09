"""wpguard.toml: site profiles, defaults, alert settings and extra feeds.

[defaults]            # any CLI option by its long name with dashes as underscores (since, hashdb, keep, ...)
[notify]              # telegram_token, telegram_chat, email, smtp_host
[sites.NAME]          # path (required), ssh (an ~/.ssh/config host), remote_cmd, plus any option from [defaults]
[feeds.NAME]          # kind = "hash"|"regex"|"yara", urls = [...], entry = [...]
"""

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

SEARCH = (Path("wpguard.toml"), Path.home() / ".config/wpguard/wpguard.toml")
PROFILE_KEYS = {"path", "ssh", "remote_cmd"}
DEFAULT_REMOTE = "uvx wpguard"
HOST_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*")  # no leading "-": a host must never look like an ssh option


class ConfigError(Exception):
    """Invalid wpguard.toml or unknown site (message is shown to the user)."""


@dataclass
class Config:
    path: Path | None = None
    defaults: dict = field(default_factory=dict)
    notify: dict = field(default_factory=dict)
    sites: dict = field(default_factory=dict)
    feeds: dict = field(default_factory=dict)


@dataclass
class Target:
    name: str  # label shown to the user
    key: str  # identity used in wpguard.lock (profile name, or the absolute path)
    path: str  # local path, or the path on the remote host
    ssh: str | None = None
    remote_cmd: str = DEFAULT_REMOTE
    opts: dict = field(default_factory=dict)


def load(explicit: str | None = None) -> Config:
    candidates = [Path(explicit)] if explicit else list(SEARCH)
    for p in candidates:
        if p.is_file():
            try:
                raw = tomllib.loads(p.read_text())
            except tomllib.TOMLDecodeError as e:
                msg = f"{p}: {e}"
                raise ConfigError(msg) from e
            return Config(
                path=p.resolve(),
                defaults=raw.get("defaults", {}),
                notify=raw.get("notify", {}),
                sites=raw.get("sites", {}),
                feeds=raw.get("feeds", {}),
            )
    if explicit:
        msg = f"config file not found: {explicit}"
        raise ConfigError(msg)
    return Config()


def expand(value):
    """~ and $VARS in strings (also inside lists) so config values can point at files."""
    if isinstance(value, str):
        return os.path.expandvars(str(Path(value).expanduser())) if value.startswith(("~", "$")) else value
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value


def resolve(cfg: Config, name: str) -> Target:
    """Profile name -> Target; `host:/path` -> ad-hoc ssh target; anything else is a local path."""
    if name in cfg.sites:
        prof = dict(cfg.sites[name])
        if "path" not in prof:
            msg = f"[sites.{name}] needs a path"
            raise ConfigError(msg)
        ssh = prof.get("ssh")
        if ssh and not HOST_RE.fullmatch(str(ssh)):
            msg = f"[sites.{name}] ssh host {ssh!r} is not a valid host/alias"
            raise ConfigError(msg)
        path = str(prof["path"]) if ssh else str(Path(expand(str(prof["path"]))).resolve())
        opts = {k: expand(v) for k, v in prof.items() if k not in PROFILE_KEYS}
        return Target(name, name, path, ssh, prof.get("remote_cmd", DEFAULT_REMOTE), opts)
    host, sep, rest = name.partition(":")
    if sep and rest.startswith("/") and "/" not in host and not Path(name).exists():
        if not HOST_RE.fullmatch(host):
            msg = f"{host!r} is not a valid host/alias"
            raise ConfigError(msg)
        return Target(name, name, rest, host)
    p = str(Path(name).resolve())
    return Target(p, p, p)


def targets(cfg: Config, names: list[str], *, every: bool) -> list[Target]:
    names = list(cfg.sites) if every else names
    return [resolve(cfg, n) for n in names]
