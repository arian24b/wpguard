"""wpguard.toml: site profiles, defaults, alert settings and extra feeds.

[defaults]            # any CLI option by its long name with dashes as underscores (since, hashdb, keep, ...)
[notify]              # telegram_token, telegram_chat, email, smtp_host
[sites.NAME]          # path and/or domain, ssh (an ~/.ssh/config host), remote_cmd, plus any option from [defaults]
[feeds.NAME]          # kind = "hash"|"regex"|"yara", urls = [...], entry = [...]
"""

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

SEARCH = (Path("wpguard.toml"), Path.home() / ".config/wpguard/wpguard.toml")
PROFILE_KEYS = {"path", "domain", "ssh", "remote_cmd"}
DEFAULT_REMOTE = "uvx wpguard"
DOMAIN_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}"
)
HOST_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*")  # no leading "-": a host must never look like an ssh option


TEMPLATE = """# wpguard configuration. Create it with `wpguard init` (this folder) or `wpguard setup` (~/.config/wpguard).
# Precedence: command line > [sites.NAME] > [defaults]. Any CLI option works as a key: long name, dashes -> underscores.
# Pins (versions, feed digests) live in wpguard.lock next to this file: `wpguard lock NAME`.

[defaults]
# since = 14                    # flag PHP modified / admins created in the last 14 days
# keep = 7                      # backup retention: newest 7 per destination
# ignore = ["wp-content/cache/*"]

[notify]                        # or env: WPGUARD_TELEGRAM_TOKEN / WPGUARD_TELEGRAM_CHAT / WPGUARD_EMAIL
# telegram_token = "123456:ABC..."
# telegram_chat = "123456789"
# email = "me@example.com"

# `wpguard discover [HOST] --save` fills this in for you. By hand:
#
# [sites.blog]                  # wpguard scan blog   |   wpguard scan blog.example.com
# path = "/var/www/blog"
# domain = "blog.example.com"   # lets you use the hostname instead of the path
# url = "https://blog.example.com"
# to = ["/srv/backups", "s3://my-bucket/blog", "rsync:backup:/srv/backups/blog"]
# encrypt_to = "age1..."        # optional: encrypt backups with age
#
# [sites.mina]                  # wpguard scan mina  ->  ssh mina "uvx wpguard scan /var/www/mina ..."
# ssh = "mina"                  # any host from ~/.ssh/config
# domain = "mina.example.com"   # path is optional when domain is set: found over ssh from the nginx/apache vhosts
# remote_cmd = "~/.local/bin/uvx wpguard"   # default: uvx wpguard
#
# [feeds.my-rules]              # extra signature feed: wpguard sigs update my-rules
# kind = "yara"                 # hash | regex | yara
# urls = ["https://example.com/rules/webshells.yar"]
"""


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
    path: str  # local path, or the path on the remote host ("" = still to be found from `domain`)
    ssh: str | None = None
    domain: str = ""  # hostname of the site; resolved to a path by wpguard.discover when path is empty
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


def _domains(prof: dict) -> set[str]:
    """Hostnames a profile answers to: `domain` (str or list) and the host of `url`."""
    d = prof.get("domain", [])
    names = {d} if isinstance(d, str) else set(d)
    if host := urlparse(str(prof.get("url", ""))).hostname:
        names.add(host)
    return {n.lower() for n in names if n}


def _profile_target(name: str, prof: dict, domain: str = "") -> Target:
    ssh = prof.get("ssh")
    if ssh and not HOST_RE.fullmatch(str(ssh)):
        msg = f"[sites.{name}] ssh host {ssh!r} is not a valid host/alias"
        raise ConfigError(msg)
    if "path" not in prof and "domain" not in prof:
        msg = f"[sites.{name}] needs a path or a domain"
        raise ConfigError(msg)
    raw = str(prof.get("path", ""))
    path = raw if ssh or not raw else str(Path(expand(raw)).resolve())
    first = domain or next(iter(sorted(_domains(prof))), "")
    opts = {k: expand(v) for k, v in prof.items() if k not in PROFILE_KEYS}
    return Target(name, name, path, ssh, remote_cmd=prof.get("remote_cmd", DEFAULT_REMOTE), opts=opts, domain=first)


def resolve(cfg: Config, name: str) -> Target:
    """What the user typed -> Target. In order: profile name, profile hostname, `host:/path`, `host:domain`,
    an existing local path, a bare domain (found from this machine's web-server vhosts), else a local path."""
    if name in cfg.sites:
        return _profile_target(name, dict(cfg.sites[name]))
    for pname, prof in cfg.sites.items():
        if name.lower() in _domains(prof):
            return _profile_target(pname, dict(prof), name.lower())
    host, sep, rest = name.partition(":")
    if sep and "/" not in host and not Path(name).exists():
        if not HOST_RE.fullmatch(host):
            msg = f"{host!r} is not a valid host/alias"
            raise ConfigError(msg)
        if rest.startswith("/"):
            return Target(name, name, rest, host)
        if DOMAIN_RE.fullmatch(rest):
            return Target(name, f"{host}:{rest.lower()}", "", host, domain=rest.lower())
    if "/" not in name and DOMAIN_RE.fullmatch(name) and not Path(name).exists():
        return Target(name, name.lower(), "", None, domain=name.lower())
    p = str(Path(name).resolve())
    return Target(p, p, p)


def write_template(path: Path, *, force: bool = False) -> bool:
    """Write the commented starter config. False if the file exists and force is not set."""
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE)
    return True


def ensure_default() -> Path | None:
    """`wpguard setup`: create ~/.config/wpguard/wpguard.toml unless a config already exists somewhere."""
    if any(p.is_file() for p in SEARCH):
        return None
    target = SEARCH[1]
    return target if write_template(target) else None


def targets(cfg: Config, names: list[str], *, every: bool) -> list[Target]:
    names = list(cfg.sites) if every else names
    return [resolve(cfg, n) for n in names]
