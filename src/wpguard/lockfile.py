"""wpguard.lock: pinned core/plugin/theme versions per site (+ signature-feed digests).

`fix` reinstalls the pinned versions instead of "latest", the update advisor updates the pins it approved, and
`lock --check` reports drift. JSON, meant to be committed next to wpguard.toml.
"""

import json
from pathlib import Path

from wpguard import feeds, wpcli
from wpguard.report import Rep

LOCK_NAME = "wpguard.lock"


def path_for(a) -> Path:
    if getattr(a, "lock_file", None):
        return Path(a.lock_file)
    cfg = getattr(a, "config_path", None)
    return (Path(cfg).parent if cfg else Path.cwd()) / LOCK_NAME


def read(p: Path) -> dict:
    try:
        data = json.loads(p.read_text())
    except OSError, ValueError:
        data = {}
    data.setdefault("version", 1)
    data.setdefault("sites", {})
    data.setdefault("feeds", {})
    return data


def write(p: Path, data: dict) -> None:
    p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def site_state(site: Path) -> dict:
    """Live versions: {'core': '6.9', 'plugins': {slug: ver}, 'themes': {slug: ver}}."""
    return {
        "core": wpcli.wp(site, "core", "version").stdout.strip(),
        "plugins": {
            i["name"]: i["version"]
            for i in wpcli.jget(site, "plugin", "list", "--format=json", "--fields=name,version")
        },
        "themes": {
            i["name"]: i["version"] for i in wpcli.jget(site, "theme", "list", "--format=json", "--fields=name,version")
        },
    }


def pinned(a) -> dict | None:
    """The lock entry of the site being processed (a.site_key), or None."""
    return read(path_for(a))["sites"].get(getattr(a, "site_key", ""))


def feed_drift(a) -> list[str]:
    """Feeds whose cached digest differs from the digest pinned in the lock."""
    want, have = read(path_for(a))["feeds"], feeds.digests()
    return [f"feed {n} changed since lock" for n, d in want.items() if n in have and have[n] != d]


def drift(state: dict, locked: dict) -> list[str]:
    out = []
    if state["core"] != locked.get("core"):
        out.append(f"core {locked.get('core')} -> {state['core']}")
    for kind in ("plugins", "themes"):
        have, want = state[kind], locked.get(kind, {})
        out += [
            f"{kind[:-1]} {n}: locked {want[n]}, installed {have[n]}" for n in want if n in have and have[n] != want[n]
        ]
        out += [f"{kind[:-1]} {n}: installed but not in lock" for n in have if n not in want]
        out += [f"{kind[:-1]} {n}: in lock but not installed" for n in want if n not in have]
    return out


def lock_cmd(site: Path, a) -> Rep:
    """`lock` writes/refreshes this site's pins; `lock --check` reports drift (exit 1)."""
    rep = Rep(site)
    p = path_for(a)
    data, state = read(p), site_state(site)
    key = a.site_key
    if a.check:
        if key not in data["sites"]:
            rep.hit("lock", key, f"not in {p.name}; run `wpguard lock` first")
        for line in drift(state, data["sites"].get(key, {})):
            rep.hit("lock", key, line)
        for line in feed_drift(a):
            rep.hit("lock", "feeds", line)
        if not rep.hits:
            rep.log(f"{key}: matches {p.name}")
        return rep
    data["sites"][key] = state
    if feeds.digests():
        data["feeds"] = feeds.digests()
    write(p, data)
    rep.log(
        f"locked {key}: core {state['core']}, {len(state['plugins'])} plugins, {len(state['themes'])} themes -> {p}"
    )
    return rep
