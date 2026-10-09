"""Update / abandonment / vulnerability checks (wordpress.org API, optional WPScan API token)."""

import os
from datetime import datetime

from wpguard import wpcli
from wpguard.util import get_json
from wpguard.wpscan import lookup

ABANDONED_DAYS = 730


def vulns(site, rep, *, token: str | None = None) -> None:
    token = token or os.environ.get("WPSCAN_TOKEN")
    if core := wpcli.jget(site, "core", "check-update", "--format=json"):
        rep.hit("outdated", "wordpress core", f"update to {core[0]['version']} available")
    for kind in ("plugin", "theme"):
        for it in wpcli.jget(site, kind, "list", "--format=json", "--fields=name,version,update"):
            n, v = it["name"], it["version"]
            if it["update"] == "available":
                rep.hit("outdated", f"{kind} {n} {v}", "update available")
            if kind == "plugin":
                st, d = get_json(f"https://api.wordpress.org/plugins/info/1.0/{n}.json")
                if st == 404 or (isinstance(d, dict) and "error" in d):
                    rep.hit("source", f"plugin {n}", "not on wordpress.org (closed/removed/premium/nulled?)")
                elif isinstance(d, dict) and d.get("last_updated"):
                    age = (datetime.now() - datetime.strptime(d["last_updated"][:10], "%Y-%m-%d")).days
                    if age > ABANDONED_DAYS:
                        rep.hit("abandoned", f"plugin {n}", f"not updated for {age // 365}y")
            if token:
                for title, fx in lookup(kind, n, v, token):
                    rep.hit("VULN", f"{kind} {n} {v}", f"{title} (fixed in {fx or 'NO FIX'})")
