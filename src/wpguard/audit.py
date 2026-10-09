"""The `audit` command: full inventory + findings, exported as Markdown or JSON (secrets redacted)."""

import os
import re
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path

from wpguard import __version__, wpcli
from wpguard.report import Rep
from wpguard.scan import scan
from wpguard.signatures import PHP_EXT

SETTINGS = (
    "siteurl", "home", "blogname", "admin_email", "default_role", "users_can_register",
    "permalink_structure", "WPLANG", "template", "stylesheet",
)  # fmt: skip
DROPINS = ("advanced-cache.php", "object-cache.php", "db.php", "db-error.php", "maintenance.php", "sunrise.php")


def audit(site: Path, a) -> Rep:
    """Inventory + scan findings as a dict in rep.data (printed by the CLI, not logged)."""
    rep = Rep(site, quiet=True)
    sc = scan(site, a, Rep(site, quiet=True))
    cfg = {}
    if (cp := site / "wp-config.php").exists():
        for k, v in re.findall(r"define\(\s*['\"](\w+)['\"]\s*,\s*([^;]*?)\)\s*;", cp.read_text(errors="replace")):
            cfg[k] = "[redacted]" if re.search(r"PASSWORD|KEY|SALT|DB_USER", k) else v.strip()
    nphp = sum(f.lower().endswith(tuple(PHP_EXT)) for _, _, fs in os.walk(site) for f in fs)
    users = wpcli.jget(site, "user", "list", "--fields=ID,user_login,user_email,roles,user_registered", "--format=json")
    wpc = site / "wp-content"
    try:
        php = subprocess.run(["php", "-r", "echo PHP_VERSION;"], capture_output=True, text=True, check=False).stdout
    except OSError:
        php = "unknown (php not found)"
    rep.data = {
        "site": str(site),
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "tool": f"wpguard {__version__}",
        "wordpress": wpcli.wp(site, "core", "version").stdout.strip(),
        "php": php,
        "settings": {k: wpcli.wp(site, "option", "get", k).stdout.strip() for k in SETTINGS},
        "plugins": wpcli.jget(site, "plugin", "list", "--format=json", "--fields=name,version,status,update"),
        "themes": wpcli.jget(site, "theme", "list", "--format=json", "--fields=name,version,status,update"),
        "users": {"count": len(users), "by_role": dict(Counter(u["roles"] for u in users)), "list": users[:500]},
        "cron_hooks": sorted(
            {e["hook"] for e in wpcli.jget(site, "cron", "event", "list", "--fields=hook", "--format=json")}
        ),
        "mu_plugins": sorted(f.name for f in (wpc / "mu-plugins").glob("*.php")),
        "dropins": [n for n in DROPINS if (wpc / n).exists()],
        "wp_config": cfg,
        "php_files": nphp,
        "findings": sc.hits,
    }
    return rep


def md_table(rows: list[dict], cols: list[str]) -> str:
    if not rows:
        return "_none_\n"

    def cell(v: object) -> str:
        return str(v).replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(cell(r.get(c, "")) for c in cols) + " |" for r in rows]
    return "\n".join(lines) + "\n"


def audit_md(d: dict) -> str:
    def kv(m: dict) -> str:
        return md_table([{"key": k, "value": v} for k, v in m.items()], ["key", "value"])

    u = d["users"]
    return "\n".join(
        [
            f"# WordPress audit: {d['site']}",
            f"_generated {d['generated']} by {d['tool']}_\n",
            (
                f"## Overview\n\n- WordPress: {d['wordpress']}\n- PHP: {d['php']}\n- PHP files: {d['php_files']}\n"
                f"- Findings: {len(d['findings'])}\n"
            ),
            "## Settings\n",
            kv(d["settings"]),
            f"## Findings ({len(d['findings'])})\n",
            md_table(d["findings"], ["kind", "what", "why"]),
            "## Plugins\n",
            md_table(d["plugins"], ["name", "version", "status", "update"]),
            "## Themes\n",
            md_table(d["themes"], ["name", "version", "status", "update"]),
            f"## Users ({u['count']}) by role: {u['by_role']}\n",
            md_table(u["list"], ["ID", "user_login", "user_email", "roles", "user_registered"]),
            f"## Must-use plugins\n\n{', '.join(d['mu_plugins']) or '_none_'}\n",
            f"## Drop-ins\n\n{', '.join(d['dropins']) or '_none_'}\n",
            f"## Cron hooks ({len(d['cron_hooks'])})\n\n{', '.join(d['cron_hooks']) or '_none_'}\n",
            "## wp-config.php constants (secrets redacted)\n",
            kv(d["wp_config"]),
        ]
    )
