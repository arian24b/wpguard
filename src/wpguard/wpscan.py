"""WPScan handler: vulnerability API lookup (free or paid token) and the real WPScan CLI pass-through."""

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

from wpguard.util import vkey


def lookup(kind: str, name: str, version: str, token: str) -> list[tuple[str, str | None]]:
    """WPScan API -> [(title, fixed_in or None)] for vulnerabilities that affect `version`."""
    req = urllib.request.Request(
        f"https://wpscan.com/api/v3/{kind}s/{name}", headers={"Authorization": f"Token token={token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
    except urllib.error.URLError, OSError, ValueError:
        return []
    return [
        (v["title"], v.get("fixed_in"))
        for v in data.get(name, {}).get("vulnerabilities", [])
        if not v.get("fixed_in") or vkey(version) < vkey(v["fixed_in"])
    ]


def wpscan_passthrough(argv: list[str]) -> None:
    argv = list(argv)
    if argv and not argv[0].startswith("-"):  # `wpscan https://site` == `wpscan --url https://site`
        argv = ["--url", *argv]
    tok = os.environ.get("WPSCAN_TOKEN")
    if tok and not any(x.startswith("--api-token") for x in argv):
        argv += ["--api-token", tok]  # visible in `ps`; use ~/.wpscan/scan.json to avoid
    if exe := shutil.which("wpscan"):
        cmd = [exe, *argv]
    elif shutil.which("docker"):
        cmd = ["docker", "run", "--rm", *(["-it"] if sys.stdin.isatty() else []), "wpscanteam/wpscan", *argv]
    else:
        sys.exit(
            "WPScan not found. Install it: `gem install wpscan` (needs ruby) or docker. Free API token: https://wpscan.com/api"
        )
    print("note: WPScan actively probes the target; only scan sites you own or may test.", file=sys.stderr)
    if not tok:
        print("note: no WPSCAN_TOKEN set -> free mode, no vulnerability data.", file=sys.stderr)
    sys.exit(subprocess.run(cmd, check=False).returncode)
