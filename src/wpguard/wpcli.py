"""wp-cli handler: download it, run it (captured, or interactive pass-through)."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from wpguard.util import STATE_DIR

WP = STATE_DIR / "wp-cli.phar"
URL = "https://github.com/wp-cli/wp-cli/releases/latest/download/wp-cli.phar"


def setup() -> None:
    WP.parent.mkdir(parents=True, exist_ok=True)
    data = urllib.request.urlopen(URL).read()
    want = urllib.request.urlopen(URL + ".sha512").read().split()[0].decode()
    if hashlib.sha512(data).hexdigest() != want:
        sys.exit("wp-cli checksum mismatch, refusing to install")
    WP.write_bytes(data)
    print("wp-cli ->", WP)


def wp(site: Path | str, *a: str, load: bool = False, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run wp-cli. Plugins/themes are NOT loaded unless `load=True` (never execute possibly infected code)."""
    cmd = [
        "php",
        str(WP),
        f"--path={site}",
        *([] if load else ["--skip-plugins", "--skip-themes"]),
        *(["--allow-root"] if os.geteuid() == 0 else []),
        *a,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=cwd)


def jget(site: Path | str, *a: str) -> list | dict:
    try:
        return json.loads(wp(site, *a).stdout)
    except json.JSONDecodeError:
        return []


def need_wp() -> None:
    if not WP.exists() or not shutil.which("php"):
        sys.exit("run `wpguard setup` first and install php")


def wp_passthrough(argv: list[str]) -> None:
    unsafe = "--unsafe" in argv
    argv = [x for x in argv if x != "--unsafe"]
    if not argv:
        sys.exit("usage: wpguard wp [--unsafe] SITE <any wp-cli args>   e.g. wpguard wp /var/www/x plugin list")
    need_wp()
    site, *rest = argv
    cmd = [
        "php",
        str(WP),
        f"--path={Path(site).resolve()}",
        *([] if unsafe else ["--skip-plugins", "--skip-themes"]),
        *(["--allow-root"] if os.geteuid() == 0 else []),
        *rest,
    ]
    sys.exit(subprocess.run(cmd, check=False).returncode)
