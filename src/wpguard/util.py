"""Small shared helpers: HTTP, versions, paths, timestamps."""

import json
import os
import re
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

STATE_DIR = Path(os.environ.get("WPGUARD_HOME") or Path.home() / ".local/share/wpguard")
UA = "wpguard (+https://github.com/arian24b/wpguard)"
MAX_DOWNLOAD = 200_000_000


_stamp_lock = threading.Lock()
_last_stamp = datetime.min


def stamp() -> str:
    """YYYYmmdd-HHMMSS, strictly increasing within a process so two backups in one second never collide."""
    global _last_stamp  # noqa: PLW0603
    with _stamp_lock:
        now = datetime.now().astimezone().replace(tzinfo=None, microsecond=0)
        _last_stamp = max(now, _last_stamp + timedelta(seconds=1))
        return _last_stamp.strftime("%Y%m%d-%H%M%S")


def vkey(v: str | None) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def fetch(url: str, headers: dict | None = None, timeout: int = 60) -> bytes | None:
    """GET `url` (https only). None on any HTTP/network failure or if larger than MAX_DOWNLOAD."""
    if not url.startswith("https://"):
        return None
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(MAX_DOWNLOAD + 1)
    except OSError, ValueError:
        return None
    return None if len(data) > MAX_DOWNLOAD else data


def get_json(url: str, headers: dict | None = None) -> tuple[int, object]:
    """(status, parsed JSON). Status 0 = network error, 404 = not found."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, None
    except OSError, ValueError:
        return 0, None
