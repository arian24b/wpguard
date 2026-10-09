"""Signature feeds: download, cache, pin (digests land in wpguard.lock) and expose to the scanner.

Catalog entries are third-party data; you choose to download them with `wpguard sigs update`.
Licenses: php-malware-finder is LGPL-3.0, Neo23x0/signature-base is the Detection Rule License 1.1 (attribution),
rfxn/Linux Malware Detect hashes come from https://www.rfxn.com/projects/linux-malware-detect/.
"""

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from wpguard.util import STATE_DIR, fetch

FEED_DIR = STATE_DIR / "feeds"
INDEX = FEED_DIR / "index.json"
PMF = "https://raw.githubusercontent.com/nbs-system/php-malware-finder/master/php-malware-finder/"
SIGBASE = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/"


@dataclass(frozen=True)
class Feed:
    kind: str  # hash | regex | yara
    urls: tuple[str, ...]
    entry: tuple[str, ...] = ()  # yara: files to run (others are only #included); empty = all
    note: str = ""


CATALOG = {
    "maldet-hashes": Feed("hash", ("https://cdn.rfxn.com/downloads/rfxn.hdb",), note="Linux Malware Detect md5 hashes"),
    "php-malware-finder": Feed(
        "yara", (PMF + "php.yar", PMF + "whitelist.yar"), entry=("php.yar",), note="NBS System PHP webshell rules"
    ),
    "signature-base-webshells": Feed(
        "yara",
        (SIGBASE + "thor-webshells.yar", SIGBASE + "gen_webshells.yar"),
        note="Neo23x0 signature-base webshell rules",
    ),
}


def catalog(extra: dict | None = None) -> dict[str, Feed]:
    """Built-in feeds plus `[feeds.NAME]` tables from wpguard.toml (kind, urls, entry)."""
    out = dict(CATALOG)
    for name, spec in (extra or {}).items():
        out[name] = Feed(spec["kind"], tuple(spec["urls"]), tuple(spec.get("entry", ())), spec.get("note", ""))
    return out


def index() -> dict:
    try:
        return json.loads(INDEX.read_text())
    except OSError, ValueError:
        return {}


def update(names: list[str], extra: dict | None, log) -> int:
    """Download feeds. Returns the number of failures."""
    cat, idx, failed = catalog(extra), index(), 0
    for name in names or list(cat):
        feed = cat.get(name)
        if feed is None:
            log(f"unknown feed {name!r} (see `wpguard sigs list`)")
            failed += 1
            continue
        d = FEED_DIR / name
        d.mkdir(parents=True, exist_ok=True)
        files = {}
        for url in feed.urls:
            fname = url.split("?")[0].rsplit("/", 1)[-1]
            if fname in {"", ".", ".."}:
                log(f"  FAILED {name}: cannot derive a file name from {url}")
                failed += 1
                break
            data = fetch(url)
            if data is None:
                log(f"  FAILED {name}: {url}")
                failed += 1
                break
            fd, tmp = tempfile.mkstemp(dir=d)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            Path(tmp).replace(d / fname)
            files[fname] = hashlib.sha256(data).hexdigest()
        else:
            digest = hashlib.sha256("".join(sorted(files.values())).encode()).hexdigest()
            idx[name] = {
                "kind": feed.kind,
                "entry": list(feed.entry),
                "files": files,
                "digest": digest,
                "updated": datetime.now().astimezone().isoformat(timespec="seconds"),
            }
            log(f"  ok {name}: {len(files)} file(s), digest {digest[:12]}")
    FEED_DIR.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(json.dumps(idx, indent=1))
    return failed


def files(kind: str) -> list[Path]:
    """Cached feed files of one kind (all files, including yara includes)."""
    return [FEED_DIR / n / f for n, meta in index().items() if meta["kind"] == kind for f in meta["files"]]


def yara_entries() -> list[Path]:
    """The yara rule files to actually run (an `entry` list limits it; includes are resolved by yara itself)."""
    out = []
    for name, meta in index().items():
        if meta["kind"] == "yara":
            out += [FEED_DIR / name / f for f in (meta["entry"] or meta["files"])]
    return out


def digests() -> dict[str, str]:
    return {n: meta["digest"] for n, meta in index().items()}


def sigs_cmd(args: list[str], extra: dict | None) -> int:
    """wpguard sigs list | update [NAMES...]"""
    verb, names = (args[0] if args else "list"), args[1:]
    if verb == "update":
        return 1 if update(names, extra, print) else 0
    if verb != "list":
        print("usage: wpguard sigs list | update [NAMES...]")
        return 2
    have = index()
    for name, feed in catalog(extra).items():
        state = (
            f"cached {have[name]['updated']} digest {have[name]['digest'][:12]}" if name in have else "not downloaded"
        )
        print(f"{name:26} {feed.kind:6} {state}\n    {feed.note}")
    return 0
