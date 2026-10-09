"""File-level scanning: walk a site and apply signatures, hashes, behavior scoring, YARA and structural checks.

Every finding is `{Path: (kind, why)}`. Kinds: sig, hash, struct, extra (safe to quarantine) and
behavior, yara (review only, unless --aggressive).
"""

import fnmatch
import os
import shutil
import statistics
import subprocess
import time
from pathlib import Path

from wpguard import behavior, wpcli, yarascan
from wpguard.signatures import PHP_EXT, build_detectors, hash_match, judge

OK_HIDDEN = {".htaccess", ".user.ini", ".well-known", ".htpasswd", ".gitignore", ".maintenance"}
SAFE_KINDS = {"sig", "hash", "struct", "extra"}  # fix quarantines these by default
SPECIAL = {".htaccess", ".user.ini", "php.ini", "wp-config.php"}
MAX_READ = 5_000_000
MAX_HASH = 50_000_000
MIN_SIBLINGS = 4


def is_ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in patterns)


def file_scan(site: Path, a, rep) -> dict[Path, tuple[str, str]]:
    det = build_detectors(a)
    hits: dict[Path, tuple[str, str]] = {}
    up = site / "wp-content/uploads"
    now = time.time()
    cutoff = now - a.since * 86400 if a.since else None
    for root, dirs, files in os.walk(site):
        for d in [d for d in dirs if d.startswith(".") and d not in OK_HIDDEN]:
            hits[Path(root, d)] = ("struct", "hidden directory")
        dirs[:] = [d for d in dirs if not (d.startswith(".") and d not in OK_HIDDEN)]
        php_times = []
        for f in files:
            if Path(f).suffix.lower() in PHP_EXT:
                try:
                    php_times.append(Path(root, f).stat().st_mtime)
                except OSError:
                    continue
        median = statistics.median(php_times) if len(php_times) >= MIN_SIBLINGS else None
        for f in files:
            p = Path(root, f)
            try:
                if p.is_symlink():
                    continue
                size, mtime = (st := p.stat()).st_size, st.st_mtime
                ext, in_up = p.suffix.lower(), up in p.parents
                if f.startswith(".") and f not in OK_HIDDEN:
                    hits[p] = ("struct", "hidden file")
                    continue
                if (det.bad or det.good) and size < MAX_HASH:  # ponytail: hashes every file; narrow by ext if IO-bound
                    if det.bad and (alg := hash_match(p, det.bad)):
                        hits[p] = ("hash", f"known-bad {alg} hash")
                        continue
                    if det.good and hash_match(p, det.good):
                        continue
                if size > MAX_READ or not (f in SPECIAL or ext in PHP_EXT or in_up):  # ponytail: skips huge files
                    continue
                data = p.read_bytes()
                if verdict := judge(f, ext, in_up, data, det.extra):
                    hits[p] = verdict
                elif det.behavior and ext in PHP_EXT:
                    rel = p.relative_to(site).as_posix()
                    pts, why = behavior.score(data, rel, mtime, median, now)
                    if pts >= det.behavior:
                        hits[p] = ("behavior", f"score {pts}: " + "; ".join(why))
                if p not in hits and cutoff and ext in PHP_EXT and mtime > cutoff:
                    rep.hit("recent", p.relative_to(site), f"php modified within {a.since}d")
            except OSError:
                continue
    mu = site / "wp-content/mu-plugins"
    for p in mu.glob("*.php") if mu.is_dir() else []:
        hits.setdefault(p, ("struct", "mu-plugin (verify it is yours)"))
    return hits


def yara_scan(site: Path, a, rep) -> dict[Path, tuple[str, str]]:
    det = build_detectors(a)
    hits: dict[Path, tuple[str, str]] = {}
    if det.yara_rules and yarascan.tool() is None:
        rep.log("  [yara] rules configured but no `yara`/`yr` binary found, skipping")
        return hits
    for rules in det.yara_rules:
        found, err = yarascan.scan(rules, site)
        if err:
            rep.log(f"  [yara] {rules.name}: {err}")
        for path, names in found.items():
            hits.setdefault(Path(path), ("yara", f"{rules.name}: {', '.join(names[:3])}"))
    return hits


def checksum_extras(site: Path) -> dict[Path, tuple[str, str]]:
    """Files wp.org checksums say should not exist (core + plugins)."""
    import re

    extras = {}
    r = wpcli.wp(site, "core", "verify-checksums")
    for m in re.finditer(r"File should not exist: (.+)", r.stdout + r.stderr):
        extras[site / m.group(1).strip()] = ("extra", "not part of WP core")
    for e in wpcli.jget(site, "plugin", "verify-checksums", "--all", "--format=json"):
        if "added" in e["message"]:
            extras[site / "wp-content/plugins" / e["plugin_name"] / e["file"]] = ("extra", "not part of plugin")
    return {p: v for p, v in extras.items() if p.is_file()}


def find_files(site: Path, a, rep) -> dict[Path, tuple[str, str]]:
    """All file findings. A path flagged more than once keeps its most actionable verdict."""
    merged: dict[Path, tuple[str, str]] = {}
    for found in (checksum_extras(site), file_scan(site, a, rep), yara_scan(site, a, rep)):
        for p, v in found.items():
            if p not in merged or (merged[p][0] not in SAFE_KINDS and v[0] in SAFE_KINDS):
                merged[p] = v
    ign = list(a.ignore or [])
    return {p: v for p, v in merged.items() if not is_ignored(p.relative_to(site).as_posix(), ign)}


def clamav(site: Path, rep) -> None:
    if shutil.which("clamscan"):
        r = subprocess.run(
            ["clamscan", "-r", "-i", "--no-summary", str(site)], capture_output=True, text=True, check=False
        )
        for line in r.stdout.splitlines():
            rep.hit("clamav", *line.rsplit(": ", 1))
