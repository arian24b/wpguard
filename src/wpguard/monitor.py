"""File-integrity monitoring (`baseline`, `watch`) and web-server access-log analysis (`logs`)."""

import glob
import gzip
import hashlib
import json
import os
import re
import urllib.parse
from collections import Counter
from pathlib import Path

from wpguard.report import Rep
from wpguard.signatures import PHP_EXT, build_detectors, judge
from wpguard.util import STATE_DIR

LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
LOG_GLOBS = [
    "/var/log/nginx/access.log*",
    "/var/log/apache2/access.log*",
    "/var/log/httpd/access_log*",
    "/var/log/apache2/*access*.log*",
    "/var/log/nginx/*access*.log*",
]
ATTACK = re.compile(r"\.\./|union\s+select|base64_|eval\(|cmd=|/etc/passwd|<script|wget%20|curl%20", re.IGNORECASE)
SKIP_DIRS = {"cache", "upgrade", "wflogs", "node_modules", ".git"}


def baseline_file(site: Path) -> Path:
    return STATE_DIR / f"baseline-{hashlib.sha1(str(site).encode(), usedforsecurity=False).hexdigest()[:12]}.json"


def snapshot(site: Path) -> dict[str, str]:
    # ponytail: media in uploads is not hashed (php/.htaccess there is); hash it too if disguised shells matter
    up, snap = site / "wp-content/uploads", {}
    for root, dirs, files in os.walk(site):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            p = Path(root, f)
            if p.is_symlink() or f.endswith((".log", ".sql")):
                continue
            if up in p.parents and p.suffix.lower() not in PHP_EXT and f != ".htaccess":
                continue
            try:
                with p.open("rb") as fh:
                    snap[str(p.relative_to(site))] = hashlib.file_digest(fh, "sha256").hexdigest()
            except OSError:
                pass
    return snap


def write_baseline(site: Path) -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    snap = snapshot(site)
    baseline_file(site).write_text(json.dumps(snap))
    return len(snap)


def baseline(site: Path, _a) -> Rep:
    rep = Rep(site)
    n = write_baseline(site)
    rep.log(f"baseline: {n} files -> {baseline_file(site)}")
    return rep


def watch(site: Path, a) -> Rep:
    rep = Rep(site)
    if not baseline_file(site).exists():
        rep.log("no baseline yet: run `baseline` on a clean site")
        return rep
    old, new = json.loads(baseline_file(site).read_text()), snapshot(site)
    extra = build_detectors(a).extra
    for kind, rels in (
        ("new", sorted(new.keys() - old.keys())),
        ("changed", sorted(r for r in new if r in old and new[r] != old[r])),
    ):
        for rel in rels:
            p = site / rel
            verdict = judge(
                p.name, p.suffix.lower(), site / "wp-content/uploads" in p.parents, p.read_bytes()[:5_000_000], extra
            )
            rep.hit(kind, rel, f"SIGNATURE MATCH: {verdict[1]}" if verdict else "file differs from baseline")
    for rel in sorted(old.keys() - new.keys()):
        rep.hit("removed", rel, "file gone since baseline")
    if not rep.hits:
        rep.log(f"{site}: unchanged")
    return rep


def quarantined_urls(sites: list[str]) -> set[str]:
    # ponytail: assumes WP lives in the docroot, so rel path == URL path
    q: set[str] = set()
    for site in sites:
        s = Path(site).resolve()
        for d in (s.parent / "wpguard-quarantine").glob(f"{s.name}-*"):
            files = d / "files"
            q |= {"/" + f.relative_to(files).as_posix() for f in files.rglob("*") if f.is_file()}
    return q


def logs(sites: list[str], a) -> Rep:
    rep = Rep("logs")
    paths = [Path(p) for p in a.log] or [Path(p) for g in LOG_GLOBS for p in sorted(glob.glob(g))]
    q = quarantined_urls(sites)
    c = {k: Counter() for k in ("login", "xmlrpc", "attack", "plugin_post", "uploads_php", "quarantined")}
    for p in paths:
        with (gzip.open if p.suffix == ".gz" else open)(p, "rt", errors="replace") as fh:
            for line in fh:
                if not (m := LOG_RE.match(line)):
                    continue
                ip, meth, url, st, _ua = m.groups()
                path = url.split("?")[0]
                if meth == "POST" and path.endswith("/wp-login.php"):
                    c["login"][ip] += 1
                if path.endswith("/xmlrpc.php") and meth == "POST":
                    c["xmlrpc"][ip] += 1
                if ATTACK.search(urllib.parse.unquote_plus(url)):
                    c["attack"][ip] += 1
                if path in q:
                    c["quarantined"][f"{ip} {meth} {path} -> {st}"] += 1
                if "/wp-content/uploads/" in path and path.lower().endswith(tuple(PHP_EXT)):
                    c["uploads_php"][f"{ip} {meth} {path} -> {st}"] += 1
                if (
                    meth == "POST"
                    and re.search(r"/wp-content/(plugins|themes)/.+\.php$", path)
                    and "admin-ajax" not in path
                ):
                    c["plugin_post"][f"{path} -> {st}"] += 1
    rep.log(f"== logs: {len(paths)} files")
    notes = {
        "login": "POST wp-login.php (brute force) by IP",
        "xmlrpc": "POST xmlrpc.php by IP",
        "attack": "attack strings in URL by IP",
        "plugin_post": "direct POST to plugin/theme PHP (exploit entry point?)",
        "uploads_php": "requests to PHP in uploads (shell use)",
        "quarantined": "requests to files you quarantined (WHO used the shell)",
    }
    for k, title in notes.items():
        rep.log(f"-- {title}")
        for item, n in c[k].most_common(a.top):
            rep.log(f"  {n:6}  {item}")
        if c[k]:
            rep.hits.append({"kind": k, "what": title, "why": f"{sum(c[k].values())} requests"})
    return rep
