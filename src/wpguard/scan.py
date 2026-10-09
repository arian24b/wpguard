"""The `scan` command: files, configs, DB, persistence, updates/vulnerabilities. Read-only."""

from pathlib import Path

from wpguard import lockfile, wpcli
from wpguard.dbscan import db_clean, db_scan, persistence
from wpguard.report import Rep
from wpguard.scanner import clamav, find_files
from wpguard.vulns import vulns


def scan(site: Path, a, rep: Rep | None = None) -> Rep:
    rep = rep or Rep(site)
    rep.log(f"== scan {site}")
    for line in lockfile.feed_drift(a):
        rep.log(f"  [warn] {line}")
    rep.files = find_files(site, a, rep)
    for p, (kind, why) in sorted(rep.files.items()):
        rep.hit(kind, p.relative_to(site), why)
    clamav(site, rep)
    r = wpcli.wp(site, "core", "verify-checksums")
    rep.log("  [core]", ((r.stdout + r.stderr).strip().splitlines() or ["?"])[-1])
    db_scan(site, rep)
    if a.clean_db:
        db_clean(site, rep, dry=True)
    persistence(site, rep, a)
    if not a.no_net:
        vulns(site, rep)
    return rep
