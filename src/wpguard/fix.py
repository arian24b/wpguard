"""fix (with --dry-run, confirmation and a quarantine manifest), undo, harden, reinstall."""

import fnmatch
import json
import os
import shutil
import sys
from pathlib import Path

from wpguard import lockfile, wpcli
from wpguard.backup import make_backup
from wpguard.dbscan import db_clean
from wpguard.monitor import write_baseline
from wpguard.report import Rep
from wpguard.scan import scan
from wpguard.scanner import SAFE_KINDS, find_files
from wpguard.util import stamp

# wp-config.php constants applied by `harden`. LOCKDOWN ones block plugin/theme installs + updates (opt-in).
HARDEN = {
    "FORCE_SSL_ADMIN": "true",
    "WP_AUTO_UPDATE_CORE": "false",
    "WP_DEBUG": "false",
    "WP_DEBUG_DISPLAY": "false",
    "FS_CHMOD_FILE": "0644",
    "FS_CHMOD_DIR": "0755",
    "DISALLOW_FILE_EDIT": "true",
}
LOCKDOWN = {"DISALLOW_FILE_MODS": "true", "AUTOMATIC_UPDATER_DISABLED": "true"}
KEEP = {"wp-config.php", ".htaccess"}  # report only, never auto-quarantine (outside uploads)
UPLOADS_HT = """# wpguard: never execute scripts from uploads
<IfModule mod_authz_core.c>
  <FilesMatch "\\.(php\\d?|phtml|phar|inc)$">
    Require all denied
  </FilesMatch>
</IfModule>
<IfModule !mod_authz_core.c>
  <FilesMatch "\\.(php\\d?|phtml|phar|inc)$">
    Order allow,deny
    Deny from all
  </FilesMatch>
</IfModule>
"""
NGINX = r"location ~* ^/wp-content/uploads/.*\.(php\d?|phtml|phar)$ { deny all; }"
MANIFEST = "manifest.json"


# ---------- quarantine / undo ----------
def split_findings(site: Path, hits: dict, *, aggressive: bool) -> tuple[dict, dict]:
    """(to quarantine, review only). Heuristic kinds and KEEP files are review-only unless --aggressive."""
    up = site / "wp-content/uploads"
    move, review = {}, {}
    for p, (kind, why) in hits.items():
        keep_manual = p.name in KEEP and up not in p.parents
        (move if (kind in SAFE_KINDS or aggressive) and not keep_manual else review)[p] = (kind, why)
    return move, review


def quarantine(site: Path, move: dict, qroot: Path, rep: Rep) -> int:
    """Move files into qroot/files/<rel> and record them in qroot/manifest.json so `undo` can put them back."""
    mf = qroot / MANIFEST
    manifest = json.loads(mf.read_text()) if mf.exists() else {"site": str(site), "items": []}
    n = 0
    for p, (kind, why) in move.items():
        if not p.exists():
            continue
        rel = p.relative_to(site).as_posix()
        dst = qroot / "files" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(p, dst)
        manifest["items"].append({"path": rel, "kind": kind, "why": why})
        rep.log(f"  quarantined {rel}")
        n += 1
    if n:
        mf.write_text(json.dumps(manifest, indent=1))
    return n


def undo(site: Path, a) -> Rep:
    """Move quarantined files back (latest quarantine, or --from DIR; --only GLOB limits it)."""
    rep = Rep(site)
    dirs = sorted((site.parent / "wpguard-quarantine").glob(f"{site.name}-*"))
    qroot = Path(a.src) if a.src else (dirs[-1] if dirs else None)
    if not qroot or not (qroot / MANIFEST).exists():
        rep.log("no quarantine with a manifest found (use --from DIR)")
        rep.exit = 1
        return rep
    manifest = json.loads((qroot / MANIFEST).read_text())
    restored = 0
    for item in manifest["items"]:
        rel = item["path"]
        if a.only and not any(fnmatch.fnmatch(rel, g) for g in a.only):
            continue
        src, dst = qroot / "files" / rel, site / rel
        if not dst.resolve().is_relative_to(site.resolve()) or not src.resolve().is_relative_to(qroot.resolve()):
            rep.log(f"  refusing path outside the site: {rel}")
        elif not src.exists():
            rep.log(f"  skip {rel}: not in quarantine (already restored?)")
        elif dst.exists():
            rep.log(f"  skip {rel}: a file already exists there")
        elif a.dry_run:
            rep.log(f"  [dry-run] would restore {rel}")
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(src, dst)
            rep.log(f"  restored {rel}")
            restored += 1
    rep.log(f"{restored} file(s) restored from {qroot}")
    return rep


# ---------- reinstall / harden ----------
def reinstall(site: Path, rep: Rep, pins: dict | None, *, dry: bool) -> None:
    """Reinstall core, plugins, themes from wordpress.org: pinned versions from wpguard.lock, otherwise latest."""
    pins = pins or {}
    core_v = pins.get("core")
    rep.log(f"== reinstall core ({core_v or 'latest'})")
    if not dry:
        args = ("core", "download", "--force", "--skip-content", *([f"--version={core_v}"] if core_v else []))
        for cmd in (args, ("core", "update-db")):
            r = wpcli.wp(site, *cmd)
            rep.log("  ", ((r.stdout + r.stderr).strip().splitlines() or ["done"])[-1])
    for kind in ("plugin", "theme"):
        rep.log(f"== reinstall {kind}s")
        for it in wpcli.jget(site, kind, "list", "--format=json", "--fields=name"):
            want = pins.get(f"{kind}s", {}).get(it["name"])
            label = f"{it['name']} {want or 'latest'}"
            if dry:
                rep.log(f"  [dry-run] would install {label}")
                continue
            r = wpcli.wp(site, kind, "install", it["name"], "--force", *([f"--version={want}"] if want else []))
            note = "" if r.returncode == 0 else "  (not on wp.org or version gone: reinstall from vendor)"
            rep.log(f"  {'ok  ' if r.returncode == 0 else 'SKIP'} {label}{note}")


def harden(site: Path, a, rep: Rep | None = None) -> Rep:
    rep = rep or Rep(site)
    rep.log("== harden")
    consts = {**HARDEN, **(LOCKDOWN if a.lockdown else {})}
    if a.url:  # pins URLs: defeats a siteurl hijacked in the DB
        consts |= {"WP_HOME": f"'{a.url}'", "WP_SITEURL": f"'{a.url}'"}
    if a.dry_run:
        rep.log("  [dry-run] would block PHP in uploads, set:", ", ".join(f"{k}={v}" for k, v in consts.items()))
        return rep
    up = site / "wp-content/uploads"
    if up.is_dir():
        (up / ".htaccess").write_text(UPLOADS_HT)
        rep.log("  uploads/.htaccess blocks PHP. nginx users add:", NGINX)
    for k, v in consts.items():
        r = wpcli.wp(site, "config", "set", k, v.strip(), "--raw")
        rep.log(f"  {k}={v.strip()}:", ((r.stdout + r.stderr).strip().splitlines() or ["set"])[-1])
    for root, dirs, files in os.walk(site):
        for n, mode in [(d, 0o755) for d in dirs] + [(f, 0o644) for f in files]:
            p = Path(root, n)
            try:
                if not p.is_symlink() and p.stat().st_mode & 0o777 != mode and n != "wp-config.php":
                    p.chmod(mode)
            except OSError:
                pass
    rep.log("  perms: dirs 755, files 644")
    if a.prune:
        for kind in ("plugin", "theme"):
            for it in wpcli.jget(site, kind, "list", "--status=inactive", "--format=json", "--fields=name"):
                wpcli.wp(site, kind, "delete", it["name"])
                rep.log(f"  pruned inactive {kind} {it['name']}")
    return rep


# ---------- fix ----------
def confirm(a, rep: Rep) -> bool:
    if a.yes:
        return True
    if sys.stdin.isatty():
        return input("Proceed with the plan above? [y/N] ").strip().lower().startswith("y")
    rep.log("refusing to change anything non-interactively: review the plan, then rerun with --yes")
    return False


def fix(site: Path, a) -> Rep:
    rep = Rep(site)
    qroot = site.parent / "wpguard-quarantine" / f"{site.name}-{stamp()}"
    pins = lockfile.pinned(a)
    scan(site, a, rep)
    move, review = split_findings(site, rep.files, aggressive=a.aggressive)

    rep.log("\n== PLAN")
    rep.log(f"  quarantine {len(move)} file(s) -> {qroot}/files (undo with `wpguard undo`)")
    for p, (kind, why) in sorted(move.items()):
        rep.log(f"    - [{kind}] {p.relative_to(site)}: {why}")
    for p, (kind, why) in sorted(review.items()):
        rep.log(f"    ? REVIEW (not touched) [{kind}] {p.relative_to(site)}: {why}")
    for uid in a.delete_user or []:
        rep.log(f"  delete user {uid}")
    rep.log(f"  reinstall core/plugins/themes ({'pinned versions from wpguard.lock' if pins else 'latest versions'})")
    rep.log(f"  DB cleanup: {'APPLY' if a.clean_db else 'dry run only'}; then harden + new salts + fresh baseline")
    if a.dry_run:
        reinstall(site, rep, pins, dry=True)
        harden(site, a, rep)
        rep.log("\nDRY RUN: nothing was changed.")
        return rep
    if not confirm(a, rep):
        rep.log("aborted, nothing changed.")
        rep.exit = 1
        return rep

    rep.log("\n== backup (without uploads; run `backup` for a full one)")
    bak = make_backup(site, a, rep, uploads=False, local_only=True)
    quarantine(site, move, qroot, rep)
    for uid in a.delete_user or []:
        rep.log(f"  delete user {uid}:", wpcli.wp(site, "user", "delete", uid, "--yes").stdout.strip())
    reinstall(site, rep, pins, dry=False)
    db_clean(site, rep, dry=not a.clean_db)
    harden(site, a, rep)
    rep.log("== new salts (logs everyone out)")
    wpcli.wp(site, "config", "shuffle-salts")

    rep.log("== rescan")
    left, _ = split_findings(site, find_files(site, a, rep), aggressive=a.aggressive)
    quarantine(site, left, qroot, rep)
    rep.log(
        f"\nDone. Backup: {bak}\nQuarantine: {qroot}\nBaseline saved ({write_baseline(site)} files): use `watch` in cron.\n"
        "Still manual: unknown admins, DB/FTP/hosting passwords, wp-config.php, find the entry hole (`logs`, VULN lines above)."
    )
    return rep
