"""Update advisor: try each pending core/plugin/theme update on a throwaway staging copy, report what breaks.

Staging = a copy of the files (without uploads) + a cloned database served by PHP's built-in web server on
127.0.0.1. Outgoing mail and HTTP (except wordpress.org, needed to download updates) are blocked inside the copy
and WP-Cron is off, so loading the site's plugins there cannot e-mail customers or hit your integrations.
Needs: php, a MySQL user allowed to CREATE DATABASE (or pass --stage-db with an existing empty database).
"""

import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Self

from wpguard import lockfile, wpcli
from wpguard.backup import make_backup
from wpguard.report import Rep

FATAL = re.compile(
    r"Fatal error|Parse error|Uncaught |There has been a critical error|Allowed memory size", re.IGNORECASE
)
DEFAULT_PATHS = ["/", "/wp-login.php", "/wp-admin/"]
STATUS_ERROR = 500
ROUTER = """<?php
$p = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($p !== '/' && is_file($_SERVER['DOCUMENT_ROOT'] . $p)) { return false; }
$_SERVER['SCRIPT_NAME'] = '/index.php';
require $_SERVER['DOCUMENT_ROOT'] . '/index.php';
"""
MU_GUARD = """<?php
// wpguard staging guard: no mail, no outgoing HTTP except wordpress.org (updates), no cron.
add_filter('pre_wp_mail', '__return_false');
add_filter('pre_http_request', function ($pre, $args, $url) {
    $host = (string) parse_url($url, PHP_URL_HOST);
    $ok = in_array($host, ['127.0.0.1', 'localhost'], true) || preg_match('/(^|\\.)(wordpress|w|wp)\\.org$/', $host);
    return $ok ? $pre : new WP_Error('wpguard_stage', 'outgoing HTTP blocked in wpguard staging');
}, 10, 3);
"""


def candidates(site: Path) -> list[dict]:
    """Pending updates: [{'kind','name','from','to'}]."""
    out = []
    now = wpcli.wp(site, "core", "version").stdout.strip()
    core = wpcli.jget(site, "core", "check-update", "--format=json")
    if core:
        out.append({"kind": "core", "name": "wordpress", "from": now, "to": core[0]["version"]})
    for kind in ("plugin", "theme"):
        for it in wpcli.jget(
            site, kind, "list", "--update=available", "--format=json", "--fields=name,version,update_version"
        ):
            out += [{"kind": kind, "name": it["name"], "from": it["version"], "to": it["update_version"]}]
    return out


def check(base: str, paths: list[str], timeout: int = 30) -> dict[str, str]:
    """GET each path; return {path: problem} for 5xx responses, PHP fatals or unreachable pages."""
    bad = {}
    for path in paths:
        try:
            with urllib.request.urlopen(base + path, timeout=timeout) as r:
                status, body = r.status, r.read(300_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read(300_000).decode("utf-8", "replace")
        except OSError as e:
            bad[path] = f"unreachable: {e}"
            continue
        if status >= STATUS_ERROR:
            bad[path] = f"HTTP {status}"
        elif m := FATAL.search(body):
            bad[path] = f"PHP error in page: {m.group(0)}"
    return bad


def try_candidates(stage, cands: list[dict], paths: list[str], rep: Rep) -> list[dict]:
    """Apply each update alone on the stage, check the site, then roll that item back. Stage API: .root .base .wp() .log_text()."""
    base_bad = check(stage.base, paths)
    if base_bad:
        rep.log(
            f"  staging copy is already unhealthy before any update: {base_bad}. Results below may not be attributable."
        )
    results = []
    for c in cands:
        kdir = {"plugin": "plugins", "theme": "themes"}.get(c["kind"])
        target = stage.root / "wp-content" / kdir / c["name"] if kdir else None
        snap = None
        if target and target.exists():
            snap = Path(tempfile.mkdtemp(prefix="wpguard-snap-")) / c["name"]
            shutil.copytree(target, snap, symlinks=True)
        mark = len(stage.log_text())
        cmd = ("core", "update") if c["kind"] == "core" else (c["kind"], "update", c["name"])
        r = stage.wp(*cmd)
        if r.returncode:
            res = {**c, "result": "update-failed", "detail": (r.stderr or r.stdout).strip()[-200:]}
        else:
            if c["kind"] == "core":
                stage.wp("core", "update-db")
            bad = {p: why for p, why in check(stage.base, paths).items() if p not in base_bad}
            fatals = FATAL.findall(stage.log_text()[mark:])
            if bad or fatals:
                detail = "; ".join(
                    [f"{p}: {w}" for p, w in bad.items()]
                    + ([f"{len(fatals)} PHP fatal(s) in server log"] if fatals else [])
                )
                res = {**c, "result": "BREAKS", "detail": detail}
            else:
                res = {**c, "result": "ok", "detail": ""}
        if snap and target:
            shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(snap, target, symlinks=True)
            shutil.rmtree(snap.parent, ignore_errors=True)
        results.append(res)
        rep.log(f"  {res['result']:13} {c['kind']:6} {c['name']} {c['from']} -> {c['to']} {res['detail']}")
    return results


class Stage:
    """Throwaway staging copy of a site. Use as a context manager."""

    def __init__(self, site: Path, a) -> None:
        self.site, self.a = site, a
        self.tmp = Path(tempfile.mkdtemp(prefix="wpguard-stage-"))
        self.root = self.tmp / "site"
        self.db = a.stage_db or f"wpguard_stage_{secrets.token_hex(3)}"
        self.created_db = False
        self.proc: subprocess.Popen | None = None
        self.log_path = self.tmp / "server.log"
        self.base = ""

    def wp(self, *args: str) -> subprocess.CompletedProcess:
        return wpcli.wp(self.root, *args)

    def log_text(self) -> str:
        return self.log_path.read_text(errors="replace") if self.log_path.exists() else ""

    def __enter__(self) -> Self:
        def ignore(d: str, _names: list[str]) -> set[str]:
            return {"uploads"} if Path(d).name == "wp-content" else set()

        old_home = wpcli.wp(self.site, "option", "get", "home").stdout.strip()
        dump = self.tmp / "db.sql"
        if (r := wpcli.wp(self.site, "db", "export", str(dump))).returncode:
            msg = f"cannot dump the database: {r.stderr.strip()}"
            raise RuntimeError(msg)
        shutil.copytree(self.site, self.root, symlinks=True, ignore=ignore)
        (self.root / "wp-content/uploads").mkdir(exist_ok=True)
        mu = self.root / "wp-content/mu-plugins"
        mu.mkdir(exist_ok=True)
        (mu / "wpguard-stage.php").write_text(MU_GUARD)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        for key, val in (("DB_NAME", self.db), ("WP_HOME", self.base), ("WP_SITEURL", self.base)):
            self.wp("config", "set", key, val)
        for key in ("DISABLE_WP_CRON", "WP_DEBUG_DISPLAY"):
            self.wp("config", "set", key, "true" if key == "DISABLE_WP_CRON" else "false", "--raw")
        self.wp("config", "set", "FORCE_SSL_ADMIN", "false", "--raw")
        made = self.wp("db", "create")
        self.created_db = made.returncode == 0
        if not self.created_db and not self.a.stage_db:
            msg = f"cannot create staging database {self.db}: {made.stderr.strip()}. Pass --stage-db with an existing empty DB."
            raise RuntimeError(msg)
        if (r := self.wp("db", "import", str(dump))).returncode:
            msg = f"staging import failed: {r.stderr.strip()}"
            raise RuntimeError(msg)
        self.wp("search-replace", old_home, self.base, "--all-tables", "--skip-columns=guid")
        router = self.tmp / "router.php"
        router.write_text(ROUTER)
        with self.log_path.open("w") as log:
            self.proc = subprocess.Popen(
                ["php", "-S", f"127.0.0.1:{port}", "-t", str(self.root), str(router)], stdout=log, stderr=log
            )
        for _ in range(50):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    return self
            time.sleep(0.2)
        msg = "staging web server did not start"
        raise RuntimeError(msg)

    def __exit__(self, *exc: object) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        if self.created_db:
            self.wp("db", "drop", "--yes")
        elif self.a.stage_db:
            self.wp("db", "reset", "--yes")
        if self.a.keep_stage:
            print(f"staging kept: {self.root} ({self.base})")
        else:
            shutil.rmtree(self.tmp, ignore_errors=True)


def updates(site: Path, a) -> Rep:
    """Advise (and with --apply, apply) pending updates after testing each on a staging copy."""
    rep = Rep(site)
    cands = candidates(site)
    if not cands:
        rep.log("nothing to update")
        return rep
    rep.log(f"== {len(cands)} pending update(s); testing each on a staging copy")
    paths = a.check_url or DEFAULT_PATHS
    try:
        with Stage(site, a) as stage:
            results = try_candidates(stage, cands, paths, rep)
    except RuntimeError as e:
        rep.log(f"staging failed: {e}")
        rep.exit = 1
        return rep
    ok = [r for r in results if r["result"] == "ok"]
    for r in results:
        if r["result"] != "ok":
            rep.hit(
                "update-" + r["result"].lower(),
                f"{r['kind']} {r['name']} {r['from']}->{r['to']}",
                r["detail"] or r["result"],
            )
    rep.log(f"\nsafe to apply: {len(ok)}   problematic: {len(results) - len(ok)}")
    if not a.apply:
        rep.log("advice only. Re-run with --apply to update the safe ones on the real site (after a backup).")
        return rep
    if not ok:
        return rep
    make_backup(site, a, rep, uploads=False, local_only=True)
    for r in ok:
        cmd = ("core", "update") if r["kind"] == "core" else (r["kind"], "update", r["name"])
        res = wpcli.wp(site, *cmd)
        rep.log(
            f"  applied {r['kind']} {r['name']}: {'ok' if res.returncode == 0 else (res.stderr or res.stdout).strip()[-120:]}"
        )
        if res.returncode:
            rep.exit = 1
    if "core" in {r["kind"] for r in ok}:
        wpcli.wp(site, "core", "update-db")
    lock_path = lockfile.path_for(a)
    data = lockfile.read(lock_path)
    if a.site_key in data["sites"]:
        data["sites"][a.site_key] = lockfile.site_state(site)
        lockfile.write(lock_path, data)
        rep.log(f"  {lock_path.name} updated")
    return rep
