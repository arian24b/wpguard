#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = ["pymysql"]  # only used by `recover` against a live MySQL
# ///
"""wpguard: scan, clean, harden and monitor hacked WordPress sites with wp-cli.

  wpguard.py setup                         download wp-cli (sha512 verified)
  wpguard.py scan     SITE...              report only (files, configs, DB, persistence, vulns)
  wpguard.py fix      SITE...              backup, quarantine, reinstall, harden, new salts, baseline
  wpguard.py harden   SITE...              block PHP in uploads, DISALLOW_FILE_EDIT, perms [--prune]
  wpguard.py baseline SITE...              snapshot file hashes (run on a CLEAN site)
  wpguard.py watch    SITE...              diff against baseline; exit 1 + alert on change (cron)
  wpguard.py logs     [SITE...]            find the entry point in web server access logs
  wpguard.py restore  SITE [--from DIR]    roll back DB + wp-content from a fix backup
  wpguard.py audit    SITE... [--format md|json] [--out F]   full inventory + findings export (secrets redacted)
  wpguard.py recover  ARGS...              rebuild a wiped site from DB/dump (see `recover --help`)

Options: --sites-file F  -j N  --report out.{json,html,txt}  --notify  --sigs FILE  --since DAYS
         --url https://real.site (pins WP_HOME/WP_SITEURL)  --lock (also DISALLOW_FILE_MODS + no auto-update)
         --no-net  --clean-db  --prune  --delete-user ID  --log FILE  --top N

Alerts (--notify) use env: WPGUARD_TELEGRAM_TOKEN + WPGUARD_TELEGRAM_CHAT, and/or WPGUARD_EMAIL (local SMTP).
Vuln lookups: optional WPSCAN_TOKEN (free wpscan.com key). Cron:  */15 * * * * wpguard.py watch /var/www/x --notify
Run as the site's file owner (sudo -u www-data). Needs php + mysql client on PATH (not for baseline/watch/logs).
"""
import argparse, glob, gzip, hashlib, html, io, json, os, pathlib, re, shutil, smtplib, ssl, subprocess, sys, tarfile, time, zipfile
import urllib.error, urllib.parse, urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

WP = Path.home() / ".local/share/wpguard/wp-cli.phar"
URL = "https://github.com/wp-cli/wp-cli/releases/latest/download/wp-cli.phar"
PHP_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".inc", ".suspected"}
# wp-config.php constants applied by `harden`. LOCK ones block plugin/theme installs + updates, so only with --lock.
HARDEN = {"FORCE_SSL_ADMIN": "true", "WP_AUTO_UPDATE_CORE": "false", "WP_DEBUG": "false", "WP_DEBUG_DISPLAY": "false",
          "FS_CHMOD_FILE": "0644", "FS_CHMOD_DIR": "0755", "DISALLOW_FILE_EDIT": "true"}
HARDEN_LOCK = {"DISALLOW_FILE_MODS": "true", "AUTOMATIC_UPDATER_DISABLED": "true"}
OK_HIDDEN = {".htaccess", ".user.ini", ".well-known", ".htpasswd", ".gitignore", ".maintenance"}
KEEP = {"wp-config.php", ".htaccess"}  # report only, never auto-quarantine (outside uploads)
LIVE = True

# Heuristic webshell/backdoor patterns; expect false positives in obfuscated commercial plugins.
SIG = re.compile(rb"""(?isx)
    eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|stripslashes\s*\(\s*\$_)
  | (system|shell_exec|passthru|exec|popen|proc_open|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
  | \$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\(
  | preg_replace\s*\(\s*['"]/[^'"]*/e['"]
  | (create_function|call_user_func(_array)?)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
  | file_put_contents\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)
  | FilesMan | c99shell | r57shell | b374k | IndoXploit | WSO\s*[0-9.]* | Web\s*Shell | Priv8
  | [A-Za-z0-9+/=]{600,}
""")
CFG_BAD = re.compile(rb"eval\s*\(|base64_decode|gzinflate|str_rot13|auto_prepend_file|\$_(?:GET|POST|REQUEST|COOKIE)"
                     rb"|(?:include|require)(?:_once)?[^;\n]*\.(?:ico|jpe?g|png|gif|txt|log|tmp)\b", re.I)
HT_BAD = re.compile(rb"RewriteRule[^\n]*https?://(?!%\{)|auto_(?:prepend|append)_file"
                    rb"|(?:AddHandler|AddType)[^\n]*php[^\n]*\.(?:jpe?g|png|gif|ico|txt|html?|css|js)\b", re.I)
AUTO = re.compile(rb"auto_(?:prepend|append)_file", re.I)
DB_PAT = r"<script|<iframe|eval[(]|base64_decode|document[.]write|fromCharCode"  # [(] not \( : SQL eats backslashes
OK_HOSTS = ["googletagmanager.com", "google-analytics.com", "google.com", "googleapis.com", "gstatic.com",
            "facebook.net", "facebook.com", "fbcdn.net", "cloudflare.com", "cdnjs.cloudflare.com",
            "jsdelivr.net", "unpkg.com", "jquery.com", "youtube.com", "twitter.com", "wp.com", "wordpress.org", "w.org"]
ODD_CRON = re.compile(r"eval|base64|shell|cmd|exec|http|^[a-z0-9]{10,}$", re.I)
LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
LOG_GLOBS = ["/var/log/nginx/access.log*", "/var/log/apache2/access.log*", "/var/log/httpd/access_log*",
             "/var/log/apache2/*access*.log*", "/var/log/nginx/*access*.log*"]
ATTACK = re.compile(r"\.\./|union\s+select|base64_|eval\(|cmd=|/etc/passwd|<script|wget%20|curl%20", re.I)
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


class Rep:
    """Per-site report. hits = things needing attention; log = readable transcript."""
    def __init__(s, site):
        s.site, s.lines, s.hits, s.files = str(site), [], [], {}

    def log(s, *a):
        line = " ".join(map(str, a))
        s.lines.append(line)
        if LIVE:
            print(line, flush=True)

    def hit(s, kind, what, why):
        s.hits.append({"kind": kind, "what": str(what), "why": why})
        s.log(f"  [{kind}] {what}  <- {why}")


def selftest():
    assert SIG.search(b"<?php eval(base64_decode($x));")
    assert SIG.search(b"<?php @$_POST['a']($_POST['b']);")
    assert not SIG.search(b"<?php echo 'hello';")
    assert HT_BAD.search(b"RewriteRule ^(.*)$ http://evil.tld/$1 [R]")
    assert not HT_BAD.search(b"RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301]")
    assert judge("x.php", ".php", True, b"GIF89a<?php", None) == "php code in uploads"
    assert vkey("1.10.0") > vkey("1.9.9")


# ---------- plumbing ----------
def setup():
    WP.parent.mkdir(parents=True, exist_ok=True)
    data = urllib.request.urlopen(URL).read()
    want = urllib.request.urlopen(URL + ".sha512").read().split()[0].decode()
    assert hashlib.sha512(data).hexdigest() == want, "wp-cli checksum mismatch"
    WP.write_bytes(data)
    print("wp-cli ->", WP)


def wp(site, *a):
    # --skip-plugins/themes: never execute possibly infected code while cleaning
    cmd = ["php", str(WP), f"--path={site}", "--skip-plugins", "--skip-themes",
           *(["--allow-root"] if os.geteuid() == 0 else []), *a]
    return subprocess.run(cmd, capture_output=True, text=True)


def jget(site, *a):
    try:
        return json.loads(wp(site, *a).stdout)
    except json.JSONDecodeError:
        return []


def get_json(url, headers=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def notify(text):
    if (t := os.environ.get("WPGUARD_TELEGRAM_TOKEN")) and (c := os.environ.get("WPGUARD_TELEGRAM_CHAT")):
        body = urllib.parse.urlencode({"chat_id": c, "text": text[:4000]}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{t}/sendMessage", body, timeout=10)
    if to := os.environ.get("WPGUARD_EMAIL"):
        m = EmailMessage()
        m["To"], m["From"], m["Subject"] = to, f"wpguard@{os.uname().nodename}", "wpguard alert"
        m.set_content(text)
        with smtplib.SMTP("localhost") as s:
            s.send_message(m)


# ---------- file scan ----------
def judge(name, ext, in_up, data, extra):
    if name == ".htaccess":
        if in_up:
            return "htaccess in uploads"
        if m := HT_BAD.search(data):
            return f"htaccess rule: {m.group(0)[:50]!r}"
    elif name in (".user.ini", "php.ini"):
        if AUTO.search(data):
            return "auto_prepend/append_file"
    elif name == "wp-config.php":
        if m := CFG_BAD.search(data):
            return f"wp-config suspicious: {m.group(0)[:50]!r}"
    elif in_up and (ext in PHP_EXT or b"<?php" in data):
        return "php code in uploads"
    elif ext in PHP_EXT and (m := SIG.search(data) or (extra and extra.search(data))):
        return f"signature: {m.group(0)[:40]!r}"


def file_scan(site: Path, a, extra, rep):
    hits, up = {}, site / "wp-content/uploads"
    cutoff = time.time() - a.since * 86400 if a.since else None
    for root, dirs, files in os.walk(site):
        for d in [d for d in dirs if d.startswith(".") and d not in OK_HIDDEN]:
            hits[Path(root, d)] = "hidden directory"
        dirs[:] = [d for d in dirs if not (d.startswith(".") and d not in OK_HIDDEN)]
        for f in files:
            p = Path(root, f)
            try:
                if p.is_symlink():
                    continue
                size, mtime = (st := p.stat()).st_size, st.st_mtime
                ext, in_up = p.suffix.lower(), up in p.parents
                if f.startswith(".") and f not in OK_HIDDEN:
                    hits[p] = "hidden file"
                    continue
                if size > 5_000_000:  # ponytail: skips huge files; raise if shells hide in big blobs
                    continue
                if f in (".htaccess", ".user.ini", "php.ini", "wp-config.php") or ext in PHP_EXT or in_up:
                    if why := judge(f, ext, in_up, p.read_bytes(), extra):
                        hits[p] = why
                    elif cutoff and ext in PHP_EXT and mtime > cutoff:
                        rep.hit("recent", p.relative_to(site), f"php modified within {a.since}d")
            except OSError:
                continue
    mu = site / "wp-content/mu-plugins"
    for p in mu.glob("*.php") if mu.is_dir() else []:
        hits.setdefault(p, "mu-plugin (verify it is yours)")
    return hits


def checksum_extras(site: Path):
    """Files wp.org checksums say should not exist (core + plugins)."""
    extras = {}
    r = wp(site, "core", "verify-checksums")
    for m in re.finditer(r"File should not exist: (.+)", r.stdout + r.stderr):
        extras[site / m.group(1).strip()] = "not part of WP core"
    for e in jget(site, "plugin", "verify-checksums", "--all", "--format=json"):
        if "added" in e["message"]:
            extras[site / "wp-content/plugins" / e["plugin_name"] / e["file"]] = "not part of plugin"
    return {p: why for p, why in extras.items() if p.is_file()}


def find_files(site, a, rep):
    extra = re.compile("|".join(Path(a.sigs).read_text().split("\n")).encode(), re.I) if a.sigs else None
    return {**file_scan(site, a, extra, rep), **checksum_extras(site)}


def quarantine(site: Path, hits, qroot: Path, rep):
    up = site / "wp-content/uploads"
    for p, why in hits.items():
        if not p.exists():
            continue
        if p.name in KEEP and up not in p.parents:
            rep.log(f"  ! review manually: {p.relative_to(site)} ({why})")
            continue
        dst = qroot / p.relative_to(site)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(p, dst)
        rep.log(f"  quarantined {p.relative_to(site)}")


def clamav(site, rep):
    if shutil.which("clamscan"):
        r = subprocess.run(["clamscan", "-r", "-i", "--no-summary", str(site)], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            rep.hit("clamav", *line.rsplit(": ", 1))


# ---------- DB / persistence / vulns ----------
def db_scan(site, rep):
    q = lambda sql: wp(site, "db", "query", sql, "--skip-column-names").stdout.strip()
    pre = wp(site, "db", "prefix").stdout.strip()
    for label, sql in {
        "posts": f"SELECT ID,post_type,post_title FROM {pre}posts WHERE post_content REGEXP '{DB_PAT}' AND post_status NOT IN ('trash','auto-draft')",
        "options": f"SELECT option_name FROM {pre}options WHERE option_value REGEXP '{DB_PAT}' AND option_name NOT LIKE '\\_transient%'",
    }.items():
        out = q(sql)
        if out:
            rep.hit("db", f"{len(out.splitlines())} {label}", "suspicious script/eval content")
            rep.log("    " + out[:2000].replace("\n", "\n    "))


def db_clean(site, rep, dry):
    host = re.sub(r"^https?://(www\.)?|[/:].*$", "", wp(site, "option", "get", "home").stdout.strip())
    ok = "|".join(map(re.escape, [host, *OK_HOSTS]))
    pats = [  # '#' is the regex delimiter, so patterns must not contain it
        rf"<script[^>]*\bsrc=[\"']?(?:https?:)?//(?!(?:[\w-]+\.)*(?:{ok})[/\"' >:])[^>]*>\s*</script>",
        r"<script[^>]*>[^<]*(?:eval\(|atob\(|fromCharCode|unescape\()[^<]*</script>",
        r"<iframe[^>]*(?:width=[\"']?[01][\"' >]|height=[\"']?[01][\"' >]|display:\s*none)[^>]*>\s*</iframe>",
    ]
    rep.log(f"== DB clean ({'DRY RUN, add --clean-db to apply' if dry else 'APPLYING'})")
    for pat in pats:
        r = wp(site, "search-replace", pat, "", "--regex", "--regex-delimiter=#", "--regex-flags=is",
               "--skip-columns=guid", "--report-changed-only", *(["--dry-run"] if dry else []))
        rep.log("  ", (r.stdout + r.stderr).strip().replace("\n", "\n   ") or "no matches")


def persistence(site, rep, a):
    cut = time.time() - (a.since or 30) * 86400
    for u in jget(site, "user", "list", "--role=administrator", "--fields=ID,user_login,user_email,user_registered", "--format=json"):
        line = f"#{u['ID']} {u['user_login']} <{u['user_email']}> registered {u['user_registered']}"
        if datetime.fromisoformat(u["user_registered"]).timestamp() > cut:
            rep.hit("admin", line, "NEW administrator, verify (fix --delete-user ID)")
        else:
            rep.log("  [admin]", line)
    hooks = {e["hook"] for e in jget(site, "cron", "event", "list", "--fields=hook", "--format=json")}
    for h in sorted(h for h in hooks if ODD_CRON.search(h)):
        rep.hit("cron", h, "odd-looking cron hook")
    for pl in jget(site, "option", "get", "active_plugins", "--format=json"):
        if not (site / "wp-content/plugins" / pl).exists():
            rep.hit("option", pl, "active plugin file missing")
    if wp(site, "option", "get", "default_role").stdout.strip() == "administrator":
        rep.hit("option", "default_role", "new users become administrators")


def vulns(site, rep):
    token = os.environ.get("WPSCAN_TOKEN")
    if core := jget(site, "core", "check-update", "--format=json"):
        rep.hit("outdated", "wordpress core", f"update to {core[0]['version']} available")
    for kind in ("plugin", "theme"):
        for it in jget(site, kind, "list", "--format=json", "--fields=name,version,update"):
            n, v = it["name"], it["version"]
            if it["update"] == "available":
                rep.hit("outdated", f"{kind} {n} {v}", "update available")
            if kind == "plugin":
                st, d = get_json(f"https://api.wordpress.org/plugins/info/1.0/{n}.json")
                if st == 404 or (isinstance(d, dict) and "error" in d):
                    rep.hit("source", f"plugin {n}", "not on wordpress.org (closed/removed/premium/nulled?)")
                elif isinstance(d, dict) and d.get("last_updated"):
                    age = (datetime.now() - datetime.strptime(d["last_updated"][:10], "%Y-%m-%d")).days
                    if age > 730:
                        rep.hit("abandoned", f"plugin {n}", f"not updated for {age // 365}y")
            if token:
                st, d = get_json(f"https://wpscan.com/api/v3/{kind}s/{n}", {"Authorization": f"Token token={token}"})
                for vu in (d or {}).get(n, {}).get("vulnerabilities", []):
                    fx = vu.get("fixed_in")
                    if not fx or vkey(v) < vkey(fx):
                        rep.hit("VULN", f"{kind} {n} {v}", f"{vu['title']} (fixed in {fx or 'NO FIX'})")


def scan(site: Path, a, rep=None):
    rep = rep or Rep(site)
    rep.log(f"== scan {site}")
    rep.files = find_files(site, a, rep)
    for p, why in sorted(rep.files.items()):
        rep.hit("file", p.relative_to(site), why)
    clamav(site, rep)
    r = wp(site, "core", "verify-checksums")
    rep.log("  [core]", ((r.stdout + r.stderr).strip().splitlines() or ["?"])[-1])
    db_scan(site, rep)
    if a.clean_db:
        db_clean(site, rep, dry=True)
    persistence(site, rep, a)
    if not a.no_net:
        vulns(site, rep)
    return rep


# ---------- fix / harden / restore ----------
def harden(site: Path, a, rep=None):
    rep = rep or Rep(site)
    rep.log("== harden")
    up = site / "wp-content/uploads"
    if up.is_dir():
        (up / ".htaccess").write_text(UPLOADS_HT)
        rep.log("  uploads/.htaccess blocks PHP. nginx users add:", NGINX)
    consts = {**HARDEN, **(HARDEN_LOCK if a.lock else {})}
    if a.url:  # pins URLs: defeats a siteurl hijacked in the DB
        consts |= {"WP_HOME": f"'{a.url}'", "WP_SITEURL": f"'{a.url}'"}
    for k, v in consts.items():
        r = wp(site, "config", "set", k, v.strip(), "--raw")
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
            for it in jget(site, kind, "list", "--status=inactive", "--format=json", "--fields=name"):
                wp(site, kind, "delete", it["name"])
                rep.log(f"  pruned inactive {kind} {it['name']}")
    return rep


def baseline_file(site):
    return WP.parent / f"baseline-{hashlib.sha1(str(site).encode()).hexdigest()[:12]}.json"


def snapshot(site: Path):
    # ponytail: media in uploads is not hashed (php/.htaccess there is); hash it too if disguised shells matter
    up, snap = site / "wp-content/uploads", {}
    for root, dirs, files in os.walk(site):
        dirs[:] = [d for d in dirs if d not in {"cache", "upgrade", "wflogs", "node_modules", ".git"}]
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


def baseline(site: Path, a):
    rep = Rep(site)
    WP.parent.mkdir(parents=True, exist_ok=True)
    snap = snapshot(site)
    baseline_file(site).write_text(json.dumps(snap))
    rep.log(f"baseline: {len(snap)} files -> {baseline_file(site)}")
    return rep


def watch(site: Path, a):
    rep = Rep(site)
    if not baseline_file(site).exists():
        rep.log("no baseline yet: run `baseline` on a clean site")
        return rep
    old, new = json.loads(baseline_file(site).read_text()), snapshot(site)
    extra = re.compile("|".join(Path(a.sigs).read_text().split("\n")).encode(), re.I) if a.sigs else None
    for kind, rels in (("new", sorted(new.keys() - old.keys())),
                       ("changed", sorted(r for r in new if r in old and new[r] != old[r]))):
        for rel in rels:
            p = site / rel
            why = judge(p.name, p.suffix.lower(), site / "wp-content/uploads" in p.parents, p.read_bytes()[:5_000_000], extra)
            rep.hit(kind, rel, f"SIGNATURE MATCH: {why}" if why else "file differs from baseline")
    for rel in sorted(old.keys() - new.keys()):
        rep.hit("removed", rel, "file gone since baseline")
    if not rep.hits:
        rep.log(f"{site}: unchanged")
    return rep


def reinstall(site, rep):
    rep.log("== reinstall core")
    for args in (("core", "download", "--force", "--skip-content"), ("core", "update-db")):
        r = wp(site, *args)
        rep.log("  ", ((r.stdout + r.stderr).strip().splitlines() or ["done"])[-1])
    for kind in ("plugin", "theme"):
        rep.log(f"== reinstall + update {kind}s")
        for it in jget(site, kind, "list", "--format=json", "--fields=name"):
            ok = wp(site, kind, "install", it["name"], "--force").returncode == 0
            rep.log(f"  {'ok  ' if ok else 'SKIP'} {it['name']}" + ("" if ok else "  (not on wp.org: reinstall from vendor)"))


def fix(site: Path, a):
    rep = Rep(site)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = site.parent / f"wpguard-backup-{site.name}-{ts}"
    qroot = site.parent / "wpguard-quarantine" / f"{site.name}-{ts}"
    bak.mkdir(parents=True)
    rep.log(f"== backup -> {bak}")
    r = wp(site, "db", "export", str(bak / "db.sql"))
    assert r.returncode == 0, f"db backup failed, aborting: {r.stderr}"
    with tarfile.open(bak / "wp-content.tgz", "w:gz") as t:  # uploads excluded: can be huge
        t.add(site / "wp-content", arcname="wp-content", filter=lambda i: None if "/uploads" in i.name else i)

    scan(site, a, rep)
    quarantine(site, rep.files, qroot, rep)
    for uid in a.delete_user or []:
        rep.log(f"  delete user {uid}:", wp(site, "user", "delete", uid, "--yes").stdout.strip())
    reinstall(site, rep)
    db_clean(site, rep, dry=not a.clean_db)
    harden(site, a, rep)
    rep.log("== new salts (logs everyone out)")
    wp(site, "config", "shuffle-salts")

    rep.log("== rescan")
    left = find_files(site, a, rep)
    quarantine(site, left, qroot, rep)
    snap = snapshot(site)
    baseline_file(site).write_text(json.dumps(snap))
    rep.log(f"\nDone. Backup: {bak}\nQuarantine: {qroot}\nBaseline saved ({len(snap)} files): use `watch` in cron.\n"
            "Still manual: unknown admins, DB/FTP/hosting passwords, wp-config.php, find the entry hole (`logs`, VULN lines above).")
    return rep


def restore(site: Path, a):
    rep = Rep(site)
    found = sorted(site.parent.glob(f"wpguard-backup-{site.name}-*"))
    bak = Path(a.src) if a.src else (found[-1] if found else None)
    if not bak or not bak.is_dir():
        rep.log("no backup found (use --from DIR)")
        return rep
    r = wp(site, "db", "import", str(bak / "db.sql"))
    rep.log("db import:", (r.stdout + r.stderr).strip() or "ok")
    with tarfile.open(bak / "wp-content.tgz") as t:
        t.extractall(site, filter="data")
    rep.log(f"wp-content restored from {bak}. Quarantined files stay in {site.parent}/wpguard-quarantine (move back by hand).")
    return rep


# ---------- audit export ----------
def audit(site: Path, a):
    """Inventory + scan findings as a dict in rep.data (printed by main, not logged)."""
    global LIVE
    rep = Rep(site)
    live, LIVE = LIVE, False
    try:
        sc = scan(site, a)
    finally:
        LIVE = live
    cfg = {}
    if (cp := site / "wp-config.php").exists():
        for k, v in re.findall(r"define\(\s*['\"](\w+)['\"]\s*,\s*([^;]*?)\)\s*;", cp.read_text(errors="replace")):
            cfg[k] = "[redacted]" if re.search(r"PASSWORD|KEY|SALT|DB_USER", k) else v.strip()
    nphp = sum(f.lower().endswith(tuple(PHP_EXT)) for _, _, fs in os.walk(site) for f in fs)
    users = jget(site, "user", "list", "--fields=ID,user_login,user_email,roles,user_registered", "--format=json")
    opt = lambda k: wp(site, "option", "get", k).stdout.strip()
    wpc = site / "wp-content"
    rep.data = {
        "site": str(site), "generated": datetime.now().isoformat(timespec="seconds"), "tool": "wpguard",
        "wordpress": wp(site, "core", "version").stdout.strip(),
        "php": subprocess.run(["php", "-r", "echo PHP_VERSION;"], capture_output=True, text=True).stdout,
        "settings": {k: opt(k) for k in ("siteurl", "home", "blogname", "admin_email", "default_role",
                                         "users_can_register", "permalink_structure", "WPLANG", "template", "stylesheet")},
        "plugins": jget(site, "plugin", "list", "--format=json", "--fields=name,version,status,update"),
        "themes": jget(site, "theme", "list", "--format=json", "--fields=name,version,status,update"),
        "users": {"count": len(users), "by_role": dict(Counter(u["roles"] for u in users)), "list": users[:500]},
        "cron_hooks": sorted({e["hook"] for e in jget(site, "cron", "event", "list", "--fields=hook", "--format=json")}),
        "mu_plugins": sorted(f.name for f in (wpc / "mu-plugins").glob("*.php")),
        "dropins": [n for n in ("advanced-cache.php", "object-cache.php", "db.php", "db-error.php", "maintenance.php", "sunrise.php") if (wpc / n).exists()],
        "wp_config": cfg, "php_files": nphp, "findings": sc.hits,
    }
    return rep


def md_table(rows, cols):
    if not rows:
        return "_none_\n"
    cell = lambda v: str(v).replace("|", "\\|").replace("\n", " ")
    return "\n".join(["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols),
                      *("| " + " | ".join(cell(r.get(c, "")) for c in cols) + " |" for r in rows)]) + "\n"


def audit_md(d):
    kv = lambda m: md_table([{"key": k, "value": v} for k, v in m.items()], ["key", "value"])
    u = d["users"]
    return "\n".join([
        f"# WordPress audit: {d['site']}", f"_generated {d['generated']} by wpguard_\n",
        f"## Overview\n\n- WordPress: {d['wordpress']}\n- PHP: {d['php']}\n- PHP files: {d['php_files']}\n"
        f"- Findings: {len(d['findings'])}\n", "## Settings\n", kv(d["settings"]),
        f"## Findings ({len(d['findings'])})\n", md_table(d["findings"], ["kind", "what", "why"]),
        "## Plugins\n", md_table(d["plugins"], ["name", "version", "status", "update"]),
        "## Themes\n", md_table(d["themes"], ["name", "version", "status", "update"]),
        f"## Users ({u['count']}) by role: {u['by_role']}\n", md_table(u["list"], ["ID", "user_login", "user_email", "roles", "user_registered"]),
        f"## Must-use plugins\n\n{', '.join(d['mu_plugins']) or '_none_'}\n",
        f"## Drop-ins\n\n{', '.join(d['dropins']) or '_none_'}\n",
        f"## Cron hooks ({len(d['cron_hooks'])})\n\n{', '.join(d['cron_hooks']) or '_none_'}\n",
        "## wp-config.php constants (secrets redacted)\n", kv(d["wp_config"]),
    ])


# ---------- access logs ----------
def logs(sites, a):
    rep = Rep("logs")
    paths = [Path(p) for p in a.log] or [Path(p) for g in LOG_GLOBS for p in sorted(glob.glob(g))]
    q = set()  # ponytail: assumes WP lives in the docroot, so rel path == URL path
    for s in sites:
        s = Path(s).resolve()
        q |= {"/" + str(f.relative_to(d)) for d in (s.parent / "wpguard-quarantine").glob(f"{s.name}-*") for f in d.rglob("*") if f.is_file()}
    c = {k: Counter() for k in ("login", "xmlrpc", "attack", "plugin_post", "uploads_php", "quarantined")}
    for p in paths:
        with (gzip.open if p.suffix == ".gz" else open)(p, "rt", errors="replace") as fh:
            for line in fh:
                if not (m := LOG_RE.match(line)):
                    continue
                ip, meth, url, st, ua = m.groups()
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
                if meth == "POST" and re.search(r"/wp-content/(plugins|themes)/.+\.php$", path) and "admin-ajax" not in path:
                    c["plugin_post"][f"{path} -> {st}"] += 1
    rep.log(f"== logs: {len(paths)} files")
    notes = {"login": "POST wp-login.php (brute force) by IP", "xmlrpc": "POST xmlrpc.php by IP",
             "attack": "attack strings in URL by IP", "plugin_post": "direct POST to plugin/theme PHP (exploit entry point?)",
             "uploads_php": "requests to PHP in uploads (shell use)", "quarantined": "requests to files you quarantined (WHO used the shell)"}
    for k, title in notes.items():
        rep.log(f"-- {title}")
        for item, n in c[k].most_common(a.top):
            rep.log(f"  {n:6}  {item}")
        if c[k]:
            rep.hits.append({"kind": k, "what": title, "why": f"{sum(c[k].values())} requests"})
    return rep


# ---------- recover: rebuild a wiped site from the DB / a dump ----------
RECOVER_DOC = """Rebuild WordPress core + plugins + themes from what the database still knows.

PHP files are NOT stored in the DB. After a wipe you can only:
  - re-download matching versions from wordpress.org
  - restore custom/premium code and uploads/ from a backup

Live MySQL:
  uv run wpguard.py recover --db harmoniq --user dbuser --password 'PASS' --host 127.0.0.1 --out site

From a dump (no MySQL on this host):
  uv run wpguard.py recover --dump /home/tmp-harmoniq.sql --db harmoniq --user dbuser --password 'PASS' --host mysql --out site --list
  uv run wpguard.py recover --dump /home/tmp-harmoniq.sql --db harmoniq --user dbuser --password 'PASS' --host mysql --out site
"""
CTX = ssl.create_default_context()
UA = "wp-recover/2.0 (+https://wordpress.org; local incident recovery)"

DB_VERSION_HINT = {
    36686: "4.8",
    38590: "4.9",
    43764: "5.0",
    44719: "5.1",
    45805: "5.3",
    47018: "5.4",
    48748: "5.5",
    49752: "5.6",
    51917: "5.9",
    53496: "6.1",
    55853: "6.3",
    56657: "6.4",
    57155: "6.5",
    58975: "6.7",
    60421: "6.8",
    60717: "6.9",
    61212: "7.0",
    61833: "7.1",
}

MALWARE_NEEDLES = (
    "eval(",
    "assert(",
    "base64_decode",
    "gzinflate",
    "gzuncompress",
    "str_rot13",
    "shell_exec",
    "passthru(",
    "system(",
    "preg_replace",
    "create_function",
    "FilesMan",
    "wso hidden",
    "c99shell",
    "wp-tmp.php",
    "chr(101).chr(118)",
)

BACKUP_NEEDLES = (
    "updraft",
    "backupbuddy",
    "backwpup",
    "ai1wm",
    "wpvivid",
    "duplicator",
    "blogvault",
    "jetpack_backup",
    "snapshot",
    "wp_all_backup",
    "xcloner",
    "all-in-one-wp-migration",
)

KEEP_SUFFIXES = ("options", "users", "usermeta", "sitemeta", "blogs", "site")
DEFAULT_COLS = {
    "options": ["option_id", "option_name", "option_value", "autoload"],
    "users": [
        "ID",
        "user_login",
        "user_pass",
        "user_nicename",
        "user_email",
        "user_url",
        "user_registered",
        "user_activation_key",
        "user_status",
        "display_name",
    ],
    "usermeta": ["umeta_id", "user_id", "meta_key", "meta_value"],
    "sitemeta": ["meta_id", "site_id", "meta_key", "meta_value"],
    "blogs": [
        "blog_id",
        "site_id",
        "domain",
        "path",
        "registered",
        "last_updated",
        "public",
        "archived",
        "mature",
        "spam",
        "deleted",
        "lang_id",
    ],
}
INSERT_HEAD = re.compile(
    r"^(?:INSERT|REPLACE)(?:\s+IGNORE)?\s+INTO\s+(?:`[^`]+`\.)?`?([A-Za-z0-9_]+)`?\s*"
    r"(?:\((.*?)\)\s*)?VALUES\s*",
    re.I | re.S,
)
TABLE_HEAD = re.compile(
    r"^(?:INSERT|REPLACE)(?:\s+IGNORE)?\s+INTO\s+(?:`[^`]+`\.)?`?([A-Za-z0-9_]+)`?",
    re.I,
)
UNESCAPE = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "Z": "\x1a",
    "b": "\b",
}


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def as_text(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return str(v)


def php_unser(raw) -> object:
    """Minimal PHP unserialize (N b i d s a). Objects/garbage -> {}."""
    s = as_text(raw)
    if not s:
        return {}
    buf = s.encode("utf-8")  # PHP string lengths are in bytes

    def val(i):
        t = buf[i : i + 1]
        if t == b"N":
            return None, i + 2
        if t in (b"b", b"i", b"d"):
            j = buf.index(b";", i)
            x = buf[i + 2 : j]
            return (x == b"1" if t == b"b" else int(x) if t == b"i" else float(x)), j + 1
        c = buf.index(b":", i + 2)
        n = int(buf[i + 2 : c])
        if t == b"s":
            return buf[c + 2 : c + 2 + n].decode("utf-8", "replace"), c + 2 + n + 2
        if t != b"a":
            raise ValueError(t)
        i, out = c + 2, {}
        for _ in range(n):
            k, i = val(i)
            out[k], i = val(i)
        return out, i + 1

    try:
        return val(0)[0]
    except (ValueError, IndexError):
        return {}


def php_map(raw) -> dict:
    v = php_unser(raw)
    return v if isinstance(v, dict) else {}


def ident(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", name or ""):
        die(f"unsafe SQL identifier: {name!r}")
    return name


def get_url(url: str, retries: int = 3) -> bytes | None:
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=120, context=CTX) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
        except Exception as e:
            last = e
        if i < retries - 1:
            print(f"    retry {i + 2}/{retries}  {url}")
    if last:
        print(f"    download failed: {url}  ({last})")
    return None


def recover_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="wpguard recover",
        description=RECOVER_DOC,
    )
    p.add_argument("--db", default="", help="database name (also written into wp-config.php)")
    p.add_argument("--user", default="", help="MySQL user (wp-config.php)")
    p.add_argument("--password", default="")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=3306)
    p.add_argument("--socket", default="")
    p.add_argument("--dump", default="", help="read .sql / .sql.gz instead of connecting")
    p.add_argument("--prefix", default="", help="table prefix, e.g. wp_. empty = autodetect")
    p.add_argument("--out", default="site", help="web root to write (wp-config.php lives here)")
    p.add_argument("--wp-version", default="", help="override core version")
    p.add_argument("--list", action="store_true", help="print inventory + audit, do not download")
    p.add_argument("--force", action="store_true", help="write into a non-empty --out directory")
    p.add_argument("--latest-core", action="store_true", help="install current wordpress.org core")
    return p.parse_args(argv)


# --- SQL dump reader ---------------------------------------------------------


def open_dump(path: str):
    p = pathlib.Path(path)
    if not p.is_file():
        die(f"dump not found: {p}")
    if p.suffix == ".gz" or p.name.endswith(".sql.gz"):
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, "r", encoding="utf-8", errors="replace")


def keep_table(name: str) -> bool:
    return any(name.endswith(suf) and (name == suf or name[-len(suf) - 1] == "_") for suf in KEEP_SUFFIXES)


def table_kind(name: str) -> str | None:
    for suf in KEEP_SUFFIXES:
        if name.endswith(suf) and (name == suf or name[len(name) - len(suf) - 1 : len(name) - len(suf)] == "_"):
            return suf
    return None


def classify_head(head: str) -> str | None:
    s = head.lstrip("\ufeff \t\r\n")
    m = TABLE_HEAD.match(s)
    if not m:
        return None
    return m.group(1)


def iter_kept_inserts(fp):
    """Yield INSERT/REPLACE statements for options/users/usermeta/sitemeta/blogs."""
    buf: list[str] = []
    in_str = False
    esc = False
    skipping = False
    classified = False

    def reset():
        nonlocal buf, skipping, classified, in_str, esc
        buf = []
        skipping = False
        classified = False
        in_str = False
        esc = False

    while True:
        chunk = fp.read(256 * 1024)
        if not chunk:
            break
        i = 0
        while i < len(chunk):
            ch = chunk[i]
            if skipping:
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == "'":
                        in_str = False
                elif ch == "'":
                    in_str = True
                elif ch == ";":
                    reset()
                i += 1
                continue
            buf.append(ch)
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == "'":
                    in_str = False
            else:
                if ch == "'":
                    in_str = True
                elif ch == ";":
                    stmt = "".join(buf).strip()
                    reset()
                    if stmt:
                        yield stmt
                    i += 1
                    continue
                elif not classified and len(buf) >= 80:
                    head = "".join(buf[:240])
                    t = classify_head(head)
                    if t is not None:
                        classified = True
                        if not keep_table(t):
                            skipping = True
                            buf = []
            i += 1
    tail = "".join(buf).strip()
    if tail:
        yield tail


def parse_sql_string(s: str, i: int) -> tuple[str, int]:
    n = len(s)
    i += 1
    out: list[str] = []
    while i < n:
        ch = s[i]
        if ch == "\\" and i + 1 < n:
            out.append(UNESCAPE.get(s[i + 1], s[i + 1]))
            i += 2
            continue
        if ch == "'":
            if i + 1 < n and s[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            return "".join(out), i + 1
        out.append(ch)
        i += 1
    return "".join(out), i


def parse_hex(s: str, i: int) -> tuple[str, int]:
    n = len(s)
    if s.startswith("0x", i) or s.startswith("0X", i):
        j = i + 2
        while j < n and s[j] in "0123456789abcdefABCDEF":
            j += 1
        blob = bytes.fromhex(s[i + 2 : j] or "")
        return blob.decode("utf-8", "replace"), j
    if (s[i] in "xX") and i + 1 < n and s[i + 1] == "'":
        j = i + 2
        while j < n and s[j] != "'":
            j += 1
        blob = bytes.fromhex(s[i + 2 : j] or "")
        return blob.decode("utf-8", "replace"), j + 1
    raise ValueError("not hex")


def parse_rows(values_sql: str) -> list[list]:
    rows: list[list] = []
    i = 0
    n = len(values_sql)
    while i < n:
        while i < n and values_sql[i] in " \t\r\n,":
            i += 1
        if i >= n or values_sql[i] == ";":
            break
        if values_sql[i] != "(":
            break
        i += 1
        row: list = []
        while i < n:
            while i < n and values_sql[i] in " \t\r\n":
                i += 1
            if i >= n:
                break
            if values_sql.startswith("NULL", i) and (i + 4 == n or values_sql[i + 4] in ",)"):
                row.append(None)
                i += 4
            elif values_sql.startswith("null", i) and (i + 4 == n or values_sql[i + 4] in ",)"):
                row.append(None)
                i += 4
            elif values_sql[i] == "'":
                val, i = parse_sql_string(values_sql, i)
                row.append(val)
            elif values_sql.startswith(("0x", "0X"), i) or (
                values_sql[i] in "xX" and i + 1 < n and values_sql[i + 1] == "'"
            ):
                val, i = parse_hex(values_sql, i)
                row.append(val)
            else:
                j = i
                while j < n and values_sql[j] not in ",)":
                    j += 1
                tok = values_sql[i:j].strip()
                row.append(tok)
                i = j
            while i < n and values_sql[i] in " \t\r\n":
                i += 1
            if i < n and values_sql[i] == ",":
                i += 1
                continue
            if i < n and values_sql[i] == ")":
                i += 1
                break
        rows.append(row)
    return rows


def parse_insert(stmt: str):
    s = stmt.strip().rstrip(";").strip()
    m = INSERT_HEAD.match(s)
    if not m:
        return None
    table, cols_raw = m.group(1), m.group(2)
    cols = None
    if cols_raw:
        cols = [c.strip().strip("`") for c in cols_raw.split(",") if c.strip()]
    rows = parse_rows(s[m.end() :])
    return table, cols, rows


class DumpWP:
    def __init__(self, prefix: str, tables: set[str], options: dict, sitemeta: dict, users: list, usermeta: dict, blogs: list[int]):
        self.p = ident(prefix)
        self.tables = tables
        self.multisite = f"{self.p}blogs" in tables and f"{self.p}sitemeta" in tables
        self.options = options  # prefix -> {name: value}
        self.sitemeta = sitemeta
        self.users = users
        self.usermeta = usermeta  # prefix -> [(user_id, key, value)]
        self._blogs = blogs

    def opt(self, name: str, blog_prefix: str | None = None) -> str | None:
        p = blog_prefix or self.p
        v = self.options.get(p, {}).get(name)
        return as_text(v) if v is not None else None

    def site_opt(self, name: str) -> str | None:
        if name in self.sitemeta:
            return as_text(self.sitemeta[name])
        return self.opt(name)

    def blog_prefixes(self) -> list[str]:
        if not self.multisite:
            return [self.p]
        out = []
        for bid in self._blogs or [1]:
            out.append(self.p if int(bid) == 1 else f"{self.p}{int(bid)}_")
        return out or [self.p]


def load_dump(path: str, wanted_prefix: str) -> DumpWP:
    print(f"reading dump {path} ...")
    tables: set[str] = set()
    options: dict[str, dict[str, str]] = {}
    sitemeta: dict[str, str] = {}
    users: list[dict] = []
    usermeta: dict[str, list[tuple]] = {}
    blogs: list[int] = []
    with open_dump(path) as fp:
        for stmt in iter_kept_inserts(fp):
            parsed = parse_insert(stmt)
            if not parsed:
                continue
            table, cols, rows = parsed
            tables.add(table)
            kind = table_kind(table)
            if kind is None:
                continue
            if not cols:
                cols = DEFAULT_COLS.get(kind)
            if not cols:
                continue
            cmap = {c: i for i, c in enumerate(cols)}
            if kind == "options":
                prefix = table[: -len("options")]
                bucket = options.setdefault(prefix, {})
                ni, vi = cmap.get("option_name"), cmap.get("option_value")
                if ni is None or vi is None:
                    continue
                for row in rows:
                    if max(ni, vi) >= len(row):
                        continue
                    name = as_text(row[ni])
                    if name:
                        bucket[name] = as_text(row[vi]) or ""
            elif kind == "sitemeta":
                ki, vi = cmap.get("meta_key"), cmap.get("meta_value")
                if ki is None or vi is None:
                    continue
                for row in rows:
                    if max(ki, vi) >= len(row):
                        continue
                    k = as_text(row[ki])
                    if k:
                        sitemeta[k] = as_text(row[vi]) or ""
            elif kind == "users":
                for row in rows:
                    def col(n, default=None):
                        i = cmap.get(n)
                        return row[i] if i is not None and i < len(row) else default

                    users.append(
                        {
                            "id": int(col("ID") or 0),
                            "login": as_text(col("user_login")) or "",
                            "email": as_text(col("user_email")) or "",
                            "registered": as_text(col("user_registered")) or "",
                        }
                    )
            elif kind == "usermeta":
                prefix = table[: -len("usermeta")]
                bucket = usermeta.setdefault(prefix, [])
                ui, ki, vi = cmap.get("user_id"), cmap.get("meta_key"), cmap.get("meta_value")
                if None in (ui, ki, vi):
                    continue
                for row in rows:
                    if max(ui, ki, vi) >= len(row):
                        continue
                    bucket.append((row[ui], as_text(row[ki]) or "", as_text(row[vi]) or ""))
            elif kind == "blogs":
                bi = cmap.get("blog_id")
                if bi is None:
                    continue
                for row in rows:
                    if bi < len(row):
                        try:
                            blogs.append(int(row[bi]))
                        except (TypeError, ValueError):
                            pass
    prefixes = [p for p in options if p + "options" in tables or p in options]
    if wanted_prefix:
        ident(wanted_prefix)
        if wanted_prefix not in options and wanted_prefix + "options" not in tables:
            die(f"no {wanted_prefix}options in dump. prefixes={list(options)}")
        prefix = wanted_prefix
    elif "wp_" in options:
        prefix = "wp_"
    elif len(options) == 1:
        prefix = next(iter(options))
    elif options:
        die(f"several prefixes {list(options)}; pass --prefix")
    else:
        die("no options table in dump. is this a WordPress dump?")
    print(f"  dump tables kept: {sorted(tables)[:12]}{' ...' if len(tables) > 12 else ''}")
    return DumpWP(prefix, tables, options, sitemeta, users, usermeta, blogs)


# --- live MySQL --------------------------------------------------------------


def connect(a: argparse.Namespace):
    import pymysql

    kw = dict(user=a.user, password=a.password, database=a.db, charset="utf8mb4")
    if a.socket:
        kw["unix_socket"] = a.socket
    else:
        kw["host"] = a.host
        kw["port"] = a.port
    try:
        return pymysql.connect(**kw)
    except pymysql.Error as e:
        die(f"MySQL connect failed: {e}")


def detect_prefix(cur, db: str, wanted: str) -> str:
    cur.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema=%s AND table_name LIKE %s",
        (db, "%options"),
    )
    names = [r[0] for r in cur.fetchall()]
    if wanted:
        ident(wanted)
        if f"{wanted}options" in names:
            return wanted
        die(f"no {wanted}options table in {db}. found: {names or 'none'}")
    candidates = [n[: -len("options")] for n in names if n.endswith("options")]
    if "wp_" in candidates:
        return "wp_"
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        die(f"no options table in {db}. is this a WordPress dump?")
    die(f"several prefixes {candidates}; pass --prefix")


class MysqlWP:
    def __init__(self, cur, prefix: str, tables: set[str]):
        self.cur = cur
        self.p = ident(prefix)
        self.tables = tables
        self.multisite = f"{self.p}blogs" in tables and f"{self.p}sitemeta" in tables

    def q(self, sql: str, args=()):
        self.cur.execute(sql, args)
        return self.cur.fetchall()

    def opt(self, name: str, blog_prefix: str | None = None) -> str | None:
        p = ident(blog_prefix or self.p)
        rows = self.q(f"SELECT option_value FROM `{p}options` WHERE option_name=%s LIMIT 1", (name,))
        return as_text(rows[0][0]) if rows else None

    def site_opt(self, name: str) -> str | None:
        if self.multisite:
            rows = self.q(
                f"SELECT meta_value FROM `{self.p}sitemeta` WHERE meta_key=%s ORDER BY site_id LIMIT 1",
                (name,),
            )
            if rows:
                return as_text(rows[0][0])
        return self.opt(name)

    def blog_prefixes(self) -> list[str]:
        if not self.multisite:
            return [self.p]
        rows = self.q(f"SELECT blog_id FROM `{self.p}blogs` ORDER BY blog_id")
        out = []
        for (bid,) in rows:
            out.append(self.p if int(bid) == 1 else f"{self.p}{int(bid)}_")
        return out or [self.p]


# --- inventory ---------------------------------------------------------------


def core_version(src, override: str) -> str | None:
    if override:
        return override
    raw = src.site_opt("_site_transient_update_core") or src.opt("_transient_update_core") or ""
    data = php_map(raw)
    for key in ("version_checked", "current"):
        v = data.get(key)
        if v:
            return str(v)
    m = re.search(r'version_checked";s:\d+:"([^"]+)"', raw)
    if m:
        return m.group(1)
    return None


def merge_checked(raw: str | None) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    data = php_map(raw)
    checked = data.get("checked")
    if isinstance(checked, dict):
        for k, v in checked.items():
            key = as_text(k) or ""
            if key:
                out[key] = as_text(v) if v not in (None, False) else None
    if not out and raw:
        for k, v in re.findall(r's:\d+:"([^"]+)";s:\d+:"([0-9][0-9a-zA-Z._-]*)"', raw):
            if "/" in k or k.endswith(".php") or re.fullmatch(r"[a-z0-9-]+", k):
                out.setdefault(k, v)
    return out


def collect_plugins(src) -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    raw = src.site_opt("_site_transient_update_plugins") or src.opt("_transient_update_plugins")
    found.update(merge_checked(raw))
    for bp in src.blog_prefixes():
        for name in ("active_plugins", "recently_activated", "uninstall_plugins"):
            vals = php_map(src.opt(name, bp))
            for k, v in vals.items():
                item = v if isinstance(v, (str, bytes)) else k
                path = as_text(item) or ""
                if path.endswith(".php"):
                    found.setdefault(path, None)
        if bp == src.p:
            sitewide = php_map(src.site_opt("active_sitewide_plugins"))
            for k in sitewide:
                path = as_text(k) or ""
                if path.endswith(".php"):
                    found.setdefault(path, None)
    return found


def collect_themes(src) -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    raw = src.site_opt("_site_transient_update_themes") or src.opt("_transient_update_themes")
    found.update(merge_checked(raw))
    for bp in src.blog_prefixes():
        for name in ("template", "stylesheet"):
            slug = src.opt(name, bp)
            if slug:
                found.setdefault(slug, None)
        allowed = php_map(src.opt("allowedthemes", bp))
        for k, v in allowed.items():
            if v:
                found.setdefault(as_text(k) or "", None)
    found.pop("", None)
    return found


def suspicious_paths(paths: list[str]) -> list[str]:
    bad = []
    for p in paths:
        s = p.lower()
        if (
            (s.endswith(".php") and "/" not in s and s not in {"hello.php"})
            or ".." in s
            or s.startswith(("http://", "https://", "php://", "data:"))
            or "/uploads/" in s
            or s.startswith(("wp-tmp", "tmp", "cache-"))
            or re.search(r"[0-9a-f]{16,}", s)
        ):
            bad.append(p)
    return bad


def db_audit(src) -> dict:
    report: dict = {"admins": [], "malware_options": [], "backup_options": [], "cron_hooks": [], "users_recent": []}
    if isinstance(src, DumpWP):
        by_id = {u["id"]: u for u in src.users}
        for bp in src.blog_prefixes():
            cap = f"{bp}capabilities"
            for uid, key, val in src.usermeta.get(bp, []):
                try:
                    user_id = int(uid)
                except (TypeError, ValueError):
                    continue
                if key == cap and "administrator" in (val or "").lower():
                    u = by_id.get(user_id, {"id": user_id, "login": "?", "email": "?", "registered": "?"})
                    report["admins"].append(
                        {"prefix": bp, "id": u["id"], "login": u["login"], "email": u["email"], "registered": u["registered"]}
                    )
            for name, val in src.options.get(bp, {}).items():
                low = name.lower()
                if any(x in low for x in BACKUP_NEEDLES):
                    report["backup_options"].append(name)
                blob = val or ""
                if any(n in blob for n in MALWARE_NEEDLES):
                    report["malware_options"].append(name)
            cron = php_map(src.opt("cron", bp))
            hooks = []
            for _ts, events in cron.items():
                if isinstance(events, dict):
                    hooks.extend(str(h) for h in events)
            report["cron_hooks"].extend(sorted(set(hooks))[:80])
        report["users_recent"] = sorted(src.users, key=lambda u: u.get("registered") or "", reverse=True)[:15]
        return report

    import pymysql

    for bp in src.blog_prefixes():
        cap = f"{bp}capabilities"
        try:
            rows = src.q(
                f"SELECT u.ID, u.user_login, u.user_email, u.user_registered "
                f"FROM `{src.p}users` u "
                f"JOIN `{bp}usermeta` m ON m.user_id=u.ID "
                f"WHERE m.meta_key=%s AND m.meta_value LIKE %s",
                (cap, "%administrator%"),
            )
            for r in rows:
                report["admins"].append(
                    {"prefix": bp, "id": r[0], "login": as_text(r[1]), "email": as_text(r[2]), "registered": str(r[3])}
                )
        except pymysql.Error:
            pass
        try:
            rows = src.q(
                f"SELECT option_name FROM `{bp}options` "
                f"WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s "
                f"OR option_name LIKE %s OR option_name LIKE %s LIMIT 80",
                ("%updraft%", "%backup%", "%wpvivid%", "%ai1wm%", "%duplicator%"),
            )
            for (n,) in rows:
                n = as_text(n) or ""
                if any(x in n.lower() for x in BACKUP_NEEDLES):
                    report["backup_options"].append(n)
        except pymysql.Error:
            pass
        try:
            rows = src.q(
                f"SELECT option_name FROM `{bp}options` WHERE "
                + " OR ".join(["option_value LIKE %s"] * len(MALWARE_NEEDLES))
                + " LIMIT 50",
                tuple(f"%{n}%" for n in MALWARE_NEEDLES),
            )
            for (n,) in rows:
                report["malware_options"].append(as_text(n))
        except pymysql.Error:
            pass
        cron = php_map(src.opt("cron", bp))
        hooks = []
        for _ts, events in cron.items():
            if isinstance(events, dict):
                hooks.extend(str(h) for h in events)
        report["cron_hooks"].extend(sorted(set(hooks))[:80])
    try:
        rows = src.q(
            f"SELECT ID, user_login, user_email, user_registered FROM `{src.p}users` "
            f"ORDER BY user_registered DESC LIMIT 15"
        )
        for r in rows:
            report["users_recent"].append(
                {"id": r[0], "login": as_text(r[1]), "email": as_text(r[2]), "registered": str(r[3])}
            )
    except pymysql.Error:
        pass
    return report


def write_wp_config(site: pathlib.Path, a: argparse.Namespace, prefix: str) -> None:
    salts = get_url("https://api.wordpress.org/secret-key/1.1/salt/")
    salt_txt = (salts or b"").decode("utf-8", "replace").strip()
    if not salt_txt:
        salt_txt = "\n".join(
            f"define('{k}', 'change-me-{i}');"
            for i, k in enumerate(
                [
                    "AUTH_KEY",
                    "SECURE_AUTH_KEY",
                    "LOGGED_IN_KEY",
                    "NONCE_KEY",
                    "AUTH_SALT",
                    "SECURE_AUTH_SALT",
                    "LOGGED_IN_SALT",
                    "NONCE_SALT",
                ]
            )
        )
        print("  !! could not fetch salts; placeholders written — replace them")
    if a.socket:
        host = a.socket
    elif a.port != 3306:
        host = f"{a.host}:{a.port}"
    else:
        host = a.host
    db = a.db or "DATABASE"
    user = a.user or "USER"
    (site / "wp-config.php").write_text(
        f"""<?php
define('DB_NAME', '{db}');
define('DB_USER', '{user}');
define('DB_PASSWORD', '{a.password}');
define('DB_HOST', '{host}');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

{salt_txt}

$table_prefix = '{prefix}';

define('WP_DEBUG', false);
define('DISALLOW_FILE_EDIT', true);
if (!defined('ABSPATH')) {{
    define('ABSPATH', __DIR__ . '/');
}}
require_once ABSPATH . 'wp-settings.php';
""",
        encoding="utf-8",
    )


def extract_core(blob: bytes, dest: pathlib.Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for info in z.infolist():
            name = info.filename
            if name.endswith("/"):
                continue
            if not name.startswith("wordpress/"):
                die(f"unexpected core zip member: {name}")
            rel = name[len("wordpress/") :]
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                out.write(src.read())


def hint_from_db_version(v: str | None) -> str | None:
    if not v or not str(v).isdigit():
        return None
    n = int(v)
    best = None
    for dbv, wpv in DB_VERSION_HINT.items():
        if dbv <= n:
            best = wpv
    return best


def fetch_zip(kind: str, slug: str, ver: str | None, dest: pathlib.Path) -> str:
    base = f"https://downloads.wordpress.org/{kind}/{slug}"
    data, status = None, "missing"
    if ver:
        data = get_url(f"{base}.{ver}.zip")
        if data:
            status = "ok"
    if not data:
        data = get_url(f"{base}.zip")
        if data:
            status = "latest"
    if not data:
        print(f"  MISSING  {kind:6} {slug} {ver or '?'}  (premium/custom — need a backup or vendor zip)")
        return "missing"
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(dest)
    note = "" if status == "ok" else "  !! exact version not on src.org -> LATEST"
    print(f"  {status:7} {kind:6} {slug} {ver or '?'}{note}")
    return status


def print_inventory(inv: dict, report: dict, plugins: dict, themes: dict, shady: list[str]) -> None:
    print(f"site:      {inv['siteurl'] or '?'}")
    print(f"home:      {inv['home'] or '?'}")
    print(f"name:      {inv['blogname'] or '?'}")
    print(f"prefix:    {inv['table_prefix']}   multisite={inv['multisite']}")
    print(f"core:      {inv['wordpress'] or 'UNKNOWN'}   db_version={inv['db_version']}   hint={inv['db_version_hint'] or '?'}")
    print(f"theme:     template={inv['template']}  stylesheet={inv['stylesheet']}")
    print(f"plugins:   {len(plugins)}")
    for path, ver in sorted(plugins.items()):
        mark = "  SUSPICIOUS" if path in shady else ""
        print(f"  - {path}  {ver or '(version unknown -> latest)'}{mark}")
    print(f"themes:    {len(themes)}")
    for slug, ver in sorted(themes.items()):
        print(f"  - {slug}  {ver or '(version unknown -> latest)'}")
    print("\nAdministrators (drop any you do not recognise):")
    for u in report["admins"]:
        print(f"  id={u['id']}  {u['login']}  {u['email']}  registered={u['registered']}  ({u['prefix']})")
    if not report["admins"]:
        print("  (none found — check --prefix / usermeta)")
    print("\nNewest users:")
    for u in report["users_recent"]:
        print(f"  id={u['id']}  {u['login']}  {u['email']}  {u['registered']}")
    if report["backup_options"]:
        print("\nBackup-plugin options (you may still have a file backup offsite):")
        for n in sorted(set(report["backup_options"]))[:40]:
            print(f"  {n}")
    if report["malware_options"]:
        print("\nOptions whose values look like injected PHP (inspect, do not blindly delete):")
        for n in sorted(set(report["malware_options"]))[:40]:
            print(f"  {n}")
    if shady:
        print("\nSuspicious active/installed plugin paths (typical webshell leftovers):")
        for pth in shady:
            print(f"  {pth}")


def recover_main(argv: list[str]) -> None:
    a = recover_args(argv)
    if not a.dump and (not a.db or not a.user):
        die("need --db and --user, or --dump dump.sql\nexample:\n  uv run wpguard.py recover --dump /home/tmp-harmoniq.sql --db harmoniq --user dbuser --password 'PASS' --host mysql --out site --list")

    if a.dump:
        src = load_dump(a.dump, a.prefix)
        prefix = src.p
    else:
        conn = connect(a)
        cur = conn.cursor()
        prefix = detect_prefix(cur, a.db, a.prefix)
        cur.execute("SHOW TABLES")
        tables = {as_text(r[0]) for r in cur.fetchall() if r[0]}
        src = MysqlWP(cur, prefix, tables)

    siteurl = src.opt("siteurl") or src.site_opt("siteurl")
    home = src.opt("home")
    blogname = src.opt("blogname")
    dbv = src.opt("db_version")
    lang = src.opt("WPLANG") or src.opt("wplang")
    template = src.opt("template")
    stylesheet = src.opt("stylesheet")
    core = core_version(src, a.wp_version)
    if a.latest_core:
        core = "latest"
    plugins = collect_plugins(src)
    themes = collect_themes(src)
    report = db_audit(src)
    hint = hint_from_db_version(dbv)
    shady_plugins = suspicious_paths(list(plugins))

    inventory = {
        "siteurl": siteurl,
        "home": home,
        "blogname": blogname,
        "table_prefix": prefix,
        "multisite": src.multisite,
        "db_version": dbv,
        "db_version_hint": hint,
        "wordpress": core,
        "language": lang,
        "template": template,
        "stylesheet": stylesheet,
        "plugins": plugins,
        "themes": themes,
        "suspicious_plugin_paths": shady_plugins,
        "admins": report["admins"],
        "recent_users": report["users_recent"],
        "backup_options": sorted(set(report["backup_options"])),
        "malware_like_options": sorted(set(report["malware_options"])),
        "cron_hooks": sorted(set(report["cron_hooks"]))[:80],
        "not_in_db": [
            "PHP files (core/plugins/themes code)",
            "wp-content/uploads (images, PDFs, videos)",
            "custom / premium / nulled plugins and themes",
            "mu-plugins, drop-ins, .htaccess",
        ],
    }
    print_inventory(inventory, report, plugins, themes, shady_plugins)

    if not core and not a.list:
        die(
            "no core version in DB. pass --wp-version 6.4.2 (see db_version hint) "
            "or --latest-core. https://wordpress.org/download/releases/"
        )

    dest = pathlib.Path(a.out).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "recovery-inventory.json").write_text(json.dumps(inventory, indent=2, default=str), encoding="utf-8")

    if a.list:
        print(f"\nWrote {dest / 'recovery-inventory.json'}")
        print("PHP is not in the database. Re-run without --list to download core/plugins/themes.")
        return

    if any(p.name != "recovery-inventory.json" for p in dest.iterdir()) and not a.force:
        die(f"{dest} is not empty. pick another --out or pass --force")

    print("\nDownloading WordPress core...")
    if core == "latest":
        blob = get_url("https://wordpress.org/latest.zip")
        core_label = "latest"
    else:
        blob = get_url(f"https://wordpress.org/wordpress-{core}.zip")
        core_label = core
        if not blob:
            print(f"  {core} missing on src.org, trying latest.zip")
            blob = get_url("https://wordpress.org/latest.zip")
            core_label = f"latest (wanted {core})"
    if not blob:
        die("could not download WordPress core")
    extract_core(blob, dest)
    print(f"  ok      core   wordpress {core_label}")

    print("\nDownloading plugins...")
    plug_dest = dest / "wp-content" / "plugins"
    for path, ver in sorted(plugins.items()):
        if path in shady_plugins:
            print(f"  skip    plugin {path}  (suspicious path, not fetched)")
            continue
        if "/" not in path:
            print(f"  skip    plugin {path}  (single-file; hello.php ships with core)")
            continue
        fetch_zip("plugin", path.split("/")[0], ver, plug_dest)

    print("\nDownloading themes...")
    theme_dest = dest / "wp-content" / "themes"
    for slug, ver in sorted(themes.items()):
        fetch_zip("theme", slug, ver, theme_dest)

    write_wp_config(dest, a, prefix)
    print(f"\nDone -> {dest}")
    print("Next:")
    print("  1. Restore wp-content/uploads from a backup (not in the DB).")
    print("  2. Install any MISSING premium/custom plugins/themes from the vendor.")
    print("  3. Point the vhost document root at this folder.")
    print("  4. Log in, delete unknown admins, change every password, then update everything.")
    print("  5. Inspect malware_like_options in recovery-inventory.json before going live.")
    print("New salts were written, so every cookie/session is invalid — that is intentional.")


# ---------- cli ----------
def write_report(path, reps):
    ext = Path(path).suffix
    if ext == ".json":
        txt = json.dumps([{"site": r.site, "hits": r.hits, "log": r.lines} for r in reps], indent=1)
    elif ext == ".html":
        txt = "<meta charset=utf-8><title>wpguard</title><body style='font:14px monospace'>" + "".join(
            f"<h2>{html.escape(r.site)} ({len(r.hits)} findings)</h2><pre>{html.escape(chr(10).join(r.lines))}</pre>" for r in reps)
    else:
        txt = "\n\n".join(f"### {r.site}\n" + "\n".join(r.lines) for r in reps)
    Path(path).write_text(txt)
    print("report ->", path)


def main():
    global LIVE
    if sys.argv[1:2] == ["recover"]:
        return recover_main(sys.argv[2:])
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["setup", "scan", "fix", "harden", "baseline", "watch", "logs", "restore", "audit", "recover"])
    ap.add_argument("sites", nargs="*")
    ap.add_argument("--sites-file")
    ap.add_argument("-j", type=int, default=1)
    ap.add_argument("--report")
    ap.add_argument("--notify", action="store_true")
    ap.add_argument("--sigs", help="file of extra regexes, one per line (maldet/Wordfence-style sets)")
    ap.add_argument("--since", type=int, help="flag PHP modified / admins created in the last N days")
    ap.add_argument("--no-net", action="store_true")
    ap.add_argument("--clean-db", action="store_true")
    ap.add_argument("--url")
    ap.add_argument("--format", choices=["md", "json"])
    ap.add_argument("--out")
    ap.add_argument("--lock", action="store_true")
    ap.add_argument("--prune", action="store_true")
    ap.add_argument("--delete-user", action="append")
    ap.add_argument("--log", action="append", default=[])
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--from", dest="src")
    a = ap.parse_args()
    selftest()
    if a.cmd == "setup":
        return setup()
    sites = a.sites + (Path(a.sites_file).read_text().split() if a.sites_file else [])
    LIVE = a.j == 1
    if a.cmd == "logs":
        reps = [logs(sites, a)]
    else:
        fn = {"scan": scan, "fix": fix, "harden": harden, "baseline": baseline, "watch": watch, "restore": restore, "audit": audit}[a.cmd]
        if not sites:
            sys.exit("give at least one SITE path")
        if a.cmd in ("scan", "fix", "harden", "restore", "audit") and (not WP.exists() or not shutil.which("php")):
            sys.exit("run `setup` first and install php")
        paths = [Path(s).resolve() for s in sites]
        bad = [p for p in paths if not (p / "wp-load.php").exists()]
        if bad:
            sys.exit(f"not WordPress roots: {bad}")
        with ThreadPoolExecutor(a.j) as ex:
            reps = list(ex.map(lambda p: fn(p, a), paths))
    if not LIVE:
        for r in reps:
            print("\n".join(r.lines))
    if a.cmd == "audit":
        fmt = a.format or ("json" if (a.out or "").endswith(".json") else "md")
        docs = [r.data for r in reps]
        txt = json.dumps(docs[0] if len(docs) == 1 else docs, indent=1) if fmt == "json" else "\n\n".join(map(audit_md, docs))
        if a.out:
            Path(a.out).write_text(txt)
            print("audit ->", a.out, file=sys.stderr)
        else:
            print(txt)
    if a.report:
        write_report(a.report, reps)
    bad = [r for r in reps if r.hits]
    if bad and a.notify and a.cmd in ("scan", "watch", "fix"):
        notify("\n".join(f"{r.site}: {len(r.hits)} findings\n" + "\n".join(f"- [{h['kind']}] {h['what']}: {h['why']}" for h in r.hits[:15]) for r in bad))
    sys.exit(1 if bad and a.cmd in ("scan", "watch") else 0)


if __name__ == "__main__":
    main()
