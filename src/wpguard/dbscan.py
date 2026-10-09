"""Database checks: injected content, cleanup of injections, persistence (admins, cron, options)."""

import re
import time
from datetime import datetime

from wpguard import wpcli

DB_PAT = r"<script|<iframe|eval[(]|base64_decode|document[.]write|fromCharCode"  # [(] not \( : SQL eats backslashes
OK_HOSTS = [
    "googletagmanager.com",
    "google-analytics.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "facebook.net",
    "facebook.com",
    "fbcdn.net",
    "cloudflare.com",
    "cdnjs.cloudflare.com",
    "jsdelivr.net",
    "unpkg.com",
    "jquery.com",
    "youtube.com",
    "twitter.com",
    "wp.com",
    "wordpress.org",
    "w.org",
]
ODD_CRON = re.compile(r"eval|base64|shell|cmd|exec|http|^[a-z0-9]{10,}$", re.IGNORECASE)


def db_scan(site, rep) -> None:
    pre = wpcli.wp(site, "db", "prefix").stdout.strip()
    queries = {
        "posts": f"SELECT ID,post_type,post_title FROM {pre}posts WHERE post_content REGEXP '{DB_PAT}' AND post_status NOT IN ('trash','auto-draft')",
        "options": f"SELECT option_name FROM {pre}options WHERE option_value REGEXP '{DB_PAT}' AND option_name NOT LIKE '\\_transient%'",
    }
    for label, sql in queries.items():
        out = wpcli.wp(site, "db", "query", sql, "--skip-column-names").stdout.strip()
        if out:
            rep.hit("db", f"{len(out.splitlines())} {label}", "suspicious script/eval content")
            rep.log("    " + out[:2000].replace("\n", "\n    "))


def db_clean(site, rep, *, dry: bool) -> None:
    host = re.sub(r"^https?://(www\.)?|[/:].*$", "", wpcli.wp(site, "option", "get", "home").stdout.strip())
    ok = "|".join(map(re.escape, [host, *OK_HOSTS]))
    pats = [  # '#' is the regex delimiter, so patterns must not contain it
        rf"<script[^>]*\bsrc=[\"']?(?:https?:)?//(?!(?:[\w-]+\.)*(?:{ok})[/\"' >:])[^>]*>\s*</script>",
        r"<script[^>]*>[^<]*(?:eval\(|atob\(|fromCharCode|unescape\()[^<]*</script>",
        r"<iframe[^>]*(?:width=[\"']?[01][\"' >]|height=[\"']?[01][\"' >]|display:\s*none)[^>]*>\s*</iframe>",
    ]
    rep.log(f"== DB clean ({'DRY RUN, add --clean-db to apply' if dry else 'APPLYING'})")
    for pat in pats:
        r = wpcli.wp(
            site,
            "search-replace",
            pat,
            "",
            "--regex",
            "--regex-delimiter=#",
            "--regex-flags=is",
            "--skip-columns=guid",
            "--report-changed-only",
            *(["--dry-run"] if dry else []),
        )
        rep.log("  ", (r.stdout + r.stderr).strip().replace("\n", "\n   ") or "no matches")


def persistence(site, rep, a) -> None:
    cut = time.time() - (a.since or 30) * 86400
    admins = wpcli.jget(
        site,
        "user",
        "list",
        "--role=administrator",
        "--fields=ID,user_login,user_email,user_registered",
        "--format=json",
    )
    for u in admins:
        line = f"#{u['ID']} {u['user_login']} <{u['user_email']}> registered {u['user_registered']}"
        if datetime.fromisoformat(u["user_registered"]).timestamp() > cut:
            rep.hit("admin", line, "NEW administrator, verify (fix --delete-user ID)")
        else:
            rep.log("  [admin]", line)
    hooks = {e["hook"] for e in wpcli.jget(site, "cron", "event", "list", "--fields=hook", "--format=json")}
    for h in sorted(h for h in hooks if ODD_CRON.search(h)):
        rep.hit("cron", h, "odd-looking cron hook")
    for pl in wpcli.jget(site, "option", "get", "active_plugins", "--format=json"):
        if not (site / "wp-content/plugins" / pl).exists():
            rep.hit("option", pl, "active plugin file missing")
    if wpcli.wp(site, "option", "get", "default_role").stdout.strip() == "administrator":
        rep.hit("option", "default_role", "new users become administrators")
