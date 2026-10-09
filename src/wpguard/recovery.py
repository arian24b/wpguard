"""Recovery handler: rebuild WordPress core + plugins + themes from what the database (or a dump) still knows."""

import argparse
import contextlib
import gzip
import io
import json
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.request
import zipfile


def need_pymysql():
    """Import pymysql lazily: only a live MySQL needs it (`pip install wpguard[mysql]`)."""
    try:
        import pymysql
    except ImportError:
        print("error: live MySQL needs pymysql: pip install 'wpguard[mysql]' (or use --dump)", file=sys.stderr)
        raise SystemExit(1) from None
    return pymysql


RECOVER_DOC = """Rebuild WordPress core + plugins + themes from what the database still knows.

PHP files are NOT stored in the DB. After a wipe you can only:
  - re-download matching versions from wordpress.org
  - restore custom/premium code and uploads/ from a backup

Live MySQL:
  wpguard recover --db harmoniq --user dbuser --password 'PASS' --host 127.0.0.1 --out site

From a dump (no MySQL on this host):
  wpguard recover --dump /home/tmp-harmoniq.sql --db harmoniq --user dbuser --password 'PASS' --host mysql --out site --list
  wpguard recover --dump /home/tmp-harmoniq.sql --db harmoniq --user dbuser --password 'PASS' --host mysql --out site
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
    re.IGNORECASE | re.DOTALL,
)
TABLE_HEAD = re.compile(
    r"^(?:INSERT|REPLACE)(?:\s+IGNORE)?\s+INTO\s+(?:`[^`]+`\.)?`?([A-Za-z0-9_]+)`?",
    re.IGNORECASE,
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
    except ValueError, IndexError:
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
        except Exception as e:  # noqa: BLE001  any network/TLS failure just means retry
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
    return open(p, encoding="utf-8", errors="replace")


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
            elif ch == "'":
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
            if (values_sql.startswith("NULL", i) and (i + 4 == n or values_sql[i + 4] in ",)")) or (
                values_sql.startswith("null", i) and (i + 4 == n or values_sql[i + 4] in ",)")
            ):
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
    def __init__(
        self,
        prefix: str,
        tables: set[str],
        options: dict,
        sitemeta: dict,
        users: list,
        usermeta: dict,
        blogs: list[int],
    ):
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
        out = [self.p if int(bid) == 1 else f"{self.p}{int(bid)}_" for bid in self._blogs or [1]]
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

                    def col(n, default=None, *, row=row, cmap=cmap):
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
                        with contextlib.suppress(TypeError, ValueError):
                            blogs.append(int(row[bi]))
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
    pymysql = need_pymysql()

    kw = {"user": a.user, "password": a.password, "database": a.db, "charset": "utf8mb4"}
    if a.socket:
        kw["unix_socket"] = a.socket
    else:
        kw["host"] = a.host
        kw["port"] = a.port
    try:
        return pymysql.connect(**kw)
    except pymysql.Error as e:
        die(f"MySQL connect failed: {e}")


def detect_prefix(cur, db: str, wanted: str) -> str:  # noqa: RET503  die() exits
    cur.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema=%s AND table_name LIKE %s",
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
            (s.endswith(".php") and "/" not in s and s != "hello.php")
            or ".." in s
            or s.startswith(("http://", "https://", "php://", "data:", "wp-tmp", "tmp", "cache-"))
            or "/uploads/" in s
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
                except TypeError, ValueError:
                    continue
                if key == cap and "administrator" in (val or "").lower():
                    u = by_id.get(user_id, {"id": user_id, "login": "?", "email": "?", "registered": "?"})
                    report["admins"].append(
                        {
                            "prefix": bp,
                            "id": u["id"],
                            "login": u["login"],
                            "email": u["email"],
                            "registered": u["registered"],
                        }
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
            for events in cron.values():
                if isinstance(events, dict):
                    hooks.extend(str(h) for h in events)
            report["cron_hooks"].extend(sorted(set(hooks))[:80])
        report["users_recent"] = sorted(src.users, key=lambda u: u.get("registered") or "", reverse=True)[:15]
        return report

    pymysql = need_pymysql()

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
            for (raw,) in rows:
                n = as_text(raw) or ""
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
        for events in cron.values():
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
    note = "" if status == "ok" else "  !! exact version not on wp.org -> LATEST"
    print(f"  {status:7} {kind:6} {slug} {ver or '?'}{note}")
    return status


def print_inventory(inv: dict, report: dict, plugins: dict, themes: dict, shady: list[str]) -> None:
    print(f"site:      {inv['siteurl'] or '?'}")
    print(f"home:      {inv['home'] or '?'}")
    print(f"name:      {inv['blogname'] or '?'}")
    print(f"prefix:    {inv['table_prefix']}   multisite={inv['multisite']}")
    print(
        f"core:      {inv['wordpress'] or 'UNKNOWN'}   db_version={inv['db_version']}   hint={inv['db_version_hint'] or '?'}"
    )
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
        die(
            "need --db and --user, or --dump dump.sql\nexample:\n  wpguard recover --dump /home/tmp-harmoniq.sql --db harmoniq --user dbuser --password 'PASS' --host mysql --out site --list"
        )

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
            print(f"  {core} missing on wp.org, trying latest.zip")
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
