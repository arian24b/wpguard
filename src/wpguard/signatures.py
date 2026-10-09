"""Signatures, hash databases and the per-file verdict (`judge`) plus the detector bundle built from CLI flags."""

import gzip
import hashlib
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from wpguard import feeds

PHP_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".inc", ".suspected"}

# Heuristic webshell/backdoor patterns; expect false positives in obfuscated commercial plugins.
SIG = re.compile(
    rb"""(?isx)
    eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|stripslashes\s*\(\s*\$_)
  | (system|shell_exec|passthru|exec|popen|proc_open|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
  | \$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\(
  | preg_replace\s*\(\s*['"]/[^'"]*/e['"]
  | (create_function|call_user_func(_array)?)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
  | file_put_contents\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)
  | FilesMan | c99shell | r57shell | b374k | IndoXploit | WSO\s*[0-9.]* | Web\s*Shell | Priv8
  | [A-Za-z0-9+/=]{600,}
"""
)
CFG_BAD = re.compile(
    rb"eval\s*\(|base64_decode|gzinflate|str_rot13|auto_prepend_file|\$_(?:GET|POST|REQUEST|COOKIE)"
    rb"|(?:include|require)(?:_once)?[^;\n]*\.(?:ico|jpe?g|png|gif|txt|log|tmp)\b",
    re.IGNORECASE,
)
HT_BAD = re.compile(
    rb"RewriteRule[^\n]*https?://(?!%\{)|auto_(?:prepend|append)_file"
    rb"|(?:AddHandler|AddType)[^\n]*php[^\n]*\.(?:jpe?g|png|gif|ico|txt|html?|css|js)\b",
    re.IGNORECASE,
)
AUTO = re.compile(rb"auto_(?:prepend|append)_file", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
HASH_ALGO = {32: "md5", 40: "sha1", 64: "sha256"}


def judge(name: str, ext: str, in_up: bool, data: bytes, extra: re.Pattern | None) -> tuple[str, str] | None:
    """(kind, why) for one file, or None. kind: 'struct' = structurally wrong place/config, 'sig' = signature match."""
    if name == ".htaccess":
        if in_up:
            return "struct", "htaccess in uploads"
        if m := HT_BAD.search(data):
            return "struct", f"htaccess rule: {m.group(0)[:50]!r}"
    elif name in (".user.ini", "php.ini"):
        if AUTO.search(data):
            return "struct", "auto_prepend/append_file"
    elif name == "wp-config.php":
        if m := CFG_BAD.search(data):
            return "struct", f"wp-config suspicious: {m.group(0)[:50]!r}"
    elif in_up and (ext in PHP_EXT or b"<?php" in data):
        return "struct", "php code in uploads"
    elif ext in PHP_EXT and (m := SIG.search(data) or (extra and extra.search(data))):
        return "sig", f"signature: {m.group(0)[:40]!r}"
    return None


def compile_regex_files(paths: list[Path]) -> re.Pattern | None:
    """One regex per line (blank lines and #comments skipped; invalid regexes are dropped, never matching everything)."""
    parts = []
    for p in paths:
        for raw in Path(p).read_text(errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                re.compile(line)
            except re.error:
                continue
            parts.append(f"(?:{line})")
    return re.compile("|".join(parts).encode(), re.IGNORECASE) if parts else None


def load_hashdb(paths: list[Path | str]) -> dict[str, set[str]]:
    """Any file that contains hex md5/sha1/sha256 tokens: csv, tsv, txt, md5sum output, json, *.gz, ClamAV .hdb, sqlite."""
    db: dict[str, set[str]] = {"md5": set(), "sha1": set(), "sha256": set()}

    def feed(text: str) -> None:
        for h in HASH_RE.findall(text):
            db[HASH_ALGO[len(h)]].add(h.lower())

    for path in paths:
        p = Path(path)
        if p.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            for (t,) in con.execute("select name from sqlite_master where type='table'").fetchall():
                for row in con.execute(f'select * from "{t}"'):
                    feed(" ".join(str(c) for c in row if isinstance(c, (str, bytes)) and c))
        else:
            with (gzip.open if p.suffix == ".gz" else open)(p, "rt", errors="ignore") as fh:
                for line in fh:
                    feed(line)
    return db


def hash_match(p: Path, db: dict[str, set[str]]) -> str | None:
    with p.open("rb") as fh:
        for algo, known in db.items():
            if known:
                fh.seek(0)
                if hashlib.file_digest(fh, algo).hexdigest() in known:
                    return algo
    return None


@dataclass
class Detectors:
    """Everything the file scan needs, built once per run from CLI flags + cached feeds."""

    extra: re.Pattern | None = None
    bad: dict | None = None
    good: dict | None = None
    yara_rules: list[Path] = field(default_factory=list)
    behavior: int = 5  # score threshold, 0 = off
    ignore: list[str] = field(default_factory=list)


def build_detectors(a) -> Detectors:
    """Cached on the namespace so parallel sites share one build."""
    if (cached := getattr(a, "_det", None)) is not None:
        return cached
    use_feeds = not getattr(a, "no_feeds", False)
    regex_files = [Path(p) for p in a.sigs or []] + (feeds.files("regex") if use_feeds else [])
    bad_files = [*(a.hashdb or []), *(feeds.files("hash") if use_feeds else [])]
    det = Detectors(
        extra=compile_regex_files(regex_files),
        bad=load_hashdb(bad_files) if bad_files else None,
        good=load_hashdb(a.hashdb_good) if a.hashdb_good else None,
        yara_rules=[Path(p) for p in a.yara or []] + (feeds.yara_entries() if use_feeds else []),
        behavior=0 if a.no_behavior else a.behavior_threshold,
        ignore=list(a.ignore or []),
    )
    a._det = det  # noqa: SLF001
    return det
