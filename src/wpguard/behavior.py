"""Heuristic 'behavior' score for a PHP file: obfuscation, dangerous-call density, odd names/places, timestamps.

Signatures catch known shells; this catches the unknown ones. A score >= threshold is reported for review and is
never auto-quarantined unless `--aggressive` is given (heuristics have false positives).
"""

import math
import re
from collections import Counter

CALLS = [
    (re.compile(rb"\beval\s*\(", re.IGNORECASE), 3, "eval()"),
    (re.compile(rb"\bassert\s*\(\s*\$", re.IGNORECASE), 3, "assert($var)"),
    (re.compile(rb"\b(?:shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(", re.IGNORECASE), 3, "shell execution"),
    (re.compile(rb"\b(?:system|exec)\s*\(\s*\$", re.IGNORECASE), 3, "system/exec($var)"),
    (re.compile(rb"\b(?:gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(", re.IGNORECASE), 2, "decompress/rot13"),
    (re.compile(rb"\bbase64_decode\s*\(", re.IGNORECASE), 1, "base64_decode"),
    (re.compile(rb"\bcreate_function\s*\(", re.IGNORECASE), 2, "create_function"),
    (re.compile(rb"\bpreg_replace\s*\(\s*['\"][^'\"]*/[a-z]*e[a-z]*['\"]", re.IGNORECASE), 3, "preg_replace /e"),
    (re.compile(rb"\$\$\w+|\$\{\s*['\"]"), 2, "variable variables"),
    (re.compile(rb"\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"), 3, "dynamic call on request input"),
    (re.compile(rb"(?:\\x[0-9a-fA-F]{2}){8,}"), 3, "hex-escaped strings"),
    (re.compile(rb"(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){6,}", re.IGNORECASE), 3, "chr() chains"),
]
DOUBLE_EXT = re.compile(r"\.php\d?\.(?:jpe?g|png|gif|ico|txt|css|js)$|\.(?:jpe?g|png|gif|ico)\.php\d?$", re.IGNORECASE)
KNOWN_BAD_NAMES = {"wp-vcd.php", "wp-tmp.php", "wp-feed.php", "xmrlpc.php", "class.plugin-modules.php", "wp-cache.php"}
ASSET_DIRS = ("wp-includes/js/", "wp-includes/css/", "wp-includes/images/", "wp-includes/fonts/", "wp-admin/images/",
              "wp-admin/css/", "wp-admin/js/", "wp-content/languages/")  # fmt: skip
WEEK = 7 * 86400


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def score(
    data: bytes, rel: str, mtime: float | None = None, sibling_median: float | None = None, now: float | None = None
) -> tuple[int, list[str]]:
    """(score, reasons) for a PHP file whose site-relative posix path is `rel`."""
    total, why = 0, []

    def add(points: int, reason: str) -> None:
        nonlocal total
        total += points
        why.append(f"{reason} (+{points})")

    for rx, pts, label in CALLS:
        if rx.search(data):
            add(pts, label)
    sample = data[:200_000]
    if len(sample) >= 1024 and entropy(sample) > 5.8:
        add(3, "high entropy (packed/obfuscated)")
    if len(sample) > 5000 and max(map(len, sample.split(b"\n"))) > 5000 and sample.count(b"\n") < len(sample) / 2000:
        add(2, "very long lines")
    name = rel.rsplit("/", 1)[-1]
    if name.lower() in KNOWN_BAD_NAMES:
        add(5, "filename used by known malware")
    if DOUBLE_EXT.search(name):
        add(4, "double extension")
    if rel.startswith(ASSET_DIRS):
        add(3, "php in an asset directory")
    if mtime is not None:
        if now is not None and mtime > now + 3600:
            add(2, "modified in the future")
        if sibling_median is not None and mtime - sibling_median > 30 * 86400:
            add(2, "much newer than its siblings")
    return total, why
