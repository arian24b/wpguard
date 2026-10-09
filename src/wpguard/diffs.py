"""`diff`: show exactly how modified core/plugin files differ from the originals on wordpress.org."""

import difflib
import hashlib
import io
import re
import zipfile
from pathlib import Path

from wpguard import wpcli
from wpguard.report import Rep
from wpguard.util import STATE_DIR, fetch

CACHE = STATE_DIR / "cache"


def original_zip(url: str) -> zipfile.ZipFile | None:
    """The official release zip, cached on disk (None when it cannot be downloaded)."""
    cached = CACHE / (hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest() + ".zip")
    if cached.exists():
        data = cached.read_bytes()
    else:
        data = fetch(url)
        if data is None:
            return None
        CACHE.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None


def modified(site: Path) -> list[dict]:
    """Core/plugin files whose checksum differs from wordpress.org."""
    out = []
    ver = wpcli.wp(site, "core", "version").stdout.strip()
    r = wpcli.wp(site, "core", "verify-checksums")
    for m in re.finditer(r"File doesn't verify against checksum: (.+)", r.stdout + r.stderr):
        rel = m.group(1).strip()
        out.append(
            {"kind": "core", "slug": "wordpress", "version": ver, "rel": rel, "path": site / rel,
             "member": f"wordpress/{rel}", "url": f"https://wordpress.org/wordpress-{ver}.zip"}
        )  # fmt: skip
    versions = {
        i["name"]: i["version"] for i in wpcli.jget(site, "plugin", "list", "--format=json", "--fields=name,version")
    }
    for e in wpcli.jget(site, "plugin", "verify-checksums", "--all", "--format=json"):
        if "doesn't verify" in e["message"]:
            slug, v = e["plugin_name"], versions.get(e["plugin_name"], "")
            out.append(
                {"kind": "plugin", "slug": slug, "version": v, "rel": e["file"],
                 "path": site / "wp-content/plugins" / slug / e["file"], "member": f"{slug}/{e['file']}",
                 "url": f"https://downloads.wordpress.org/plugin/{slug}.{v}.zip"}
            )  # fmt: skip
    return out


def unified(original: bytes, current: bytes, label: str) -> list[str]:
    return list(
        difflib.unified_diff(
            original.decode("utf-8", "replace").splitlines(),
            current.decode("utf-8", "replace").splitlines(),
            fromfile=f"original/{label}",
            tofile=f"site/{label}",
            lineterm="",
            n=2,
        )
    )


def diff(site: Path, a) -> Rep:
    rep = Rep(site)
    zips: dict[str, zipfile.ZipFile | None] = {}
    for m in modified(site):
        if (a.plugin and m["slug"] not in a.plugin) or (a.core and m["kind"] != "core"):
            continue
        label = f"{m['slug']}@{m['version']}/{m['rel']}"
        if m["url"] not in zips:
            zips[m["url"]] = original_zip(m["url"])
        z = zips[m["url"]]
        try:
            original = z.read(m["member"]) if z else None
        except KeyError:
            original = None
        if original is None:
            rep.hit("modified", label, "original not available from wordpress.org (cannot diff)")
            continue
        try:
            current = m["path"].read_bytes()
        except OSError as e:
            rep.hit("modified", label, f"cannot read: {e}")
            continue
        if b"\0" in current or b"\0" in original:
            rep.hit("modified", label, "binary file differs")
            continue
        lines = unified(original, current, m["rel"])
        added = sum(1 for ln in lines if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in lines if ln.startswith("-") and not ln.startswith("---"))
        rep.hit("modified", label, f"+{added} -{removed} lines vs the official file")
        shown = lines[: a.max_lines]
        rep.log(
            "\n".join("      " + ln for ln in shown)
            + (f"\n      ... {len(lines) - len(shown)} more lines" if len(lines) > len(shown) else "")
        )
    if not rep.hits:
        rep.log("all core and plugin files match wordpress.org")
    return rep
