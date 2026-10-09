"""Find WordPress sites by hostname: parse nginx/apache vhosts and match them to wp-config.php locations.

Works on this machine or on an ssh host (`ssh mina` from ~/.ssh/config). Best effort: it reads the usual config
locations; unusual layouts can still be registered by hand in wpguard.toml.
"""

import re
import subprocess
from pathlib import Path

from wpguard.config import Config, ConfigError, Target

MARK = "@@FIND@@"
SCRIPT = (
    "cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* "
    "/etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf /usr/local/nginx/conf/vhost/*.conf 2>/dev/null; "
    f"echo {MARK}; "
    "find /var/www /srv /home /opt -maxdepth 6 -name wp-config.php -not -path '*/node_modules/*' 2>/dev/null"
)
_cache: dict[str | None, list[dict]] = {}


def _strip_comments(text: str) -> str:
    return re.sub(r"(?m)^\s*#.*$", "", text)


def _clean_domains(names: list[str]) -> list[str]:
    return [n.lower() for n in names if n and n != "_" and not n.startswith(("*", "~")) and "$" not in n]


def _nginx(text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"\bserver\s*\{", text):
        depth, j = 1, m.end()
        while j < len(text) and depth:
            depth += (text[j] == "{") - (text[j] == "}")
            j += 1
        top = text[m.end() : j - 1]
        while re.search(
            r"\{[^{}]*\}", top
        ):  # drop nested blocks (location {...}) so only server-level directives remain
            top = re.sub(r"\{[^{}]*\}", "", top)
        names = [n for line in re.findall(r"server_name\s+([^;]+);", top) for n in line.split()]
        root = re.search(r"(?:^|[;{}\n])\s*root\s+([^;]+);", top)
        if root and (domains := _clean_domains(names)):
            out.append({"domains": domains, "root": root.group(1).strip().strip("\"'")})
    return out


def _apache(text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"<VirtualHost[^>]*>(.*?)</VirtualHost>", text, re.DOTALL | re.IGNORECASE):
        body = m.group(1)
        names = re.findall(r"(?im)^\s*Server(?:Name|Alias)\s+(.+)$", body)
        root = re.search(r"(?im)^\s*DocumentRoot\s+(\S+)", body)
        if root and (domains := _clean_domains([n for line in names for n in line.split()])):
            out.append({"domains": domains, "root": root.group(1).strip("\"'")})
    return out


def parse_vhosts(text: str) -> list[dict]:
    """[{'domains': [...], 'root': '/var/www/x'}] from nginx server{} and apache <VirtualHost> blocks."""
    text = _strip_comments(text)
    return _nginx(text) + _apache(text)


def match(vhosts: list[dict], wp_roots: list[str]) -> list[dict]:
    """Attach each vhost to the WordPress root it serves (same dir, or a parent/child dir of the docroot)."""
    found: dict[str, list[str]] = {}
    for v in vhosts:
        root = v["root"].rstrip("/")
        exact = [w for w in wp_roots if w == root]
        below = sorted((w for w in wp_roots if w.startswith(root + "/")), key=len)
        above = sorted((w for w in wp_roots if root.startswith(w + "/")), key=len, reverse=True)
        if pick := (exact or below or above):
            for d in v["domains"]:
                if d not in found.setdefault(pick[0], []):
                    found[pick[0]].append(d)
    return [{"path": p, "domains": d} for p, d in sorted(found.items())]


def collect(host: str | None) -> str:
    """Raw vhost config text + the find output, from this machine or over ssh."""
    cmd = ["ssh", host, SCRIPT] if host else ["sh", "-c", SCRIPT]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if host and r.returncode == 255 and not r.stdout:
        msg = f"ssh {host} failed: {r.stderr.strip()[-200:]}"
        raise ConfigError(msg)
    return r.stdout


def sites_on(host: str | None) -> list[dict]:
    """WordPress sites (path + domains) served by `host` (None = this machine). Cached per run."""
    if host not in _cache:
        conf, _, found = collect(host).partition(MARK)
        roots = [
            str(Path(line.strip()).parent) for line in found.splitlines() if line.strip().endswith("wp-config.php")
        ]
        _cache[host] = match(parse_vhosts(conf), roots)
    return _cache[host]


def fill(t: Target) -> None:
    """Resolve a hostname-only Target to the path of its site."""
    want = t.domain.lower()
    for s in sites_on(t.ssh):
        names = {d.lower() for d in s["domains"]}
        if want in names or f"www.{want}" in names or want.removeprefix("www.") in names:
            t.path = s["path"]
            return
    where = f"on {t.ssh}" if t.ssh else "on this machine"
    msg = f"no WordPress site for {t.domain!r} found {where}. Try `wpguard discover{' ' + t.ssh if t.ssh else ''}`"
    raise ConfigError(msg)


def slug(domain: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", domain).strip("-")


def toml_block(site: dict, host: str | None) -> str:
    lines = [f"[sites.{slug(site['domains'][0])}]", f'path = "{site["path"]}"', f'domain = "{site["domains"][0]}"']
    if host:
        lines.insert(1, f'ssh = "{host}"')
    return "\n".join(lines) + "\n"


def discover(hosts: list[str], cfg: Config, config_path: Path | None, *, save: bool) -> int:
    """`wpguard discover [HOST...] [--save]`: list sites by hostname; --save adds missing ones to the config."""
    from wpguard.config import SEARCH, write_template

    new_blocks, total = [], 0
    known = {(p.get("ssh"), str(p.get("path", ""))) for p in cfg.sites.values()}
    for host in hosts or [None]:
        found = sites_on(host)
        print(f"== {host or 'this machine'}: {len(found)} WordPress site(s)")
        for s in found:
            total += 1
            mark = "" if (host, s["path"]) not in known else "  (already in config)"
            print(f"  {', '.join(s['domains']):45} {s['path']}{mark}")
            if not mark:
                new_blocks.append(toml_block(s, host))
    if save and new_blocks:
        target = config_path or SEARCH[1]
        write_template(target) if not target.exists() else None
        with target.open("a") as fh:
            fh.write("\n" + "\n".join(new_blocks))
        print(f"added {len(new_blocks)} site(s) to {target}")
    elif new_blocks:
        print("(use --save to add the new ones to your config)")
    return 0 if total else 1
