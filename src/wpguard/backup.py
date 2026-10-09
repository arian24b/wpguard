"""backup / verify / restore: DB dump + site files in a zstd tar, optional age encryption, multi-destination upload."""

import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from wpguard import wpcli
from wpguard.destinations import DestError, Local, parse, upload_all
from wpguard.report import Rep
from wpguard.util import stamp

SKIP_UPLOADS = "site/wp-content/uploads"
CHUNK = 1024 * 1024


def sha256(p: Path) -> str:
    with p.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def age_encrypt(src: Path, recipient: str) -> Path:
    if not shutil.which("age"):
        msg = "--encrypt-to needs the `age` binary (https://age-encryption.org)"
        raise DestError(msg)
    out = src.with_name(src.name + ".age")
    r = subprocess.run(["age", "-r", recipient, "-o", str(out), str(src)], capture_output=True, text=True, check=False)
    if r.returncode:
        msg = f"age failed: {r.stderr.strip()}"
        raise DestError(msg)
    src.unlink()
    return out


def age_decrypt(src: Path, identity: str, dst: Path) -> None:
    r = subprocess.run(
        ["age", "-d", "-i", identity, "-o", str(dst), str(src)], capture_output=True, text=True, check=False
    )
    if r.returncode:
        msg = f"age decrypt failed: {r.stderr.strip()}"
        raise DestError(msg)


def write_archive(site: Path, out: Path, *, uploads: bool) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        sql = Path(tmp) / "db.sql"
        r = wpcli.wp(site, "db", "export", str(sql))
        if r.returncode:
            sys.exit(f"db export failed, aborting: {r.stderr.strip()}")
        with tarfile.open(out, "x:zst") as t:  # "x": never overwrite an existing backup
            t.add(sql, arcname="db.sql")
            t.add(site, arcname="site", filter=lambda i: None if not uploads and i.name.startswith(SKIP_UPLOADS) else i)
    out.chmod(0o600)  # holds wp-config.php and the DB


def verify_archive(arc: Path, identity: str | None = None) -> list[str]:
    """Problems found in a backup (empty list = good): checksum sidecar, readable tar, plausible db.sql, WP files."""
    problems: list[str] = []
    if (side := arc.with_name(arc.name + ".sha256")).exists():
        if sha256(arc) != side.read_text().split()[0]:
            return [f"checksum mismatch for {arc.name}"]
    else:
        problems.append("no .sha256 sidecar (cannot detect corruption of the file itself)")
    if arc.suffix == ".age":
        if not identity:
            return [*problems, "encrypted: only the checksum was verified (pass --age-identity to verify contents)"]
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / arc.name.removesuffix(".age")
            age_decrypt(arc, identity, plain)
            return [p for p in verify_archive(plain) if "sidecar" not in p]
    seen = set()
    try:
        with tarfile.open(arc, "r:zst") as t:
            for m in t:
                seen.add(m.name)
                if m.isfile():
                    f = t.extractfile(m)
                    head = f.read(CHUNK) if f else b""
                    while f and f.read(CHUNK):
                        pass
                    if m.name == "db.sql" and not (m.size and (b"CREATE TABLE" in head or b"INSERT INTO" in head)):
                        problems.append("db.sql is empty or does not look like a MySQL dump")
    except (tarfile.TarError, OSError, EOFError, ValueError) as e:
        return [*problems, f"archive unreadable: {e}"]
    problems += [f"missing {need} in archive" for need in ("db.sql", "site/wp-load.php") if need not in seen]
    return problems


def make_backup(site: Path, a, rep: Rep, *, uploads: bool = True, local_only: bool = False) -> Path:
    """Create the archive, optionally encrypt/verify, upload to every destination, apply retention."""
    specs = [] if local_only else list(a.to or [])
    dests = [parse(s) for s in specs]
    out_dir = Path(a.out) if a.out else None
    local = [d for d in dests if isinstance(d, Local)]
    if not dests or (out_dir and not local):
        dests.insert(0, Local(out_dir or site.parent))
    staging_is_temp = False
    if local_only or any(isinstance(d, Local) for d in dests):
        staging = next(d.dir for d in dests if isinstance(d, Local)).resolve()
    else:
        staging, staging_is_temp = Path(tempfile.mkdtemp(prefix="wpguard-")), True
    if staging == site or site in staging.parents:
        sys.exit("backup destination must be outside the site directory")
    staging.mkdir(parents=True, exist_ok=True)
    arc = staging / f"wpguard-backup-{site.name}-{stamp()}.tar.zst"
    write_archive(site, arc, uploads=uploads)
    if a.encrypt_to:
        arc = age_encrypt(arc, a.encrypt_to)
        arc.chmod(0o600)
    digest = sha256(arc)
    side = arc.with_name(arc.name + ".sha256")
    side.write_text(f"{digest}  {arc.name}\n")
    rep.log(f"  backup -> {arc} ({arc.stat().st_size // 1024} KiB, sha256 {digest[:12]}...)")
    if a.verify:
        problems = [p for p in verify_archive(arc, a.age_identity) if "sidecar" not in p]
        for p in problems:
            rep.log(f"  VERIFY FAILED: {p}")
        if problems:
            rep.exit = 1
            return arc
        rep.log("  verified: archive readable, db.sql plausible, WordPress files present")
    for label, result in upload_all(dests, [arc, side], site.name, a.keep or 0).items():
        rep.log(f"  {label}: {result}")
        if result.startswith("FAILED"):
            rep.exit = 1
    if staging_is_temp and not a.keep_local and not rep.exit:
        shutil.rmtree(staging, ignore_errors=True)
    elif staging_is_temp:
        rep.log(f"  local copy kept in {staging}")
    return arc


def backup(site: Path, a) -> Rep:
    rep = Rep(site)
    make_backup(site, a, rep, uploads=not a.no_uploads)
    return rep


def latest(site: Path, a) -> Path | None:
    if a.src:
        return Path(a.src)
    base = Path(a.out) if a.out else site.parent
    found = sorted(p for p in base.glob(f"wpguard-backup-{site.name}-*.tar.zst*") if not p.name.endswith(".sha256"))
    return found[-1] if found else None


def verify(site: Path, a) -> Rep:
    rep = Rep(site)
    if not (arc := latest(site, a)) or not arc.is_file():
        rep.log("no backup found (use --from FILE or --out DIR)")
        rep.exit = 1
        return rep
    problems = verify_archive(arc, a.age_identity)
    for p in problems:
        rep.hit("verify", arc.name, p)
    if not problems:
        rep.log(f"OK {arc}")
    return rep


def restore(site: Path, a) -> Rep:
    rep = Rep(site)
    arc = latest(site, a)
    if not arc or not arc.is_file():
        rep.log("no backup found (use --from FILE.tar.zst)")
        rep.exit = 1
        return rep
    if (side := arc.with_name(arc.name + ".sha256")).exists() and sha256(arc) != side.read_text().split()[0]:
        rep.log(f"CHECKSUM MISMATCH for {arc}, aborting")
        rep.exit = 1
        return rep
    with tempfile.TemporaryDirectory() as tmp:
        src = arc
        if arc.suffix == ".age":
            if not a.age_identity:
                rep.log("encrypted backup: pass --age-identity KEYFILE")
                rep.exit = 1
                return rep
            src = Path(tmp) / arc.name.removesuffix(".age")
            age_decrypt(arc, a.age_identity, src)
        with tarfile.open(src, "r:zst") as t:
            for m in t:
                if m.name == "db.sql":
                    t.extract(m, tmp, filter="data")
                elif m.name.startswith("site/"):
                    t.extract(m.replace(name=m.name.removeprefix("site/")), site, filter="data")
        r = wpcli.wp(site, "db", "import", f"{tmp}/db.sql")
    rep.log("db import:", (r.stdout + r.stderr).strip() or "ok")
    rep.log(f"files restored from {arc}. Quarantined files stay in {site.parent}/wpguard-quarantine (use `undo`).")
    return rep
