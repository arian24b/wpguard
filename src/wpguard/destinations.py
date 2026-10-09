"""Backup destinations (local dir, S3-compatible bucket, rsync over ssh) with concurrent upload and retention.

Specs:  /srv/backups | s3://bucket/prefix | rsync:HOST:/path   (HOST may be an ~/.ssh/config alias like `mina`).
S3 needs `pip install wpguard[s3]` and the usual AWS_* env vars (AWS_ENDPOINT_URL works for MinIO/R2/etc).
"""

import re
import shlex
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SSH = ["ssh", "-o", "BatchMode=yes"]


class DestError(Exception):
    """A destination failed (message is shown to the user)."""


class Local:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory).expanduser()
        self.label = str(self.dir)

    def put(self, files: list[Path]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        for f in files:
            if f.parent.resolve() != self.dir.resolve():
                shutil.copy2(f, self.dir / f.name)
                (self.dir / f.name).chmod(0o600)

    def names(self) -> list[str]:
        return sorted(p.name for p in self.dir.glob("wpguard-backup-*")) if self.dir.is_dir() else []

    def delete(self, name: str) -> None:
        (self.dir / name).unlink(missing_ok=True)

    def size(self, name: str) -> int | None:
        p = self.dir / name
        return p.stat().st_size if p.is_file() else None


class S3:
    def __init__(self, spec: str) -> None:
        self.label = spec
        bucket, _, prefix = spec.removeprefix("s3://").partition("/")
        self.bucket, self.prefix = bucket, (prefix.strip("/") + "/") if prefix.strip("/") else ""
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                import boto3
            except ImportError as e:
                msg = "S3 needs boto3: pip install 'wpguard[s3]'"
                raise DestError(msg) from e
            self._client = boto3.client("s3")
        return self._client

    def put(self, files: list[Path]) -> None:
        client = self.client  # raises the friendly "pip install" error first
        from boto3.s3.transfer import TransferConfig

        cfg = TransferConfig(max_concurrency=8, multipart_threshold=64 * 1024 * 1024)
        for f in files:
            client.upload_file(str(f), self.bucket, self.prefix + f.name, Config=cfg)

    def names(self) -> list[str]:
        out = []
        for page in self.client.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=self.prefix):
            out += [o["Key"].removeprefix(self.prefix) for o in page.get("Contents", [])]
        return sorted(n for n in out if n.startswith("wpguard-backup-"))

    def delete(self, name: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=self.prefix + name)

    def size(self, name: str) -> int | None:
        try:
            return self.client.head_object(Bucket=self.bucket, Key=self.prefix + name)["ContentLength"]
        except Exception:  # noqa: BLE001  botocore ClientError without importing botocore
            return None


class Rsync:
    def __init__(self, spec: str) -> None:
        self.label = f"rsync:{spec}"
        self.host, _, self.path = spec.partition(":")
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", self.host) or not self.path:
            msg = f"bad rsync destination {spec!r}, use rsync:HOST:/path"
            raise DestError(msg)

    def _ssh(self, command: str) -> subprocess.CompletedProcess:
        return subprocess.run([*SSH, self.host, command], capture_output=True, text=True, check=False)

    def put(self, files: list[Path]) -> None:
        if not shutil.which("rsync"):
            msg = "rsync not found"
            raise DestError(msg)
        self._ssh(f"mkdir -p {shlex.quote(self.path)}")
        r = subprocess.run(
            ["rsync", "-a", "--partial", "--chmod=F600", "-e", " ".join(SSH), *map(str, files), f"{self.host}:{self.path}/"],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        if r.returncode:
            msg = f"rsync failed: {r.stderr.strip()[-200:]}"
            raise DestError(msg)

    def names(self) -> list[str]:
        r = self._ssh(f"ls -1 {shlex.quote(self.path)}")
        return sorted(n for n in r.stdout.split() if n.startswith("wpguard-backup-")) if r.returncode == 0 else []

    def delete(self, name: str) -> None:
        self._ssh(f"rm -f -- {shlex.quote(f'{self.path}/{name}')}")

    def size(self, name: str) -> int | None:
        r = self._ssh(f"stat -c %s -- {shlex.quote(f'{self.path}/{name}')}")
        return int(r.stdout) if r.returncode == 0 and r.stdout.strip().isdigit() else None


def parse(spec: str) -> Local | S3 | Rsync:
    if spec.startswith("s3://"):
        return S3(spec)
    if spec.startswith("rsync:"):
        return Rsync(spec.removeprefix("rsync:"))
    return Local(Path(spec))


def retention(dest, site_name: str, keep: int) -> list[str]:
    """Delete all but the newest `keep` backups of `site_name` (archive + sidecars). Returns deleted names."""
    rx = re.compile(rf"wpguard-backup-{re.escape(site_name)}-(\d{{8}}-\d{{6}})\.tar\.zst(?:\.age)?(?:\.sha256)?")
    groups: dict[str, list[str]] = {}
    for n in dest.names():
        if m := rx.fullmatch(n):
            groups.setdefault(m.group(1), []).append(n)
    old = sorted(groups)[: max(len(groups) - keep, 0)] if keep > 0 else []
    deleted = []
    for ts in old:
        for n in groups[ts]:
            dest.delete(n)
            deleted.append(n)
    return deleted


def upload_all(dests: list, files: list[Path], site_name: str, keep: int) -> dict[str, str]:
    """Upload `files` to every destination concurrently, check the archive size, apply retention.

    Returns {label: 'ok ...' | 'FAILED ...'}. Retention only runs after a verified upload.
    """
    archive = files[0]

    def one(d) -> str:
        d.put(files)
        got = d.size(archive.name)
        if got != archive.stat().st_size:
            msg = f"size mismatch after upload ({got} != {archive.stat().st_size})"
            raise DestError(msg)
        gone = retention(d, site_name, keep) if keep else []
        return f"ok ({len(gone)} old file(s) removed)" if gone else "ok"

    def safe(d) -> tuple[str, str]:
        try:
            return d.label, one(d)
        except Exception as e:  # noqa: BLE001  one broken destination must not stop the others
            return d.label, f"FAILED: {e}"

    with ThreadPoolExecutor(max_workers=max(len(dests), 1)) as ex:
        return dict(ex.map(safe, dests))
