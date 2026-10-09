"""Run a wpguard command on a remote host over ssh. The host can be an ~/.ssh/config alias (`ssh mina`)."""

import re
import shlex
import shutil
import subprocess
from pathlib import Path

from wpguard.report import Rep

DEFAULT_REMOTE_CMD = "uvx wpguard"


def build(host: str, remote_cmd: str, argv: list[str]) -> list[str]:
    """['ssh', HOST, 'uvx wpguard scan /var/www/x --since 7'] (one remote command string, quoted)."""
    return ["ssh", host, f"{remote_cmd} {shlex.join(argv)}"]


def run(host: str, remote_cmd: str, argv: list[str], *, live: bool, pull: str | None = None) -> Rep:
    """Execute and stream. A non-zero remote exit code becomes rep.exit (1 = findings, same as locally)."""
    rep = Rep(f"{host}:{argv[1] if len(argv) > 1 else ''}")
    cmd = build(host, remote_cmd, argv)
    if live and not pull:
        rep.exit = subprocess.run(cmd, check=False).returncode
        return rep
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    for line in (r.stdout + r.stderr).splitlines():
        rep.log(line)
    rep.exit = r.returncode
    if pull and argv[0] == "backup" and r.returncode == 0:
        rep.log(pull_backup(host, r.stdout, Path(pull)))
    return rep


def pull_backup(host: str, output: str, dest: Path) -> str:
    """rsync the archive (+ .sha256) that the remote `backup` printed back to this machine."""
    m = re.search(r"backup -> (\S+\.tar\.zst(?:\.age)?)", output)
    if not m:
        return "pull: could not find the archive path in the remote output"
    if not shutil.which("rsync"):
        return "pull: rsync not found"
    dest.mkdir(parents=True, exist_ok=True)
    src = m.group(1)
    r = subprocess.run(
        ["rsync", "-a", "-e", "ssh -o BatchMode=yes", f"{host}:{src}", f"{host}:{src}.sha256", f"{dest}/"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    return f"pulled {Path(src).name} -> {dest}" if r.returncode == 0 else f"pull failed: {r.stderr.strip()[-200:]}"
