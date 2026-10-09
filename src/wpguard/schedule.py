"""Scheduler helpers: generate/install cron lines or systemd user timers for watch, backup, scan, sigs, updates."""

import re
import shutil
import subprocess
import sys
from pathlib import Path

from wpguard.report import Rep

JOBS = {"watch": "watch", "backup": "backup", "scan": "scan", "sigs": "sigs update", "updates": "updates"}
MARK = "# wpguard:"
UNIT_DIR = Path.home() / ".config/systemd/user"


def parse_when(every: str | None, daily: str | None, cron: str | None) -> tuple[str, str | None]:
    """-> (cron expression, systemd OnCalendar or None when the schedule is a raw cron expression)."""
    if cron:
        return cron, None
    if daily:
        if not (m := re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", daily)):
            sys.exit("--daily HH:MM, e.g. --daily 03:30")
        h, mi = int(m.group(1)), int(m.group(2))
        return f"{mi} {h} * * *", f"*-*-* {h:02d}:{mi:02d}:00"
    if every and (m := re.fullmatch(r"(\d+)([mh])", every)):
        n = int(m.group(1))
        if m.group(2) == "m" and 1 <= n <= 59:
            return f"*/{n} * * * *", f"*:0/{n}"
        if m.group(2) == "h" and 1 <= n <= 23:
            return f"0 */{n} * * *", f"0/{n}:00"
    sys.exit("give --every 15m | --every 6h | --daily 03:30 | --cron '*/10 * * * *'")


def command(job: str, target: str, a) -> str:
    """The wpguard command line a timer runs. Alerts are on for jobs that find things."""
    parts = [sys.executable, "-m", "wpguard", *JOBS[job].split()]
    if job != "sigs":
        parts.append(target)
    if job in {"watch", "scan", "updates"}:
        parts.append("--notify")
    if cfg := getattr(a, "config_path", None):
        parts += ["--config", str(Path(cfg).resolve())]
    import shlex

    return shlex.join(parts)


def cron_line(job: str, target: str, expr: str, cmd: str) -> str:
    return f"{expr} {cmd} >/dev/null 2>&1 {MARK}{job}:{target}"


def merge_crontab(current: str, new_line: str, job: str, target: str) -> str:
    """Replace any line carrying our marker for (job, target), keep everything else."""
    tag = f"{MARK}{job}:{target}"
    kept = [ln for ln in current.splitlines() if not ln.rstrip().endswith(tag)]
    return "\n".join([*kept, new_line]) + "\n"


def strip_crontab(current: str, job: str, target: str) -> str:
    tag = f"{MARK}{job}:{target}"
    return "".join(ln + "\n" for ln in current.splitlines() if not ln.rstrip().endswith(tag))


def unit_name(job: str, target: str) -> str:
    return "wpguard-" + re.sub(r"[^A-Za-z0-9_.-]", "_", f"{job}-{target}")


def systemd_units(job: str, target: str, calendar: str, cmd: str) -> dict[str, str]:
    name = unit_name(job, target)
    return {
        f"{name}.service": f"[Unit]\nDescription=wpguard {job} {target}\n\n[Service]\nType=oneshot\nExecStart={cmd}\n",
        f"{name}.timer": (
            f"[Unit]\nDescription=wpguard {job} {target}\n\n[Timer]\nOnCalendar={calendar}\nPersistent=true\n\n"
            "[Install]\nWantedBy=timers.target\n"
        ),
    }


def _crontab(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["crontab", *args], input=stdin, capture_output=True, text=True, check=False)


def schedule(args: list[str], a) -> Rep:
    """wpguard schedule {add|remove|show} JOB SITE [--every 15m|--daily 03:30|--cron EXPR] [--systemd] [--install]."""
    rep = Rep("schedule")
    if len(args) < 3 or args[0] not in {"add", "remove", "show"} or args[1] not in JOBS:
        sys.exit(f"usage: wpguard schedule add|remove|show {'|'.join(JOBS)} SITE [--every 15m] [--install] [--systemd]")
    verb, job, target = args[0], args[1], args[2]
    if any(ord(c) < 32 for c in target):
        sys.exit("invalid target name")
    if verb == "remove":
        return _remove(rep, job, target, systemd=a.systemd)
    expr, cal = parse_when(a.every, a.daily, a.cron)
    cmd = command(job, target, a)
    if a.systemd:
        if cal is None:
            sys.exit("systemd needs --every/--daily (not a raw --cron expression)")
        units = systemd_units(job, target, cal, cmd)
        for fname, body in units.items():
            rep.log(f"# {UNIT_DIR / fname}\n{body}")
        if verb == "add" and a.install:
            UNIT_DIR.mkdir(parents=True, exist_ok=True)
            for fname, body in units.items():
                (UNIT_DIR / fname).write_text(body)
            for c in (["daemon-reload"], ["enable", "--now", unit_name(job, target) + ".timer"]):
                subprocess.run(["systemctl", "--user", *c], check=False)
            rep.log("installed. For timers to run while logged out: loginctl enable-linger $USER")
        return rep
    line = cron_line(job, target, expr, cmd)
    rep.log(line)
    if verb == "add" and a.install:
        if not shutil.which("crontab"):
            sys.exit("crontab not found")
        cur = _crontab(["-l"])
        text = merge_crontab(cur.stdout if cur.returncode == 0 else "", line, job, target)
        r = _crontab(["-"], text)
        rep.log("installed in your crontab" if r.returncode == 0 else f"crontab failed: {r.stderr.strip()}")
        rep.exit = r.returncode
    elif verb == "add":
        rep.log("(printed only; add --install to write it to your crontab)")
    return rep


def _remove(rep: Rep, job: str, target: str, *, systemd: bool) -> Rep:
    if systemd:
        name = unit_name(job, target)
        subprocess.run(["systemctl", "--user", "disable", "--now", f"{name}.timer"], check=False)
        for suffix in ("service", "timer"):
            (UNIT_DIR / f"{name}.{suffix}").unlink(missing_ok=True)
        rep.log(f"removed {name}")
        return rep
    cur = _crontab(["-l"])
    new = strip_crontab(cur.stdout if cur.returncode == 0 else "", job, target)
    r = _crontab(["-"], new)
    rep.log(f"removed {job}:{target} from crontab" if r.returncode == 0 else f"crontab failed: {r.stderr.strip()}")
    return rep
