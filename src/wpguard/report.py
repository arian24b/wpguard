"""Per-site report object, report files and alerts."""

import html
import json
import os
import smtplib
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path


class Rep:
    """Per-site report: `hits` need attention, `lines` is the readable transcript."""

    live = True  # stream lines to stdout as they happen (off when sites run in parallel)

    def __init__(self, site: object, *, quiet: bool = False) -> None:
        self.site = str(site)
        self.lines: list[str] = []
        self.hits: list[dict] = []
        self.files: dict = {}  # Path -> (kind, why), filled by the file scan
        self.data: dict = {}  # structured payload (audit, ...)
        self.exit = 0  # non-zero forces a failing exit code (remote runs, failed verify)
        self.quiet = quiet

    def log(self, *a: object) -> None:
        line = " ".join(map(str, a))
        self.lines.append(line)
        if self.live and not self.quiet:
            print(line, flush=True)

    def hit(self, kind: str, what: object, why: str) -> None:
        self.hits.append({"kind": kind, "what": str(what), "why": why})
        self.log(f"  [{kind}] {what}  <- {why}")


def write_report(path: str, reps: list[Rep]) -> None:
    ext = Path(path).suffix
    if ext == ".json":
        txt = json.dumps([{"site": r.site, "hits": r.hits, "log": r.lines} for r in reps], indent=1)
    elif ext == ".html":
        txt = "<meta charset=utf-8><title>wpguard</title><body style='font:14px monospace'>" + "".join(
            f"<h2>{html.escape(r.site)} ({len(r.hits)} findings)</h2><pre>{html.escape(chr(10).join(r.lines))}</pre>"
            for r in reps
        )
    else:
        txt = "\n\n".join(f"### {r.site}\n" + "\n".join(r.lines) for r in reps)
    Path(path).write_text(txt)
    print("report ->", path)


def notify(text: str, cfg: dict | None = None) -> None:
    """Telegram and/or email. Env wins over the `[notify]` config table."""
    cfg = cfg or {}
    tok = os.environ.get("WPGUARD_TELEGRAM_TOKEN") or cfg.get("telegram_token")
    chat = os.environ.get("WPGUARD_TELEGRAM_CHAT") or cfg.get("telegram_chat")
    if tok and chat:
        body = urllib.parse.urlencode({"chat_id": chat, "text": text[:4000]}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{tok}/sendMessage", body, timeout=10)
    if to := os.environ.get("WPGUARD_EMAIL") or cfg.get("email"):
        m = EmailMessage()
        m["To"], m["From"], m["Subject"] = to, f"wpguard@{os.uname().nodename}", "wpguard alert"
        m.set_content(text)
        with smtplib.SMTP(cfg.get("smtp_host", "localhost")) as s:
            s.send_message(m)
