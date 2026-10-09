"""Command line: argument parsing, config/profile merging, local vs ssh dispatch, reports and exit codes."""

import argparse
import copy
import shutil
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from wpguard import __version__, config, discover, feeds, remote, wpcli, wpscan
from wpguard.audit import audit, audit_md
from wpguard.backup import backup, restore, verify
from wpguard.diffs import diff
from wpguard.fix import fix, harden, undo
from wpguard.lockfile import lock_cmd
from wpguard.monitor import baseline, logs, watch
from wpguard.recovery import recover_main
from wpguard.report import Rep, notify, write_report
from wpguard.scan import scan
from wpguard.schedule import schedule
from wpguard.updates import updates

SITE_HELP = {
    "scan": "read-only scan: files, DB, admins, updates",
    "fix": "plan, confirm, quarantine, reinstall, harden",
    "undo": "put quarantined files back",
    "harden": "block PHP in uploads, wp-config constants, perms",
    "baseline": "snapshot file hashes of a clean site",
    "watch": "compare with the baseline, alert on changes",
    "backup": "DB + files -> .tar.zst, upload, retention",
    "verify": "check a backup archive",
    "restore": "restore DB + files from a backup",
    "audit": "inventory + findings as Markdown/JSON",
    "diff": "diff modified core/plugin files vs wordpress.org",
    "lock": "pin versions in wpguard.lock (--check: drift)",
    "updates": "test pending updates on a staging copy",
}
OTHER_HELP = {
    "setup": "download wp-cli, create the global config",
    "init": "create ./wpguard.toml",
    "discover [HOST..]": "find WordPress sites by hostname (--save)",
    "logs [SITE..]": "find the entry point in access logs",
    "sigs list|update": "signature feeds (hashes, YARA rules)",
    "schedule add|remove|show": "cron/systemd timers: schedule add watch SITE",
    "wp SITE ARGS..": "run any wp-cli command (--unsafe loads plugins)",
    "wpscan [URL] ARGS..": "run the real WPScan (WPSCAN_TOKEN = API key)",
    "recover ARGS..": "rebuild a wiped site from a DB/dump",
}


def commands_help() -> str:
    def block(title: str, table: dict[str, str]) -> str:
        return title + "\n" + "\n".join(f"  {name:26} {info}" for name, info in table.items())

    return (
        "wpguard: scan, clean, harden, back up and monitor WordPress sites\n\n"
        "SITE = path | profile | hostname | host:/path | host:domain (ssh)\n\n"
        + block("site commands (wpguard COMMAND SITE... [OPTIONS]):", SITE_HELP)
        + "\n\n"
        + block("other commands:", OTHER_HELP)
        + "\n\ndocs: https://github.com/arian24b/wpguard"
    )


class OneLine(argparse.RawDescriptionHelpFormatter):
    """--help with exactly one line per option: `-j, --jobs N   short info` (help text is never wrapped)."""

    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=34, width=max(shutil.get_terminal_size((100, 24)).columns, 90))

    def _split_lines(self, text: str, width: int) -> list[str]:  # noqa: ARG002
        return [text]

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        return f"{', '.join(action.option_strings)} {action.metavar or action.dest.upper()}"


SITE_CMDS: dict[str, Callable] = {
    "scan": scan, "fix": fix, "harden": harden, "undo": undo, "baseline": baseline, "watch": watch,
    "backup": backup, "verify": verify, "restore": restore, "audit": audit, "diff": diff, "lock": lock_cmd,
    "updates": updates,
}  # fmt: skip
FAIL_ON_HITS = {"scan", "watch", "lock", "verify", "diff", "updates"}
NOTIFY_ON = {*FAIL_ON_HITS, "fix"}
LOCAL_WP_CMDS = {"scan", "fix", "harden", "restore", "audit", "backup", "diff", "lock", "updates", "undo"}
LOCAL_ONLY = {"config", "report", "sites_file", "jobs", "pull", "all", "help", "version", "force", "save"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="wpguard",
        usage="wpguard COMMAND [SITE...] [OPTIONS]",
        description=commands_help(),
        formatter_class=OneLine,
    )
    ap.add_argument(
        "cmd", metavar="COMMAND", choices=[*SITE_CMDS, "logs", "setup", "init", "discover", "sigs", "schedule"]
    )
    ap.add_argument("sites", metavar="SITE", nargs="*", help="path, profile, hostname, host:/path or host:domain")
    ap.add_argument("--version", action="version", version=f"wpguard {__version__}", help="show the version")
    g = ap.add_argument_group("general")
    g.add_argument("--config", metavar="FILE", help="config file (default ./wpguard.toml, ~/.config/wpguard/)")
    g.add_argument("--all", action="store_true", help="every site profile in the config")
    g.add_argument("--force", action="store_true", help="overwrite (init) / re-download (setup)")
    g.add_argument("--save", action="store_true", help="(discover) add found sites to the config")
    g.add_argument("--sites-file", metavar="FILE", help="extra sites, whitespace separated")
    g.add_argument("-j", "--jobs", metavar="N", type=int, default=1, help="sites in parallel (default 1)")
    g.add_argument("--report", metavar="FILE", help="write a report (.json .html .txt)")
    g.add_argument("--notify", action="store_true", help="alert via telegram/email on findings")
    g.add_argument("--url", metavar="URL", help="pin WP_HOME/WP_SITEURL (harden, fix)")
    g.add_argument("--ignore", metavar="GLOB", action="append", help="ignore site-relative paths (repeatable)")
    g.add_argument("--lock-file", metavar="FILE", help="wpguard.lock path (default next to the config)")
    d = ap.add_argument_group("detection")
    d.add_argument("--sigs", metavar="FILE", action="append", help="extra regexes, one per line")
    d.add_argument("--hashdb", metavar="FILE", action="append", help="known-bad hash database")
    d.add_argument("--hashdb-good", metavar="FILE", action="append", help="known-clean hash database")
    d.add_argument("--yara", metavar="FILE", action="append", help="YARA rules (needs yara or yr)")
    d.add_argument("--no-feeds", action="store_true", help="skip downloaded signature feeds")
    d.add_argument("--no-behavior", action="store_true", help="disable behavior scoring")
    d.add_argument("--behavior-threshold", metavar="N", type=int, default=5, help="review score cutoff (default 5)")
    d.add_argument("--since", metavar="DAYS", type=int, help="flag PHP/admins changed in the last N days")
    d.add_argument("--no-net", action="store_true", help="skip wordpress.org / WPScan lookups")
    f = ap.add_argument_group("fix / harden")
    f.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    f.add_argument("--yes", action="store_true", help="no confirmation prompt")
    f.add_argument("--aggressive", action="store_true", help="also quarantine behavior/yara findings")
    f.add_argument("--clean-db", action="store_true", help="apply DB cleanup (default: dry run)")
    f.add_argument("--prune", action="store_true", help="delete inactive plugins/themes")
    f.add_argument("--delete-user", metavar="ID", action="append", help="delete this user (repeatable)")
    f.add_argument("--lockdown", action="store_true", help="also DISALLOW_FILE_MODS (blocks updates)")
    f.add_argument("--only", metavar="GLOB", action="append", help="(undo) restore only matching files")
    b = ap.add_argument_group("backup")
    b.add_argument("--out", metavar="PATH", help="backup: directory | audit: output file")
    b.add_argument("--to", metavar="DEST", action="append", help="DIR | s3://bucket/prefix | rsync:HOST:/path")
    b.add_argument("--keep", metavar="N", type=int, help="retention: newest N per destination")
    b.add_argument("--no-uploads", action="store_true", help="leave out wp-content/uploads")
    b.add_argument("--encrypt-to", metavar="KEY", help="age recipient (age1...) to encrypt with")
    b.add_argument("--age-identity", metavar="FILE", help="age key for verify/restore")
    b.add_argument("--verify", action="store_true", help="verify the archive before uploading")
    b.add_argument("--keep-local", action="store_true", help="keep the local copy (remote-only destinations)")
    b.add_argument("--from", metavar="PATH", dest="src", help="backup file or quarantine dir")
    b.add_argument("--pull", metavar="DIR", help="remote backup: rsync the archive back")
    x = ap.add_argument_group("diff / lock / updates")
    x.add_argument("--core", action="store_true", help="(diff) core files only")
    x.add_argument("--plugin", metavar="SLUG", action="append", help="(diff) only this plugin")
    x.add_argument("--max-lines", metavar="N", type=int, default=60, help="(diff) lines per file (default 60)")
    x.add_argument("--check", action="store_true", help="(lock) report drift, exit 1")
    x.add_argument("--apply", action="store_true", help="(updates) apply the safe updates")
    x.add_argument("--stage-db", metavar="NAME", help="(updates) existing empty DB for staging")
    x.add_argument("--check-url", metavar="PATH", action="append", help="(updates) extra URL path to check")
    x.add_argument("--keep-stage", action="store_true", help="(updates) keep the staging copy")
    s = ap.add_argument_group("schedule")
    s.add_argument("--every", metavar="15m|6h", help="run every N minutes/hours")
    s.add_argument("--daily", metavar="HH:MM", help="run once a day")
    s.add_argument("--cron", metavar="EXPR", help="raw cron expression")
    s.add_argument("--systemd", action="store_true", help="systemd user timer instead of cron")
    s.add_argument("--install", action="store_true", help="write it (default: print only)")
    o = ap.add_argument_group("output")
    o.add_argument("--format", metavar="md|json", choices=["md", "json"], help="(audit) export format")
    o.add_argument("--log", metavar="FILE", action="append", default=[], help="(logs) access log file")
    o.add_argument("--top", metavar="N", type=int, default=10, help="(logs) rows per section (default 10)")
    return ap


def apply_opts(ap: argparse.ArgumentParser, ns: argparse.Namespace, opts: dict, origin: str) -> None:
    """Fill options the user did not give on the command line from config values (CLI always wins)."""
    dests = {act.dest for act in ap._actions}  # noqa: SLF001
    for key, val in opts.items():
        if key not in dests:
            msg = f"{origin}: unknown option {key!r}"
            raise config.ConfigError(msg)
        if getattr(ns, key) == ap.get_default(key):
            setattr(ns, key, list(val) if isinstance(val, list) else val)


def serialize(ap: argparse.ArgumentParser, ns: argparse.Namespace) -> list[str]:
    """Namespace -> CLI flags that differ from defaults (what a remote wpguard must be told)."""
    out: list[str] = []
    for act in ap._actions:  # noqa: SLF001
        if not act.option_strings or act.dest in LOCAL_ONLY:
            continue
        val = getattr(ns, act.dest, None)
        if val in (None, False, [], act.default):
            continue
        flag = max(act.option_strings, key=len)
        if isinstance(act, argparse._StoreTrueAction):  # noqa: SLF001
            out.append(flag)
        elif isinstance(act, argparse._AppendAction):  # noqa: SLF001
            for v in val:
                out += [flag, str(v)]
        else:
            out += [flag, str(val)]
    return out


def run_target(ap: argparse.ArgumentParser, ns: argparse.Namespace, cfg: config.Config, t: config.Target) -> Rep:
    ta = copy.copy(ns)
    ta._det = None  # noqa: SLF001  detectors are built per target (options may differ)
    ta.site_key, ta.config_path = t.key, cfg.path
    apply_opts(ap, ta, t.opts, f"[sites.{t.name}]")  # first writer wins: CLI > profile > defaults
    apply_opts(ap, ta, cfg.defaults, "[defaults]")
    if t.ssh:
        return remote.run(t.ssh, t.remote_cmd, [ns.cmd, t.path, *serialize(ap, ta)], live=Rep.live, pull=ns.pull)
    return SITE_CMDS[ns.cmd](Path(t.path), ta)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["wp"]:
        wpcli.wp_passthrough(argv[1:])
    if argv[:1] == ["wpscan"]:
        wpscan.wpscan_passthrough(argv[1:])
    if argv[:1] == ["recover"]:
        recover_main(argv[1:])
        return 0
    if not argv:
        print(commands_help())
        return 2
    ap = build_parser()
    ns = ap.parse_args(argv)
    if ns.cmd == "init":
        path = Path(ns.config) if ns.config else Path("wpguard.toml")
        if config.write_template(path, force=ns.force):
            print(f"created {path.resolve()}  (edit it, then try: wpguard discover --save)")
            return 0
        print(f"{path} already exists (use --force to overwrite)")
        return 1
    if ns.cmd == "setup":
        wpcli.setup()
        if created := config.ensure_default():
            print(f"created {created}  (edit it, or run: wpguard discover --save)")
        return 0
    try:
        cfg = config.load(ns.config)
    except config.ConfigError as e:
        sys.exit(f"error: {e}")
    if ns.cmd == "sigs":
        return feeds.sigs_cmd(ns.sites, cfg.feeds)
    ns.config_path = cfg.path
    if ns.cmd == "discover":
        try:
            return discover.discover(ns.sites, cfg, cfg.path, save=ns.save)
        except config.ConfigError as e:
            sys.exit(f"error: {e}")
    if ns.cmd == "schedule":
        ns.site_key = ""
        rep = schedule(ns.sites, ns)
        return rep.exit
    if ns.sites_file:
        ns.sites += Path(ns.sites_file).read_text().split()
    Rep.live = ns.jobs == 1
    if ns.cmd == "logs":
        reps = [logs([str(Path(s).resolve()) for s in ns.sites], ns)]
    else:
        if not ns.sites and not ns.all:
            sys.exit("give at least one SITE (path, profile name, host:/path) or --all")
        if ns.cmd == "fix" and ns.jobs > 1 and not (ns.yes or ns.dry_run):
            sys.exit("fix with -j > 1 cannot ask for confirmation: add --yes (or use --dry-run)")
        try:
            targets = config.targets(cfg, ns.sites, every=ns.all)
            for t in targets:
                if not t.path:
                    discover.fill(t)  # hostname-only target: find its path from the vhosts
            if ns.cmd in LOCAL_WP_CMDS and any(not t.ssh for t in targets):
                wpcli.need_wp()
            bad = [t.path for t in targets if not t.ssh and not (Path(t.path) / "wp-load.php").exists()]
            if bad:
                sys.exit(f"not WordPress roots: {bad}")
            with ThreadPoolExecutor(ns.jobs) as ex:
                reps = list(ex.map(lambda t: run_target(ap, ns, cfg, t), targets))
        except config.ConfigError as e:
            sys.exit(f"error: {e}")
    if not Rep.live:
        for r in reps:
            print("\n".join(r.lines))
    if ns.cmd == "audit":
        _export_audit(ns, reps)
    if ns.report:
        write_report(ns.report, reps)
    found = [r for r in reps if r.hits]
    if found and ns.notify and ns.cmd in NOTIFY_ON:
        notify(
            "\n".join(
                f"{r.site}: {len(r.hits)} findings\n"
                + "\n".join(f"- [{h['kind']}] {h['what']}: {h['why']}" for h in r.hits[:15])
                for r in found
            ),
            cfg.notify,
        )
    return 1 if any(r.exit for r in reps) or (found and ns.cmd in FAIL_ON_HITS) else 0


def _export_audit(ns: argparse.Namespace, reps: list[Rep]) -> None:
    import json

    fmt = ns.format or ("json" if (ns.out or "").endswith(".json") else "md")
    docs = [r.data for r in reps]
    txt = (
        json.dumps(docs[0] if len(docs) == 1 else docs, indent=1) if fmt == "json" else "\n\n".join(map(audit_md, docs))
    )
    if ns.out:
        Path(ns.out).write_text(txt)
        print("audit ->", ns.out, file=sys.stderr)
    else:
        print(txt)
