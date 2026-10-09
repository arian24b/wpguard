"""Command line: argument parsing, config/profile merging, local vs ssh dispatch, reports and exit codes."""

import argparse
import copy
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from wpguard import __version__, config, feeds, remote, wpcli, wpscan
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

DOC = """wpguard: scan, clean, harden, back up and monitor hacked WordPress sites with wp-cli.

site commands (SITE = path, profile name from wpguard.toml, or host:/path over ssh):
  scan  fix  harden  undo  baseline  watch  backup  verify  restore  audit  diff  lock  updates
other commands:
  setup                      download wp-cli (sha512 verified)
  logs [SITE...]             find the entry point in web server access logs
  sigs list|update [NAME..]  signature feeds (maldet hashes, YARA rules)
  schedule add|remove|show JOB SITE   cron / systemd timers (JOB: watch backup scan sigs updates)
  wp [--unsafe] SITE ARGS... run ANY wp-cli command (plugins/themes not loaded unless --unsafe)
  wpscan [URL] ARGS...       run the real WPScan (local or docker); WPSCAN_TOKEN is used if set
  recover ARGS...            rebuild a wiped site from a DB / dump (see `recover --help`)
Docs: https://github.com/arian24b/wpguard
"""
SITE_CMDS: dict[str, Callable] = {
    "scan": scan, "fix": fix, "harden": harden, "undo": undo, "baseline": baseline, "watch": watch,
    "backup": backup, "verify": verify, "restore": restore, "audit": audit, "diff": diff, "lock": lock_cmd,
    "updates": updates,
}  # fmt: skip
FAIL_ON_HITS = {"scan", "watch", "lock", "verify", "diff", "updates"}
NOTIFY_ON = {*FAIL_ON_HITS, "fix"}
LOCAL_WP_CMDS = {"scan", "fix", "harden", "restore", "audit", "backup", "diff", "lock", "updates", "undo"}
LOCAL_ONLY = {"config", "report", "sites_file", "jobs", "pull", "all", "help", "version"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="wpguard", description=DOC, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=[*SITE_CMDS, "logs", "setup", "sigs", "schedule"])
    ap.add_argument("sites", nargs="*", help="paths, profile names or host:/path")
    ap.add_argument("--version", action="version", version=f"wpguard {__version__}")
    g = ap.add_argument_group("general")
    g.add_argument("--config", help="wpguard.toml (default: ./wpguard.toml, ~/.config/wpguard/wpguard.toml)")
    g.add_argument("--all", action="store_true", help="every site profile in the config")
    g.add_argument("--sites-file")
    g.add_argument("-j", "--jobs", type=int, default=1)
    g.add_argument("--report", help="write report: out.json | out.html | out.txt")
    g.add_argument("--notify", action="store_true", help="alert (telegram/email) when there are findings")
    g.add_argument("--url", help="real site URL: pins WP_HOME/WP_SITEURL (harden/fix)")
    g.add_argument("--ignore", action="append", help="glob of site-relative paths to ignore (repeatable)")
    g.add_argument("--lock-file", help="path of wpguard.lock (default: next to the config, else ./)")
    d = ap.add_argument_group("detection")
    d.add_argument("--sigs", action="append", help="file of extra regexes, one per line")
    d.add_argument("--hashdb", action="append", help="known-bad hash database (csv/txt/json/sqlite/.hdb)")
    d.add_argument("--hashdb-good", action="append", help="known-clean hash database (suppresses findings)")
    d.add_argument("--yara", action="append", help="YARA rule file (needs the yara or yr binary)")
    d.add_argument("--no-feeds", action="store_true", help="ignore downloaded signature feeds")
    d.add_argument("--no-behavior", action="store_true", help="disable heuristic behavior scoring")
    d.add_argument("--behavior-threshold", type=int, default=5)
    d.add_argument("--since", type=int, help="flag PHP modified / admins created in the last N days")
    d.add_argument("--no-net", action="store_true", help="skip wordpress.org / WPScan lookups")
    f = ap.add_argument_group("fix / harden")
    f.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    f.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    f.add_argument("--aggressive", action="store_true", help="also quarantine behavior/yara findings")
    f.add_argument("--clean-db", action="store_true")
    f.add_argument("--prune", action="store_true")
    f.add_argument("--delete-user", action="append")
    f.add_argument("--lockdown", action="store_true", help="also DISALLOW_FILE_MODS + no auto-update (blocks updates)")
    f.add_argument("--only", action="append", help="(undo) glob of files to restore")
    b = ap.add_argument_group("backup")
    b.add_argument("--out", help="backup: local directory | audit: output file")
    b.add_argument(
        "--to", action="append", help="destination: DIR | s3://bucket/prefix | rsync:HOST:/path (repeatable)"
    )
    b.add_argument("--keep", type=int, help="retention: keep the newest N backups per destination")
    b.add_argument("--no-uploads", action="store_true")
    b.add_argument("--encrypt-to", help="age recipient (age1...) to encrypt the archive")
    b.add_argument("--age-identity", help="age identity file (verify/restore of encrypted backups)")
    b.add_argument("--verify", action="store_true", help="backup: verify the archive before uploading")
    b.add_argument(
        "--keep-local", action="store_true", help="keep the local copy when only remote destinations are set"
    )
    b.add_argument("--from", dest="src", help="restore/verify/undo: backup file or quarantine dir")
    b.add_argument("--pull", help="remote backup: rsync the archive back into this directory")
    x = ap.add_argument_group("diff / lock / updates")
    x.add_argument("--core", action="store_true", help="(diff) core files only")
    x.add_argument("--plugin", action="append", help="(diff) only this plugin slug")
    x.add_argument("--max-lines", type=int, default=60)
    x.add_argument("--check", action="store_true", help="(lock) report drift instead of writing")
    x.add_argument("--apply", action="store_true", help="(updates) apply the safe updates on the real site")
    x.add_argument("--stage-db", help="(updates) existing empty database to use for staging")
    x.add_argument("--check-url", action="append", help="(updates) extra URL path to health-check")
    x.add_argument("--keep-stage", action="store_true")
    s = ap.add_argument_group("schedule")
    s.add_argument("--every", help="15m | 6h")
    s.add_argument("--daily", help="HH:MM")
    s.add_argument("--cron", help="raw cron expression")
    s.add_argument("--systemd", action="store_true")
    s.add_argument("--install", action="store_true")
    o = ap.add_argument_group("output")
    o.add_argument("--format", choices=["md", "json"], help="(audit)")
    o.add_argument("--log", action="append", default=[], help="(logs) access log file")
    o.add_argument("--top", type=int, default=10)
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
        print(DOC)
        return 2
    ap = build_parser()
    ns = ap.parse_args(argv)
    try:
        cfg = config.load(ns.config)
    except config.ConfigError as e:
        sys.exit(f"error: {e}")
    if ns.cmd == "setup":
        wpcli.setup()
        return 0
    if ns.cmd == "sigs":
        return feeds.sigs_cmd(ns.sites, cfg.feeds)
    ns.config_path = cfg.path
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
