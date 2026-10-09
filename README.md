# wpguard

**English** | [فارسی](README.fa.md)

Single-file Python 3.14 + [uv](https://docs.astral.sh/uv/) CLI to scan, clean, harden and monitor hacked WordPress sites using [wp-cli](https://wp-cli.org/).

Everything lives in one file, `wpguard.py`. It uses only the standard library, except `pymysql`, which uv installs from the script header and which `recover` needs only against a live MySQL (not for `--dump`).

## Requirements

- Linux, `uv`, `php`, MySQL/MariaDB client on `PATH` (`baseline`, `watch`, `logs` need none of php/mysql)
- Run as the **site's file owner** (`sudo -u www-data ...`) so new files get correct ownership
- Shell access to the site's files and DB

## Quick start

```bash
uv run wpguard.py setup                              # download wp-cli (sha512 verified)
uv run wpguard.py scan /var/www/site                 # 1. look first, changes nothing
sudo -u www-data uv run wpguard.py fix /var/www/site --url https://your.site
uv run wpguard.py harden /var/www/site --lock --url https://your.site   # after everything is updated
uv run wpguard.py baseline /var/www/site             # snapshot the clean state
# cron, every 15 min:
*/15 * * * * /path/uv run /path/wpguard.py watch /var/www/site --notify
```

## Commands

| Command | What it does |
|---|---|
| `setup` | download wp-cli to `~/.local/share/wpguard/` |
| `scan SITE...` | report only: webshell signatures, PHP in uploads, core/plugin checksum extras, `wp-config.php`/`.htaccess`/`.user.ini` tampering, hidden files, mu-plugins, ClamAV (if installed), DB injections, new admins, odd cron hooks, outdated/abandoned/vulnerable plugins |
| `fix SITE...` | backup → scan → quarantine → delete chosen users → reinstall core/plugins/themes from wordpress.org → DB clean → harden → new salts → rescan → baseline |
| `harden SITE...` | block PHP in uploads, apply the hardening constants (`HARDEN` in the script), perms 755/644, `--prune` removes inactive plugins/themes |
| `baseline SITE...` | save SHA-256 of every file (media in uploads excluded; PHP/.htaccess there included) |
| `watch SITE...` | diff against baseline; exit 1 and alert on new/changed/removed files, flags signature matches |
| `logs [SITE...]` | find the entry point in access logs (brute force, xmlrpc, exploit POSTs, shell requests) |
| `backup SITE...` | full backup: DB dump (`wp db export`) + all site files in one `wpguard-backup-<site>-<time>.tar.zst` (zstd) with a `.sha256` sidecar, mode 600, never overwrites. Needs Python 3.14 (uv fetches it) |
| `restore SITE` | roll DB + files back from the latest backup (or `--from FILE.tar.zst`); verifies the `.sha256` first |
| `audit SITE...` | full inventory (WP/PHP versions, settings, plugins, themes, users by role, cron hooks, mu-plugins, drop-ins, `wp-config.php` constants with secrets redacted) plus all scan findings, exported as Markdown or JSON |
| `wp [--unsafe] SITE ARGS...` | run **any** wp-cli command on a site, e.g. `wpguard wp /var/www/x plugin list`. Plugins/themes are not loaded (safe on infected sites) unless you pass `--unsafe` |
| `wpscan [URL] ARGS...` | run the real [WPScan](https://wpscan.com/) with all its flags (local `wpscan`, else docker `wpscanteam/wpscan`). `WPSCAN_TOKEN` is added as `--api-token` if set; without it WPScan runs in free mode (no vulnerability data) |
| `recover ARGS...` | rebuild a wiped site from the DB or a dump (see `recover --help`) |

## Options

| Option | Meaning |
|---|---|
| `--sites-file F` | extra site paths, whitespace separated |
| `-j N` | scan N sites in parallel (output printed per site at the end) |
| `--report out.{json,html,txt}` | write a report |
| `--notify` | alert on findings (env below) |
| `--sigs FILE` | extra regex signatures, one per line (e.g. exported from maldet/Wordfence sets) |
| `--since DAYS` | flag PHP modified / admins created in the last N days |
| `--hashdb FILE` | (`scan`/`fix`/`audit`) known-**bad** hash database; repeatable. Any file containing hex md5/sha1/sha256: `.csv`, `.tsv`, `.txt`, `md5sum`/`sha256sum` output, `.json`, `.gz`, SQLite (`.db`/`.sqlite`). Algorithm is detected by hash length; matching files are reported (and quarantined by `fix`) |
| `--hashdb-good FILE` | known-**clean** hash database (same formats); matching files are skipped, which removes false positives |
| `--no-net` | skip wordpress.org / WPScan lookups |
| `--clean-db` | really apply DB cleanup (`fix` otherwise only dry-runs it) |
| `--delete-user ID` | (`fix`) delete a rogue admin, repeatable |
| `--prune` | (`harden`/`fix`) delete inactive plugins and themes |
| `--url URL` | pin `WP_HOME`/`WP_SITEURL` (defeats DB siteurl hijack) |
| `--lock` | also set `DISALLOW_FILE_MODS` + `AUTOMATIC_UPDATER_DISABLED` (blocks updates; use last) |
| `--log F` / `--top N` | (`logs`) log files (plain or `.gz`) / rows per section |
| `--format md\|json` / `--out FILE` | (`audit`) export format (defaults to json if `--out` ends in `.json`, else md) and destination (default stdout) |
| `--out DIR` | (`backup`) destination directory (default: next to the site, must be outside it). `audit` uses `--out` as the output file |
| `--no-uploads` | (`backup`) leave out `wp-content/uploads` |
| `--from FILE` | (`restore`) specific backup archive |

Environment: `WPGUARD_TELEGRAM_TOKEN` + `WPGUARD_TELEGRAM_CHAT`, `WPGUARD_EMAIL` (local SMTP), `WPSCAN_TOKEN` (free wpscan.com key, adds CVE lookups).

## Guide: cleaning a hacked site

1. **Isolate.** Put the site in maintenance mode or restrict by IP while you work.
2. **Scan first.** `scan SITE --since 14 --report before.html`. Read every line; note unknown admins and `VULN`/`abandoned`/`source` entries (probable entry point).
3. **Find the hole.** `logs SITE` (use `--log` for non-default paths). Look at POSTs to plugin PHP files and who requested the files you later quarantine.
4. **Fix.** `fix SITE --url https://your.site --delete-user 7`. Review the DB cleanup dry-run output, then rerun with `--clean-db` if the matches are really malicious.
5. **Premium/custom plugins** reported as `SKIP` are not on wordpress.org: reinstall them from the vendor by hand. Never use nulled copies.
6. **Manual items `fix` cannot do:** change DB, FTP/SSH, hosting and WordPress passwords; review `wp-config.php`; remove unknown users; check quarantine for false positives.
7. **Lock down.** After all updates: `harden SITE --lock --url ...`. To update later, temporarily remove `DISALLOW_FILE_MODS` (`wp config delete DISALLOW_FILE_MODS`).
8. **Monitor.** `baseline SITE` now, `watch` from cron. Re-run `baseline` after every legitimate update, or `watch` reports it.
9. **Rollback** if something broke: `restore SITE`; quarantined files are in `../wpguard-quarantine/` (move back by hand).

## Guide: wp-cli, WPScan and hash databases

```bash
uv run wpguard.py wp /var/www/site plugin list --status=active --format=json
uv run wpguard.py wp /var/www/site user list --role=administrator
uv run wpguard.py wp --unsafe /var/www/site cron event list      # loads plugins/themes: only on a trusted site

export WPSCAN_TOKEN=xxxx                                           # free key from wpscan.com/api (25 req/day); optional
uv run wpguard.py wpscan https://your.site --enumerate vp,vt,u --plugins-detection mixed

uv run wpguard.py scan /var/www/site --hashdb malware.csv --hashdb-good vendor-clean.sha256
```
`wpscan` needs `gem install wpscan` or docker. It probes the live site over HTTP, so use it only on sites you own. Hash databases are matched against every file (up to 50 MB), so a large database on a big site takes longer; use known-bad lists from sources you trust (maldet, your own incident samples).

## Guide: backup and restore

```bash
uv run wpguard.py backup /var/www/site --out /srv/backups          # DB + files (+ uploads)
uv run wpguard.py backup /var/www/site --no-uploads                # small, code + DB only
uv run wpguard.py restore /var/www/site --from /srv/backups/wpguard-backup-site-20261009-113206.tar.zst
```
The archive contains `db.sql` and the site tree under `site/`; it includes `wp-config.php` (DB password), so keep it private. `fix` makes an uploads-free backup automatically before changing anything. `restore` overwrites files from the archive and re-imports the DB; it does not delete files that are not in the archive.

## Guide: audit export

```bash
uv run wpguard.py audit /var/www/site --out site-audit.md
uv run wpguard.py audit /var/www/a /var/www/b -j 2 --format json --out audits.json   # list of sites
```
Read-only (same checks as `scan`, plus inventory). Use it for before/after comparison or to hand a report to a client; DB password, DB user and salts are redacted, but emails and usernames are included, so share carefully.

## Guide: site fully wiped

```bash
uv run wpguard.py recover --dump /backup/site.sql --db NAME --user U --password 'P' --host 127.0.0.1 --out site --list   # inventory only
uv run wpguard.py recover --dump /backup/site.sql ... --out site     # download core/plugins/themes at DB versions
```
Then restore `uploads/` and premium code from a backup, point the vhost at `site/`, and continue from step 4 above.

## Development

`pyproject.toml` configures ruff with `select = ["ALL"]` (the ignores are listed with reasons there).

```bash
uv run ruff check .
uv run ruff format .
```

## What it does NOT do

- It is heuristic. Obfuscated commercial plugins may be flagged (false positives) and novel shells may be missed. It does not replace a WAF or server-level scanning.
- DB cleaning is regex-based. Always read the dry run.
- Quarantine paths are outside the web root, in `<site parent>/wpguard-quarantine/`; backups in `<site parent>/wpguard-backup-*`. Delete them when no longer needed (they contain old, possibly malicious files and DB dumps).
- `fix` installs the **latest** plugin/theme versions; major jumps can break compatibility.
- Scans never execute site code: wp-cli runs with `--skip-plugins --skip-themes`.

## Safety notes

Use only on sites you own or are authorised to administer. Back up before any `fix`/`restore` (the tool does, but verify `db.sql` is non-empty).
