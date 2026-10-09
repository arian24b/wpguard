# wpguard

[![CI](https://github.com/arian24b/wpguard/actions/workflows/ci.yml/badge.svg)](https://github.com/arian24b/wpguard/actions/workflows/ci.yml)

**English** | [فارسی](README.fa.md)

Command line tool to scan, clean, harden, back up and monitor hacked WordPress sites, built on [wp-cli](https://wp-cli.org/). Python 3.14, no runtime dependencies (`boto3` for S3 and `pymysql` for `recover` are optional extras).

## Install

```bash
uvx wpguard --help                 # run without installing (`uvx --from wpguard wpg` for the short name) (uv downloads Python 3.14 if needed)
uv tool install wpguard            # or: pipx install wpguard
pip install 'wpguard[s3]'          # S3 backups (boto3)   |   'wpguard[mysql]' for `recover` against a live MySQL
wpg --help                         # `wpg` is a short alias of `wpguard` (installed together)
wpguard setup                      # downloads wp-cli (sha512 verified) and creates ~/.config/wpguard/wpguard.toml
wpguard init                       # (optional) starter ./wpguard.toml for this project
```

Requirements: Linux, `php` and a MySQL/MariaDB client for the site commands (not for `baseline`, `watch`, `logs`, `verify`). Run as the **site's file owner** (`sudo -u www-data wpguard ...`) so new files keep the right ownership. Optional tools it uses when present: `yara` (or YARA-X `yr`), `clamscan`, `age`, `rsync`, `ssh`, `wpscan`/docker.

## Quick start

```bash
wpguard scan /var/www/site                       # 1. look first, changes nothing
wpguard fix  /var/www/site --dry-run             # 2. see the full plan
wpguard fix  /var/www/site --url https://your.site     # 3. does it (asks to confirm; --yes to skip)
wpguard undo /var/www/site                       #    false positive? put quarantined files back
wpguard harden /var/www/site --lockdown --url https://your.site   # after everything is updated
wpguard baseline /var/www/site                   # snapshot the clean state
wpguard schedule add watch /var/www/site --every 15m --install    # alert on any change
```

`SITE` can be a path, a **profile name** from `wpguard.toml`, a **hostname** (`blog.example.com`), or **`host:/path`** / **`host:domain`** to run it over ssh (see below).

## Commands

| Command | What it does |
|---|---|
| `scan` | read-only: signatures, hash DBs, YARA, behavior score, `wp-config.php`/`.htaccess`/`.user.ini` tampering, hidden files, mu-plugins, ClamAV, core/plugin checksum extras, DB injections, new admins, odd cron, outdated/abandoned/vulnerable plugins |
| `fix` | scan → **plan** → confirm → backup → quarantine → reinstall core/plugins/themes (pinned versions if locked) → DB clean → harden → new salts → rescan → baseline. `--dry-run` stops after the plan |
| `undo` | move quarantined files back (latest quarantine, `--from DIR`, `--only GLOB`) |
| `harden` | block PHP in uploads, apply wp-config constants, perms 755/644; `--prune` removes inactive plugins/themes |
| `diff` | unified diff of every modified core/plugin file against the official wordpress.org file |
| `backup` | DB dump + all files → `wpguard-backup-<site>-<time>.tar.zst`, optional encryption, concurrent upload to several destinations, retention, verification |
| `verify` | check a backup (checksum, readable archive, plausible `db.sql`, WordPress files present) |
| `restore` | re-import the DB and files from a backup (checksum verified first) |
| `baseline` / `watch` | SHA-256 snapshot / diff against it; exit 1 and alert on new, changed or removed files |
| `lock` | write `wpguard.lock` (pinned core/plugin/theme versions and feed digests); `lock --check` reports drift |
| `updates` | try every pending update on a **staging copy**, report which ones break the site; `--apply` applies the safe ones |
| `logs` | find the entry point in access logs: brute force, xmlrpc, exploit POSTs, requests to shells you quarantined |
| `audit` | full inventory + findings as Markdown or JSON (secrets redacted) |
| `sigs list` / `sigs update` | signature feeds (maldet hashes, YARA rule sets) |
| `schedule add\|remove\|show JOB SITE` | cron lines or systemd user timers for `watch backup scan sigs updates` |
| `wp [--unsafe] SITE ARGS...` | run **any** wp-cli command (plugins/themes not loaded unless `--unsafe`) |
| `wpscan [URL] ARGS...` | run the real [WPScan](https://wpscan.com/) (local binary or docker); `WPSCAN_TOKEN` becomes `--api-token` |
| `recover ARGS...` | rebuild a wiped site from the DB or a dump (`recover --help`) |
| `setup` | download wp-cli and create `~/.config/wpguard/wpguard.toml` if no config exists |
| `init` | create a commented starter `./wpguard.toml` (or `--config FILE`; `--force` overwrites) |
| `discover [HOST...]` | find WordPress sites by hostname on this machine or ssh hosts; `--save` adds them to the config |

## Config file and profiles

`wpguard setup` (global, `~/.config/wpguard/wpguard.toml`) or `wpguard init` (this directory) writes a commented starter file; `wpguard discover --save` fills in sites for you. It is searched in `./` then `~/.config/wpguard/`, or use `--config FILE`:

```toml
[defaults]
since = 14
keep = 7

[sites.blog]
path = "/var/www/blog"
url = "https://blog.example.com"
to = ["/srv/backups", "s3://my-bucket/blog", "rsync:backup:/srv/backups/blog"]

[sites.mina]
ssh = "mina"                      # a host from ~/.ssh/config
path = "/var/www/mina"            # path on the remote host
```

Now `wpguard scan blog`, `wpguard backup --all`, `wpguard fix mina --dry-run` work. Any CLI option can be a config key (long name, dashes → underscores). Precedence: command line > `[sites.NAME]` > `[defaults]`. Unknown keys are an error. `[notify]` holds `telegram_token`, `telegram_chat`, `email` (env vars `WPGUARD_TELEGRAM_TOKEN`, `WPGUARD_TELEGRAM_CHAT`, `WPGUARD_EMAIL` win; keep the file private).

### wpguard.lock

`wpguard lock blog` records core, plugin and theme versions (and the digests of downloaded signature feeds) in `wpguard.lock` next to the config; commit it. Then:

- `fix` reinstalls the **pinned** versions instead of "latest" (no surprise major jumps while cleaning),
- `lock --check` exits 1 when something drifted (new plugin, version changed, feed changed): a good cron job,
- `updates --apply` refreshes the pins for the updates it applied.

## Sites by hostname

Any site command accepts the site's **hostname** instead of its path:

```bash
wpguard discover                         # list WordPress sites on this machine (nginx/apache vhosts + wp-config.php)
wpguard discover mina --save             # same on the ssh host `mina`, and add them to wpguard.toml
wpguard scan blog.example.com            # by hostname (profile `domain`/`url`, or found from this machine's vhosts)
wpguard backup mina:blog.example.com     # hostname on an ssh host: path is looked up over ssh, then the command runs there
```

Resolution order for `SITE`: profile name → profile `domain`/`url` host → `host:/path` → `host:domain` → an existing local path → a bare domain looked up in this machine's web-server configs. A profile may omit `path` when it has a `domain` (and optionally `ssh`): the path is then found from the vhosts. Discovery reads `/etc/nginx`, `/etc/apache2`, `/etc/httpd` (`server_name`/`ServerName`/`ServerAlias` + `root`/`DocumentRoot`) and `wp-config.php` under `/var/www /srv /home /opt`; unusual layouts can still be registered by hand. `www.` variants match.

## Remote sites over SSH

```bash
wpguard scan mina:/var/www/site          # ad-hoc: host from ~/.ssh/config, path on the remote
wpguard scan mina                        # profile with ssh = "mina"
wpguard backup mina --to s3://bkt/mina --pull ./pulled     # remote backup, archive rsync'ed back
```

wpguard runs the same command on the remote machine through `ssh <host> <remote_cmd> ...`, so your `~/.ssh/config` (keys, ProxyJump, ports) is used as-is. The remote needs `uv` (the default `remote_cmd` is `uvx wpguard`; set `remote_cmd = "~/.local/bin/wpguard"` per profile if it is installed). Your CLI options and config values are forwarded; `--config`, `--report`, `-j`, `--pull` stay local. Exit codes propagate (1 = findings). Paths in options such as `--hashdb` are read **on the remote host**.

## Detection

- **Signatures** (built in) and `--sigs FILE` (your own regexes; blank/invalid lines are ignored).
- **Hash databases**: `--hashdb` known-bad, `--hashdb-good` known-clean (suppresses findings). Any file with hex md5/sha1/sha256: csv, txt, json, `.gz`, ClamAV `.hdb`, SQLite.
- **Behavior score** (`--behavior-threshold`, default 5; `--no-behavior`): dangerous-call density, hex/chr obfuscation, high entropy, very long lines, double extensions, PHP in asset dirs, names used by known malware, mtime far newer than siblings or in the future. **Review only**: `fix` does not quarantine behavior or YARA findings unless you pass `--aggressive`.
- **YARA**: `--yara RULES.yar` (repeatable) through the `yara` or `yr` binary.
- **Feeds**: `wpguard sigs update` downloads maldet md5 hashes ([rfxn](https://www.rfxn.com/projects/linux-malware-detect/)), [php-malware-finder](https://github.com/nbs-system/php-malware-finder) (LGPL-3.0) and [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) webshell rules (Detection Rule License 1.1: attribution). They are cached under `~/.local/share/wpguard/feeds`, used automatically by `scan`/`fix` (`--no-feeds` disables) and their digests are pinned by `lock`. Add your own with `[feeds.NAME]` in the config.
- **Core/plugin diff**: `wpguard diff SITE [--core] [--plugin SLUG]` shows what an attacker changed in an official file.
- `--ignore GLOB` (repeatable, or `ignore = [...]` in config) silences known-good paths.

## Safer fix

`fix` always prints the plan (what will be quarantined, what is *only* flagged for review, which users will be deleted, which versions will be installed) and then asks `Proceed? [y/N]`. Non-interactive runs refuse unless `--yes`; `-j > 1` requires `--yes` or `--dry-run`. Quarantined files are **moved** (never deleted) into `<site parent>/wpguard-quarantine/<site>-<time>/files/` with a `manifest.json`; `wpguard undo` puts them back. `wp-config.php` and `.htaccess` outside uploads are only ever reported. A backup (without uploads) is taken before anything changes.

## Backups

```bash
wpguard backup blog                                   # to the destinations in the profile (or next to the site)
wpguard backup /var/www/site --out /srv/backups --verify --keep 7
wpguard backup blog --to s3://bkt/blog --to rsync:backup:/srv/b --encrypt-to age1... --keep 14
wpguard verify blog --out /srv/backups                # latest local backup
wpguard restore /var/www/site --from /srv/backups/wpguard-backup-site-20261009-113206.tar.zst
```

Archive layout: `db.sql` + `site/...` in a zstd tar, mode 600, with a `.sha256` sidecar; an existing backup is never overwritten. **Destinations** (`--to`, repeatable): a local directory, `s3://bucket/prefix` (`boto3`, standard `AWS_*` env, `AWS_ENDPOINT_URL` for MinIO/R2), `rsync:HOST:/path` (HOST may be an ssh alias). All destinations upload **concurrently**; each is size-checked after upload and one failing destination does not stop the others (exit 1). **Retention** (`--keep N`) keeps the newest N per destination and site, and only runs after a verified upload. `--verify` checks the archive before uploading. `--encrypt-to` needs [`age`](https://age-encryption.org); restore/verify of such files needs `--age-identity KEY`. `--no-uploads` leaves out `wp-content/uploads`. The archive contains `wp-config.php` (DB password): keep it private.

## Update advisor

`wpguard updates SITE` lists pending core/plugin/theme updates and tests **each one** on a throwaway copy: files (without uploads) plus a cloned database, served by PHP's built-in server on 127.0.0.1. After every update it requests `/`, `/wp-login.php`, `/wp-admin/` (add more with `--check-url`) and reads the server log; 5xx pages and PHP fatals are reported as `BREAKS`, then that plugin is rolled back and the next one is tested alone. Inside the copy outgoing mail and HTTP (except wordpress.org) are blocked and WP-Cron is off, so loading the site's plugins cannot e-mail customers. Needs `php` and a MySQL user that may `CREATE DATABASE` (or `--stage-db EXISTING_EMPTY_DB`). `--apply` backs up and then updates only the items that passed. `--keep-stage` leaves the copy for inspection.

## Scheduler

```bash
wpguard schedule show backup blog --daily 03:30          # prints the cron line
wpguard schedule add watch blog --every 15m --install    # writes it to your crontab (idempotent, marker comments)
wpguard schedule add backup blog --daily 03:30 --systemd --install    # systemd user timer
wpguard schedule remove watch blog
```

Jobs: `watch backup scan sigs updates`; `watch`, `scan` and `updates` run with `--notify`. Put alert settings in `[notify]` (cron has no environment). For systemd user timers to run while logged out: `loginctl enable-linger $USER`.

## Other guides

**Cleaning a hacked site**: isolate the site → `scan --since 14` → `logs` (find the hole: POSTs to plugin PHP, requests to files you later quarantine) → `fix --dry-run`, then `fix` → reinstall premium plugins marked `SKIP` from the vendor → change DB/FTP/SSH/WordPress passwords and remove unknown admins → `harden --lockdown` after updating → `baseline` + `schedule add watch`.

**Wiped site**: `wpguard recover --dump site.sql --db NAME --user U --out site --list` (inventory), then without `--list` to download core/plugins/themes at the versions the DB records; restore uploads and premium code from a backup and continue as above.

**Audit**: `wpguard audit blog --out blog.md` (or `.json`): versions, settings, plugins, themes, users by role, cron hooks, mu-plugins, drop-ins, `wp-config.php` constants with DB user/password/salts redacted, plus all findings.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .      # ruff, select = ["ALL"] (ignores are listed with reasons in pyproject.toml)
uv run pytest
uv build
```

GitHub Actions (`.github/workflows/ci.yml`) runs ruff, pytest and a wheel smoke test on every push and pull request. Pushing a `v*` tag runs `release.yml` and publishes to PyPI through trusted publishing (configure the publisher once on pypi.org).

## What it does NOT do

- Detection is heuristic. Obfuscated commercial plugins can be flagged and new shells can be missed; it does not replace a WAF or server-level scanning.
- DB cleaning is regex-based: read the dry run. `fix` installs pinned versions if locked, otherwise the **latest** (a major jump can break compatibility; `updates` exists to test that).
- The update advisor needs a real PHP + MySQL environment; DB migrations done by a plugin update can leave the staging DB changed between candidates.
- Remote mode requires `uv` (or an installed `wpguard`) on the remote host.
- Quarantine and backups sit next to the site (outside the web root); delete them when no longer needed, they hold old malicious files and database dumps.

## Safety and license

Use only on sites you own or are authorised to administer. MIT license (`LICENSE`). Third-party signature feeds keep their own licenses (see above).
