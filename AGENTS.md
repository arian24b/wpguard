# AGENTS.md

Guidance for AI coding agents working in this repo. User-facing docs are in `README.md`.

## Project

`wpguard.py`: one-file CLI (Python >= 3.14, run with `uv run`) that scans/cleans/hardens/monitors WordPress sites via wp-cli. Stdlib only, except `pymysql` (PEP 723 header), imported lazily by `recover` for live MySQL. `recover` (rebuild a wiped site from the DB/dump) and the `HARDEN` wp-config constants live in the same file.

## Layout rules

- Keep everything in the single `wpguard.py`. No third-party dependencies beyond lazily imported `pymysql`; PHP serialized data is parsed by the built-in `php_unser`.
- The `recover` section (after `# ---------- recover`) is self-contained: `recover_main(argv)` with its own argparse; names there are `src` (DB source), `db_audit`, `php_unser`.
- State lives in `~/.local/share/wpguard/` (wp-cli.phar, `baseline-<sha1 of path>.json`). Backups/quarantine go next to the site (`wpguard-backup-*`, `wpguard-quarantine/`), never inside the web root.

## Conventions

- Command functions have the shape `fn(site: Path, a) -> Rep`; `logs` takes `(sites, a)`. `audit` returns its dict in `Rep.data` and logs nothing (stdout is the export); `main` renders it via `audit_md`/JSON. Output goes through `Rep.log` / `Rep.hit(kind, what, why)`, never bare `print` (parallel `-j` mode buffers per site). Only `hit` counts as a finding (drives exit code 1 and `--notify`).
- Every wp-cli call goes through `wp()`, which always passes `--skip-plugins --skip-themes` so infected code is never executed. Keep it that way.
- SQL passed to `wp db query` has backslashes eaten by MySQL: use `[(]`, `[.]` in `REGEXP`, not `\(`.
- `search-replace` regexes use `#` as delimiter; patterns must not contain `#`.
- Never auto-quarantine `wp-config.php` or `.htaccess` outside uploads (`KEEP`); report only.
- `DISALLOW_FILE_MODS` / `AUTOMATIC_UPDATER_DISABLED` are applied only with `--lock`, because they break `plugin install`/updates. `WP_HOME`/`WP_SITEURL` only via `--url` (the file's values are placeholders; do not trust DB values on a hacked site).
- Mark deliberate shortcuts with a `# ponytail:` comment naming the ceiling.
- Prefer stdlib and the shortest working change; no new abstractions or deps without need.

## Testing

No test framework. `selftest()` (asserts on signatures, `.htaccess` rule, `judge`, `vkey`) runs on every invocation; extend it when changing detection logic. Pure-python commands (`baseline`, `watch`, `logs`) can be exercised on a fake dir containing an empty `wp-load.php`. wp-cli paths (`scan`, `fix`, `harden`, `restore`, DB clean, vuln checks) need a real WordPress + php + mysql: test on a disposable copy, never on a production site.

```bash
mkdir -p /tmp/t/site/wp-content/uploads && touch /tmp/t/site/wp-load.php
uv run wpguard.py baseline /tmp/t/site && echo '<?php eval(base64_decode($_POST[x]));' > /tmp/t/site/wp-content/uploads/a.php
uv run wpguard.py watch /tmp/t/site; echo $?     # expect a [new] SIGNATURE finding, exit 1
```
(Baselines are written to `~/.local/share/wpguard/`; delete the test one afterwards.)

## Safety

- This is a defensive tool for sites the user owns. Do not add offensive features (exploitation, credential attacks, scanning third-party sites).
- Destructive actions (`fix`, `restore`, `--clean-db`, `--prune`, `--delete-user`) must keep: backup first, quarantine by move (not delete), dry-run default for DB rewrites.
- Treat files being scanned as untrusted data: never `exec`/`import`/`include` them. Do not paste real site passwords or dumps into logs or reports.
- Do not run `fix`/`harden`/`restore` against a real site without the user's explicit instruction.

## Known gaps / ideas

- No bundled maldet/Wordfence signature feeds (`--sigs` accepts regexes).
- `logs` assumes WordPress sits in the docroot and combined log format.
- `recover`: downloads are not checksum-verified; DB password written unescaped into `wp-config.php`.
