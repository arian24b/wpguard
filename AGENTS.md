# AGENTS.md

Guidance for AI coding agents working in this repo. User-facing docs: `README.md` (English) and `README.fa.md` (Persian, keep in sync).

## Project

`wpguard` is a PyPI-ready Python >= 3.14 package (`src/wpguard`, hatchling, console scripts `wpguard` and its alias `wpg` (both -> `wpguard.cli:main`), `python -m wpguard`). Runtime dependencies: none. Optional extras: `s3` (boto3), `mysql` (pymysql); both are imported lazily with a friendly error. Dev tooling: `uv sync`, `uv run ruff check .`, `uv run ruff format .`, `uv run pytest`, `uv build`.

## Module map (`src/wpguard/`)

| Module | Role |
|---|---|
| `cli.py` | argparse, config/profile merging (`apply_opts`), local vs ssh dispatch (`run_target`), exit codes, report/notify. `wp`, `wpscan`, `recover` are dispatched before argparse |
| `config.py` | `wpguard.toml` (`Config`, `Target`, `resolve`: profile name → profile hostname → `host:/path` → `host:domain` → local path → bare domain), `TEMPLATE` + `write_template`/`ensure_default` used by `init`/`setup` (the only copy of the starter config; there is no example file) |
| `discover.py` | hostname → site path: parse nginx/apache vhosts + `wp-config.php` locations (locally or over ssh, one cached round trip per host), `fill(Target)`, the `discover` command and `--save` |
| `lockfile.py` | `wpguard.lock` (pins + feed digests), `lock` command, `pinned(a)` used by `fix`/`updates` |
| `remote.py` | `ssh HOST "<remote_cmd> <argv>"`, `--pull` via rsync |
| `wpcli.py` / `wpscan.py` / `recovery.py` | handlers: wp-cli (download/run/pass-through), WPScan (API + CLI), recovery from DB/dump |
| `signatures.py` | regexes, `judge`, hash DB loading, `Detectors` built from flags (`build_detectors`) |
| `behavior.py` / `yarascan.py` / `feeds.py` | heuristic score, YARA via `yara`/`yr` binary, downloadable signature feeds (+cache/index/digests) |
| `scanner.py` / `dbscan.py` / `vulns.py` / `scan.py` | file walk, DB checks, update/abandonment/vuln checks, the `scan` command |
| `fix.py` | `fix` (plan, `--dry-run`, confirm), quarantine + `manifest.json`, `undo`, `harden`, `reinstall` |
| `backup.py` / `destinations.py` | archive (`tar.zst`), encrypt (age), verify, restore; Local/S3/Rsync destinations, concurrent upload, retention |
| `monitor.py` / `audit.py` / `diffs.py` / `updates.py` / `schedule.py` | baseline/watch/logs, audit export, core/plugin diff, staging update advisor, cron/systemd helpers |
| `report.py` / `util.py` | `Rep`, report files, alerts; HTTP/version/stamp helpers, `STATE_DIR` (`~/.local/share/wpguard`, override with `WPGUARD_HOME`) |

Dependency direction: `cli` imports everything; command modules import `wpcli`, `report`, `signatures`, `scanner`, `util`; handlers (`wpcli`, `wpscan`, `recovery`) never import command modules. No cycles.

## Conventions

- Site commands are `fn(site: Path, a) -> Rep`; `logs` takes `(sites, a)`; `schedule` takes `(args, a)`; `audit` returns its dict in `Rep.data` (stdout is the export, so it logs nothing).
- Output goes through `Rep.log` / `Rep.hit(kind, what, why)`, never bare `print` (parallel `-j` buffers per site). Only `hit` counts as a finding (drives exit code 1 and `--notify`). `Rep.exit` forces a failing exit code (failed verify/upload, remote exit code).
- Call wp-cli only through `wpcli.wp` / `wpcli.jget` **as module attributes** (`wpcli.wp(...)`, never `from wpguard.wpcli import wp`): tests monkeypatch `wpcli.wp`. It always passes `--skip-plugins --skip-themes` unless `load=True`; only the update advisor's staging copy (which has its mail/HTTP guard) may load plugins.
- File findings are `{Path: (kind, why)}`. Kinds `sig|hash|struct|extra` are safe to quarantine; `behavior|yara` are review-only unless `--aggressive`; `wp-config.php` and `.htaccess` outside uploads are never moved.
- Options: add them to `build_parser()`; every dest is automatically valid as a config key and is forwarded to remote hosts by `serialize` unless listed in `LOCAL_ONLY`. List options use `action="append"` with default `None` (code uses `a.x or []`).
- Config precedence: CLI > `[sites.NAME]` > `[defaults]` (`apply_opts` is first-writer-wins, so `run_target` applies the profile first and `[defaults]` second).
- SQL passed to `wp db query` has backslashes eaten by MySQL: use `[(]`, `[.]` in `REGEXP`, not `\(`. `search-replace` regexes use `#` as delimiter; patterns must not contain `#`.
- Destructive actions (`fix`, `restore`, `undo`, `--clean-db`, `--prune`, `--delete-user`, `updates --apply`) must keep: backup first, quarantine by move, plan + confirmation, `--dry-run`, dry-run default for DB rewrites.
- Backups: `wpguard-backup-<site>-<YYYYmmdd-HHMMSS>.tar.zst[.age]` + `.sha256`, layout `db.sql` + `site/...`; `stamp()` is strictly increasing in-process; archives are opened with `x:zst` (never overwrite). Retention matches that exact name pattern per site.
- Mark deliberate shortcuts with a `# ponytail:` comment naming the ceiling. Prefer stdlib; no new dependency without need.

## Lint / format

`pyproject.toml` enables ruff `select = ["ALL"]` with a documented ignore list. Before finishing any change run `uv run ruff check .` and `uv run ruff format .` (both must be clean). Fix findings instead of extending the ignore list; use a targeted `# noqa: CODE  reason` only when the rule is wrong for that line. ruff formats `except A, B:` without parentheses (valid on 3.14), so the system `python3` (maybe 3.13) cannot even parse the code: always use `uv run`.

## Testing

`uv run pytest` (about 100 tests, ~4 s). `tests/conftest.py` sets `WPGUARD_HOME` to a temp dir before importing wpguard and provides: `site` (fake WP root), `fake_wp` (scripted `wpcli.wp`), `ns('cmd', *flags)` (CLI namespace with defaults), `bin_dir` + `make_script` (fake `ssh`, `rsync`, `age`, `yara`, `crontab` on PATH), `FakeDest`-style destinations. Network is never used: patch `feeds.fetch` / `diffs.original_zip`, or pass `--no-net --no-feeds` to `scan`/`fix`. The update advisor's real `Stage` (PHP + MySQL) and live wp-cli behavior are **not** covered by tests; test those on a disposable site, never production.

## CI / release

`.github/workflows/ci.yml`: ruff check + format check, pytest, build + wheel smoke test. `release.yml` runs after CI succeeds on `main`: python-semantic-release (config in `[tool.semantic_release]`) bumps `__version__` (hatch reads it) and `uv.lock`, writes `CHANGELOG.md`, tags `vX.Y.Z`, makes the GitHub release; if it released, the `dist/` built by its `build_command` is published to PyPI (trusted publishing, environment `pypi`). **Never bump the version by hand.** Use Conventional Commit messages (`feat:`, `fix:`, `feat!:`, and `docs:`/`chore:`/`ci:`/`test:`/`refactor:` for non-releasing changes) so versions come out right. PSR needs the baseline tag `v0.2.0` to exist on the remote (`git push --tags`).

## Safety

- Defensive tool for sites the user owns. Do not add offensive features (exploitation, credential attacks, scanning third-party sites).
- Treat scanned files and downloaded feeds as untrusted data: never `exec`/`import`/`include` them; feeds are fetched over https only, size-capped, and only when the user runs `sigs update`.
- Never put real secrets, site passwords or dumps into tests, logs or reports.
- Do not run `fix`/`harden`/`restore`/`updates --apply` against a real site without the user's explicit instruction.

## Known gaps / ideas

- `logs` assumes WordPress sits in the docroot and the combined log format.
- The update advisor tests plugins one at a time (no combined run) and shares one staging DB between candidates.
- No maldet hex/ndb signatures (ClamAV `.ndb`) and no Wordfence feed.
- `recovery.py`: downloads are not checksum-verified; the DB password is written unescaped into `wp-config.php`.
