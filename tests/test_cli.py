import json

import pytest

from wpguard import cli, feeds


def test_baseline_then_watch_exit_codes(site, tmp_path, capsys):
    assert cli.main(["baseline", str(site)]) == 0
    assert cli.main(["watch", str(site)]) == 0
    (site / "wp-content/uploads/a.php").write_text("<?php eval(base64_decode($_POST[1]));")
    assert cli.main(["watch", str(site), "--report", str(tmp_path / "r.json")]) == 1
    report = json.loads((tmp_path / "r.json").read_text())
    assert report[0]["hits"][0]["kind"] == "new"
    assert "SIGNATURE MATCH" in capsys.readouterr().out


def test_profiles_all_and_config_defaults(site, tmp_path, capsys):
    other = tmp_path / "other"
    other.mkdir()
    (other / "wp-load.php").write_text("<?php")
    cfg = tmp_path / "wpguard.toml"
    cfg.write_text(f'[sites.blog]\npath = "{site}"\n[sites.other]\npath = "{other}"\n')
    assert cli.main(["baseline", "--all", "--config", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert out.count("baseline:") == 2
    assert cli.main(["watch", "blog", "--config", str(cfg)]) == 0


def test_unknown_option_in_config_is_a_clean_error(site, tmp_path):
    cfg = tmp_path / "wpguard.toml"
    cfg.write_text(f'[sites.blog]\npath = "{site}"\nbogus_option = 1\n')
    with pytest.raises(SystemExit, match="unknown option 'bogus_option'"):
        cli.main(["baseline", "blog", "--config", str(cfg)])


def test_requires_a_site_and_a_wordpress_root(tmp_path, fake_wp):
    with pytest.raises(SystemExit, match="at least one SITE"):
        cli.main(["scan"])
    with pytest.raises(SystemExit, match="not WordPress roots"):
        cli.main(["scan", str(tmp_path)])


def test_parallel_fix_requires_yes(site, fake_wp):
    with pytest.raises(SystemExit, match="--yes"):
        cli.main(["fix", str(site), "-j", "2"])


def test_scan_end_to_end_with_fake_wp(site, fake_wp, tmp_path, capsys):
    (site / "wp-content/uploads/a.php").write_text("<?php")
    code = cli.main(["scan", str(site), "--no-net", "--no-feeds", "--report", str(tmp_path / "r.html")])
    assert code == 1
    out = capsys.readouterr().out
    assert "[struct] wp-content/uploads/a.php" in out
    assert "<h2>" in (tmp_path / "r.html").read_text()


def test_audit_exports_md_and_json(site, fake_wp, tmp_path):
    fake_wp.responses[("core", "version")] = (0, "6.9\n", "")
    fake_wp.responses[("plugin", "list")] = (
        0,
        json.dumps([{"name": "akismet", "version": "5", "status": "active", "update": "none"}]),
        "",
    )
    fake_wp.responses[("user", "list")] = (
        0,
        json.dumps(
            [
                {
                    "ID": 1,
                    "user_login": "a",
                    "user_email": "e",
                    "roles": "administrator",
                    "user_registered": "2020-01-01 00:00:00",
                }
            ]
        ),
        "",
    )
    (site / "wp-config.php").write_text("<?php define('DB_PASSWORD','s3cret'); define('WP_DEBUG', false);")
    md = tmp_path / "a.md"
    assert cli.main(["audit", str(site), "--no-net", "--no-feeds", "--out", str(md)]) == 0
    text = md.read_text()
    assert "# WordPress audit" in text
    assert "s3cret" not in text
    assert "[redacted]" in text
    js = tmp_path / "a.json"
    cli.main(["audit", str(site), "--no-net", "--no-feeds", "--out", str(js)])
    data = json.loads(js.read_text())
    assert data["wordpress"] == "6.9"
    assert data["users"]["by_role"] == {"administrator": 1}


def test_sigs_list_runs_without_a_site(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(feeds, "FEED_DIR", tmp_path)
    monkeypatch.setattr(feeds, "INDEX", tmp_path / "index.json")
    assert cli.main(["sigs", "list"]) == 0
    assert "maldet-hashes" in capsys.readouterr().out


def test_schedule_show_via_cli(capsys):
    assert cli.main(["schedule", "show", "watch", "blog", "--every", "10m"]) == 0
    assert "*/10 * * * *" in capsys.readouterr().out


def test_version_and_help_paths(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert "wpguard 0." in capsys.readouterr().out
    assert cli.main([]) == 2


def test_notify_called_on_findings(site, fake_wp, monkeypatch):
    sent = []
    monkeypatch.setattr(cli, "notify", lambda text, cfg=None: sent.append(text))
    (site / "wp-content/uploads/a.php").write_text("<?php")
    cli.main(["scan", str(site), "--no-net", "--no-feeds", "--notify"])
    assert "a.php" in sent[0]


def test_init_creates_a_starter_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["init"]) == 0
    assert (tmp_path / "wpguard.toml").read_text().startswith("# wpguard configuration")
    assert cli.main(["init"]) == 1  # exists
    assert "already exists" in capsys.readouterr().out
    assert cli.main(["init", "--force"]) == 0
    assert cli.main(["init", "--config", str(tmp_path / "sub/other.toml")]) == 0


def test_setup_downloads_wpcli_and_creates_default_config(tmp_path, monkeypatch):
    from wpguard import config, wpcli

    downloaded = []
    monkeypatch.setattr(wpcli, "setup", lambda: downloaded.append(True))
    monkeypatch.setattr(config, "SEARCH", (tmp_path / "no.toml", tmp_path / "cfg/wpguard.toml"))
    assert cli.main(["setup"]) == 0
    assert downloaded
    assert (tmp_path / "cfg/wpguard.toml").exists()
