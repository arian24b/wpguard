import pytest

from conftest import make_script
from wpguard import schedule as sch


def test_parse_when():
    assert sch.parse_when("15m", None, None) == ("*/15 * * * *", "*:0/15")
    assert sch.parse_when("6h", None, None) == ("0 */6 * * *", "0/6:00")
    assert sch.parse_when(None, "03:30", None) == ("30 3 * * *", "*-*-* 03:30:00")
    assert sch.parse_when(None, None, "5 4 * * 1") == ("5 4 * * 1", None)
    for bad in ("0m", "99m", "abc"):
        with pytest.raises(SystemExit):
            sch.parse_when(bad, None, None)
    with pytest.raises(SystemExit):
        sch.parse_when(None, "25:00", None)


def test_command_line(ns, tmp_path):
    a = ns("schedule")
    a.config_path = tmp_path / "wpguard.toml"
    cmd = sch.command("watch", "blog", a)
    assert " -m wpguard watch blog --notify --config " in cmd
    assert sch.command("sigs", "x", ns("schedule")).endswith("-m wpguard sigs update")
    assert "--notify" not in sch.command("backup", "blog", ns("schedule"))


def test_crontab_merge_is_idempotent_and_keeps_other_lines():
    mine = sch.cron_line("watch", "blog", "*/15 * * * *", "wpguard watch blog")
    base = "MAILTO=me\n0 1 * * * other-job\n"
    once = sch.merge_crontab(base, mine, "watch", "blog")
    twice = sch.merge_crontab(once, mine.replace("*/15", "*/5"), "watch", "blog")
    assert twice.count("# wpguard:watch:blog") == 1
    assert "*/5 * * * *" in twice
    assert "other-job" in twice
    assert "# wpguard:watch:blog" not in sch.strip_crontab(twice, "watch", "blog")
    assert "other-job" in sch.strip_crontab(twice, "watch", "blog")


def test_systemd_units():
    units = sch.systemd_units("backup", "my blog", "*-*-* 03:30:00", "/usr/bin/python -m wpguard backup blog")
    name = sch.unit_name("backup", "my blog")
    assert name == "wpguard-backup-my_blog"
    assert "ExecStart=/usr/bin/python -m wpguard backup blog" in units[f"{name}.service"]
    assert "OnCalendar=*-*-* 03:30:00" in units[f"{name}.timer"]


def test_add_install_and_remove_with_fake_crontab(bin_dir, tmp_path, ns):
    store = tmp_path / "crontab.txt"
    store.write_text("0 1 * * * keep-me\n")
    make_script(bin_dir, "crontab", f'if [ "$1" = "-l" ]; then cat {store}; else cat > {store}; fi\n')
    a = ns("schedule", "--every", "15m", "--install")
    assert sch.schedule(["add", "watch", "blog"], a).exit == 0
    text = store.read_text()
    assert "keep-me" in text
    assert "*/15 * * * *" in text
    assert text.count("# wpguard:watch:blog") == 1
    sch.schedule(["remove", "watch", "blog"], ns("schedule"))
    assert store.read_text() == "0 1 * * * keep-me\n"


def test_show_prints_only(bin_dir, tmp_path, ns, capsys):
    rep = sch.schedule(["show", "scan", "blog"], ns("schedule", "--daily", "02:00"))
    assert "0 2 * * *" in rep.lines[0]


def test_newline_in_target_is_rejected(ns):
    with pytest.raises(SystemExit, match="invalid target"):
        sch.schedule(["add", "watch", "blog\n* * * * * evil"], ns("schedule", "--every", "5m"))


def test_usage_errors(ns):
    with pytest.raises(SystemExit):
        sch.schedule(["add", "nonsense", "blog"], ns("schedule", "--every", "5m"))
    with pytest.raises(SystemExit):
        sch.schedule(["add", "watch", "blog"], ns("schedule", "--systemd", "--cron", "* * * * *"))
