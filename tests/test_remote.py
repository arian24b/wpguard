from pathlib import Path

from conftest import make_script
from wpguard import cli, remote


def test_build_quotes_arguments():
    assert remote.build("mina", "uvx wpguard", ["scan", "/var/www/my site", "--since", "7"]) == [
        "ssh", "mina", "uvx wpguard scan '/var/www/my site' --since 7",
    ]  # fmt: skip


def test_run_streams_exit_code(bin_dir, tmp_path):
    log = tmp_path / "ssh.log"
    make_script(bin_dir, "ssh", f'printf "%s\\n" "$@" > {log}; echo remote-says-hi; exit 1\n')
    rep = remote.run("mina", "uvx wpguard", ["scan", "/var/www/x"], live=False)
    assert rep.exit == 1
    assert "remote-says-hi" in rep.lines
    assert log.read_text().split("\n")[:2] == ["mina", "uvx wpguard scan /var/www/x"]


def test_pull_backup_via_rsync(bin_dir, tmp_path):
    seen = tmp_path / "rsync.args"
    make_script(bin_dir, "rsync", f'printf "%s\\n" "$@" > {seen}\n')
    make_script(
        bin_dir, "ssh", "echo '  backup -> /srv/b/wpguard-backup-x-20260101-000000.tar.zst (1 KiB, sha256 abc...)'\n"
    )
    rep = remote.run("mina", "uvx wpguard", ["backup", "/var/www/x"], live=False, pull=str(tmp_path / "pulled"))
    assert any("pulled wpguard-backup-x" in line for line in rep.lines)
    args = seen.read_text().split("\n")
    assert "mina:/srv/b/wpguard-backup-x-20260101-000000.tar.zst" in args
    assert "mina:/srv/b/wpguard-backup-x-20260101-000000.tar.zst.sha256" in args


def test_pull_without_path_in_output():
    assert "could not find" in remote.pull_backup("mina", "nothing here", Path("/tmp"))


def test_cli_dispatches_adhoc_host_over_ssh(bin_dir, tmp_path):
    log = tmp_path / "ssh.log"
    make_script(bin_dir, "ssh", f'printf "%s\\n" "$@" > {log}; exit 0\n')
    code = cli.main(["scan", "mina:/var/www/x", "--since", "7", "--no-net", "--report", str(tmp_path / "r.txt")])
    assert code == 0
    host, cmdline = log.read_text().split("\n")[:2]
    assert host == "mina"
    assert cmdline == "uvx wpguard scan /var/www/x --since 7 --no-net"  # --report is local-only, not forwarded


def test_cli_profile_with_ssh_and_options(bin_dir, tmp_path):
    log = tmp_path / "ssh.log"
    make_script(bin_dir, "ssh", f'printf "%s\\n" "$@" > {log}; exit 1\n')
    cfg = tmp_path / "wpguard.toml"
    cfg.write_text(
        '[defaults]\nno_net = true\n[sites.mina]\nssh = "mina"\npath = "/var/www/mina"\nremote_cmd = "~/bin/uvx wpguard"\nsince = 3\n'
    )
    code = cli.main(["scan", "mina", "--config", str(cfg)])
    assert code == 1  # remote exit code propagates (findings)
    assert log.read_text().split("\n")[1] == "~/bin/uvx wpguard scan /var/www/mina --since 3 --no-net"
