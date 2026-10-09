import json

from wpguard import fix as fixmod
from wpguard.fix import quarantine, split_findings, undo
from wpguard.report import Rep

SHELL = b"<?php @eval(base64_decode($_POST['x']));"


def make_findings(site):
    shell = site / "wp-content/plugins/akismet/evil.php"
    shell.write_bytes(SHELL)
    up = site / "wp-content/uploads/a.php"
    up.write_bytes(b"<?php")
    beh = site / "wp-content/plugins/akismet/odd.php"
    beh.write_text("<?php // odd")
    cfg = site / "wp-config.php"
    return {
        shell: ("sig", "sig"),
        up: ("struct", "php in uploads"),
        beh: ("behavior", "score 6"),
        cfg: ("struct", "wp-config suspicious"),
    }


def test_split_findings(site):
    hits = make_findings(site)
    move, review = split_findings(site, hits, aggressive=False)
    assert {p.name for p in move} == {"evil.php", "a.php"}
    assert {p.name for p in review} == {"odd.php", "wp-config.php"}
    move2, review2 = split_findings(site, hits, aggressive=True)
    assert "odd.php" in {p.name for p in move2}
    assert "wp-config.php" in {p.name for p in review2}  # never auto-moved, even when aggressive


def test_quarantine_writes_manifest_and_undo_restores(site, ns):
    hits = make_findings(site)
    move, _ = split_findings(site, hits, aggressive=False)
    qroot = site.parent / "wpguard-quarantine" / f"{site.name}-20260101-000000"
    rep = Rep(site, quiet=True)
    assert quarantine(site, move, qroot, rep) == 2
    assert not (site / "wp-content/uploads/a.php").exists()
    manifest = json.loads((qroot / "manifest.json").read_text())
    assert {i["path"] for i in manifest["items"]} == {"wp-content/plugins/akismet/evil.php", "wp-content/uploads/a.php"}
    assert (qroot / "files/wp-content/uploads/a.php").exists()

    # --only restores just what matches; --dry-run changes nothing
    a = ns("undo", "--only", "wp-content/uploads/*", "--dry-run")
    a.src = None
    undo(site, a)
    assert not (site / "wp-content/uploads/a.php").exists()
    a = ns("undo", "--only", "wp-content/uploads/*")
    undo(site, a)
    assert (site / "wp-content/uploads/a.php").exists()
    assert not (site / "wp-content/plugins/akismet/evil.php").exists()
    undo(site, ns("undo"))
    assert (site / "wp-content/plugins/akismet/evil.php").exists()


def test_undo_skips_existing_and_refuses_traversal(site, ns):
    qroot = site.parent / "wpguard-quarantine" / f"{site.name}-1"
    (qroot / "files").mkdir(parents=True)
    (qroot / "files/ok.php").write_text("q")
    (site / "ok.php").write_text("already here")
    (qroot / "manifest.json").write_text(json.dumps({"items": [{"path": "ok.php"}, {"path": "../../escape.php"}]}))
    rep = undo(site, ns("undo"))
    text = "\n".join(rep.lines)
    assert "a file already exists" in text
    assert "refusing path outside the site" in text
    assert (site / "ok.php").read_text() == "already here"


def test_fix_dry_run_changes_nothing(site, ns, fake_wp):
    make_findings(site)
    fake_wp.responses[("plugin", "list")] = (0, json.dumps([{"name": "akismet"}]), "")
    fake_wp.responses[("theme", "list")] = (0, "[]", "")
    rep = fixmod.fix(site, ns("fix", "--dry-run", "--no-feeds", "--no-net"))
    text = "\n".join(rep.lines)
    assert "DRY RUN: nothing was changed" in text
    assert "[dry-run] would install akismet latest" in text
    assert (site / "wp-content/uploads/a.php").exists()
    assert not (site.parent / "wpguard-quarantine").exists()
    assert not fake_wp.ran("core", "download")
    assert not fake_wp.ran("config", "set")


def test_fix_refuses_without_yes_when_not_interactive(site, ns, fake_wp, monkeypatch):
    make_findings(site)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rep = fixmod.fix(site, ns("fix", "--no-feeds", "--no-net"))
    assert rep.exit == 1
    assert "rerun with --yes" in "\n".join(rep.lines)
    assert (site / "wp-content/uploads/a.php").exists()


def test_fix_yes_quarantines_and_reinstalls_pinned_versions(site, ns, fake_wp, tmp_path):
    from pathlib import Path

    from wpguard import lockfile

    make_findings(site)

    def export(_site, *a):
        Path(a[2]).write_text("-- dump\nCREATE TABLE t (id int);\n")
        import subprocess

        return subprocess.CompletedProcess(a, 0, "", "")

    fake_wp.responses[("db", "export")] = export
    fake_wp.responses[("plugin", "list")] = (0, json.dumps([{"name": "akismet"}]), "")
    fake_wp.responses[("theme", "list")] = (0, "[]", "")
    lock = tmp_path / "wpguard.lock"
    lockfile.write(
        lock, {"version": 1, "feeds": {}, "sites": {"blog": {"core": "6.4.2", "plugins": {"akismet": "5.3"}}}}
    )
    a = ns("fix", "--yes", "--no-feeds", "--no-net", "--lock-file", str(lock), "--url", "https://x.test")
    rep = fixmod.fix(site, a)
    assert rep.exit == 0
    assert not (site / "wp-content/uploads/a.php").exists()
    assert (site / "wp-content/plugins/akismet/evil.php").exists() is False
    assert ("core", "download", "--force", "--skip-content", "--version=6.4.2") in [c for _, c in fake_wp.calls]
    assert ("plugin", "install", "akismet", "--force", "--version=5.3") in [c for _, c in fake_wp.calls]
    assert fake_wp.ran("config", "shuffle-salts")
    assert any(c[:3] == ("config", "set", "WP_HOME") for _, c in fake_wp.calls)
    assert list(site.parent.glob("wpguard-backup-blog-*.tar.zst"))
    assert (site.parent / "wpguard-quarantine").exists()
