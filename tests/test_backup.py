import subprocess
import sys
import tarfile
import types
from pathlib import Path

import pytest

from conftest import make_script
from wpguard import backup as bk
from wpguard import destinations as dst
from wpguard.report import Rep

DUMP = "-- MySQL dump\nCREATE TABLE wp_posts (id int);\nINSERT INTO wp_posts VALUES (1);\n"


@pytest.fixture
def db(fake_wp):
    """db export writes a dump, db import records what it was given."""
    imported = []

    def export(_site, *a):
        Path(a[2]).write_text(DUMP)
        return subprocess.CompletedProcess(a, 0, "", "")

    def imp(_site, *a):
        imported.append(Path(a[2]).read_text())
        return subprocess.CompletedProcess(a, 0, "", "")

    fake_wp.responses[("db", "export")] = export
    fake_wp.responses[("db", "import")] = imp
    return imported


def names(arc):
    with tarfile.open(arc, "r:zst") as t:
        return t.getnames()


def test_backup_contents_checksum_and_uploads_flag(site, ns, db):
    (site / "wp-content/uploads/a.jpg").write_text("img")
    out = site.parent / "bk"
    full = bk.make_backup(site, ns("backup", "--out", str(out)), Rep(site, quiet=True))
    slim = bk.make_backup(site, ns("backup", "--out", str(out), "--no-uploads"), Rep(site, quiet=True), uploads=False)
    assert "site/wp-content/uploads/a.jpg" in names(full)
    assert "site/wp-content/uploads/a.jpg" not in names(slim)
    assert full.stat().st_mode & 0o777 == 0o600
    assert full.with_name(full.name + ".sha256").read_text().split()[0] == bk.sha256(full)
    assert bk.verify_archive(full) == []


def test_backup_refuses_destination_inside_site(site, ns, db):
    with pytest.raises(SystemExit):
        bk.make_backup(site, ns("backup", "--out", str(site / "inside")), Rep(site, quiet=True))


def test_verify_detects_problems(site, ns, db, tmp_path):
    arc = bk.make_backup(site, ns("backup", "--out", str(tmp_path / "bk")), Rep(site, quiet=True))
    arc.write_bytes(arc.read_bytes() + b"junk")
    assert "checksum mismatch" in bk.verify_archive(arc)[0]
    # a valid tar.zst that is not a WordPress backup
    bad = tmp_path / "wpguard-backup-x-20260101-000000.tar.zst"
    with tarfile.open(bad, "w:zst") as t:
        info = tarfile.TarInfo("db.sql")
        info.size = 0
        t.addfile(info)
    problems = bk.verify_archive(bad)
    assert any("db.sql is empty" in p for p in problems)
    assert any("missing site/wp-load.php" in p for p in problems)
    garbage = tmp_path / "wpguard-backup-y-20260101-000000.tar.zst"
    garbage.write_bytes(b"not zstd at all")
    assert any("unreadable" in p for p in bk.verify_archive(garbage))


def test_restore_roundtrip_and_tamper(site, ns, db, tmp_path):
    arc = bk.make_backup(site, ns("backup", "--out", str(tmp_path / "bk")), Rep(site, quiet=True))
    (site / "wp-config.php").unlink()
    (site / "index.php").write_text("HACKED")
    a = ns("restore", "--from", str(arc))
    rep = bk.restore(site, a)
    assert rep.exit == 0
    assert (site / "wp-config.php").exists()
    assert "wp-blog-header" in (site / "index.php").read_text()
    assert db == [DUMP]
    arc.write_bytes(arc.read_bytes() + b"x")
    assert bk.restore(site, a).exit == 1


def test_verify_flag_blocks_upload_of_bad_archive(site, ns, db, monkeypatch):
    monkeypatch.setattr(bk, "verify_archive", lambda *a, **k: ["synthetic problem"])
    rep = Rep(site, quiet=True)
    bk.make_backup(site, ns("backup", "--out", str(site.parent / "bk"), "--verify"), rep)
    assert rep.exit == 1
    assert any("VERIFY FAILED" in line for line in rep.lines)


def test_encrypt_with_age(site, ns, db, bin_dir, tmp_path):
    make_script(
        bin_dir, "age", 'out=""; while [ $# -gt 1 ]; do [ "$1" = "-o" ] && out="$2"; shift; done; cp "$1" "$out"\n'
    )
    arc = bk.make_backup(
        site, ns("backup", "--out", str(tmp_path / "bk"), "--encrypt-to", "age1abc"), Rep(site, quiet=True)
    )
    assert arc.name.endswith(".tar.zst.age")
    assert not list((tmp_path / "bk").glob("*.tar.zst"))  # plaintext removed
    assert bk.verify_archive(arc)[0].startswith("encrypted: only the checksum")


def test_encrypt_without_age_binary(site, ns, db, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(dst.DestError, match="age"):
        bk.make_backup(
            site, ns("backup", "--out", str(tmp_path / "bk"), "--encrypt-to", "age1abc"), Rep(site, quiet=True)
        )


# ---------- destinations ----------
def mk(dir_, site, ts, *, sidecar=True):
    for suffix in (".tar.zst", ".tar.zst.sha256") if sidecar else (".tar.zst",):
        (dir_ / f"wpguard-backup-{site}-{ts}{suffix}").write_text(ts)


def test_retention_keeps_newest_per_site(tmp_path):
    for ts in ("20260101-000001", "20260102-000001", "20260103-000001", "20260104-000001"):
        mk(tmp_path, "blog", ts)
    mk(tmp_path, "other", "20250101-000001")
    deleted = dst.retention(dst.Local(tmp_path), "blog", keep=2)
    assert len(deleted) == 4  # 2 old archives + their sidecars
    left = sorted(p.name for p in tmp_path.iterdir())
    assert "wpguard-backup-blog-20260104-000001.tar.zst" in left
    assert "wpguard-backup-blog-20260101-000001.tar.zst" not in left
    assert "wpguard-backup-other-20250101-000001.tar.zst" in left  # other sites untouched
    assert dst.retention(dst.Local(tmp_path), "blog", keep=0) == []


class FakeDest:
    def __init__(self, label, *, fail=False, wrong_size=False):
        self.label, self.fail, self.wrong_size, self.put_calls, self.store = label, fail, wrong_size, 0, {}

    def put(self, files):
        if self.fail:
            raise dst.DestError("boom")
        self.put_calls += 1
        self.store = {f.name: f.stat().st_size + (1 if self.wrong_size else 0) for f in files}

    def names(self):
        return sorted(self.store)

    def delete(self, name):
        self.store.pop(name, None)

    def size(self, name):
        return self.store.get(name)


def test_upload_all_concurrent_and_isolated_failures(tmp_path):
    arc = tmp_path / "wpguard-backup-blog-20260101-000001.tar.zst"
    arc.write_text("data")
    side = tmp_path / (arc.name + ".sha256")
    side.write_text("x")
    good, broken, bad_size = FakeDest("good"), FakeDest("broken", fail=True), FakeDest("badsize", wrong_size=True)
    res = dst.upload_all([good, broken, bad_size], [arc, side], "blog", keep=0)
    assert res["good"] == "ok"
    assert res["broken"] == "FAILED: boom"
    assert "size mismatch" in res["badsize"]
    assert good.put_calls == 1


def test_parse_specs(tmp_path):
    assert isinstance(dst.parse(str(tmp_path)), dst.Local)
    s3 = dst.parse("s3://bucket/some/prefix")
    assert (s3.bucket, s3.prefix) == ("bucket", "some/prefix/")
    r = dst.parse("rsync:mina:/srv/backups")
    assert (r.host, r.path) == ("mina", "/srv/backups")
    with pytest.raises(dst.DestError):
        dst.parse("rsync:nopath")
    with pytest.raises(dst.DestError):
        dst.parse("rsync:-oProxyCommand=x:/p")


def test_s3_with_fake_boto3(monkeypatch, tmp_path):
    uploaded = {}

    class Client:
        def upload_file(self, filename, bucket, key, Config=None):  # noqa: N803
            uploaded[key] = Path(filename).stat().st_size

        def head_object(self, Bucket, Key):  # noqa: N803
            return {"ContentLength": uploaded[Key]}

        def delete_object(self, Bucket, Key):  # noqa: N803
            uploaded.pop(Key)

        def get_paginator(self, _name):
            return types.SimpleNamespace(paginate=lambda **k: [{"Contents": [{"Key": key} for key in uploaded]}])

    boto3 = types.ModuleType("boto3")
    boto3.client = lambda _svc: Client()
    transfer = types.ModuleType("boto3.s3.transfer")
    transfer.TransferConfig = lambda **k: k
    for name, mod in (("boto3", boto3), ("boto3.s3", types.ModuleType("boto3.s3")), ("boto3.s3.transfer", transfer)):
        monkeypatch.setitem(sys.modules, name, mod)
    for ts in ("20260101-000001", "20260102-000001"):
        mk(tmp_path, "blog", ts)
    files = [
        tmp_path / "wpguard-backup-blog-20260102-000001.tar.zst",
        tmp_path / "wpguard-backup-blog-20260102-000001.tar.zst.sha256",
    ]
    uploaded["pre/wpguard-backup-blog-20260101-000001.tar.zst"] = 1
    res = dst.upload_all([dst.S3("s3://bkt/pre")], files, "blog", keep=1)
    assert res == {"s3://bkt/pre": "ok (1 old file(s) removed)"}
    assert set(uploaded) == {"pre/" + f.name for f in files}


def test_s3_without_boto3_is_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)
    res = dst.upload_all([dst.S3("s3://b/p")], [Path(__file__)], "blog", keep=0)
    assert "pip install 'wpguard[s3]'" in res["s3://b/p"]


def test_rsync_destination_with_fake_ssh_and_rsync(bin_dir, tmp_path):
    remote = tmp_path / "remote"
    remote.mkdir()
    # fake ssh: strips options + host, runs the command locally; fake rsync: copies into the "remote" dir
    make_script(
        bin_dir,
        "ssh",
        'while [ "${1#-}" != "$1" ]; do shift; [ "$1" = "BatchMode=yes" ] && shift; done; shift; sh -c "$*"\n',
    )
    make_script(
        bin_dir, "rsync", f'for last; do :; done; for f in "$@"; do [ -f "$f" ] && cp "$f" {remote}/; done; exit 0\n'
    )
    arc = tmp_path / "wpguard-backup-blog-20260102-000001.tar.zst"
    arc.write_text("payload")
    side = tmp_path / (arc.name + ".sha256")
    side.write_text("sum")
    old = remote / "wpguard-backup-blog-20260101-000001.tar.zst"
    old.write_text("old")
    res = dst.upload_all([dst.Rsync(f"mina:{remote}")], [arc, side], "blog", keep=1)
    assert res[f"rsync:mina:{remote}"].startswith("ok"), res
    assert not old.exists()
    assert (remote / arc.name).read_text() == "payload"
