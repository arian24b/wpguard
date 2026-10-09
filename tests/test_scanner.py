import os
import time

from conftest import make_script
from wpguard.scanner import SAFE_KINDS, file_scan, find_files, is_ignored
from wpguard.signatures import build_detectors

SHELL = b"<?php @eval(base64_decode($_POST['x']));"


def test_uploads_and_signatures_and_hidden(site, ns):
    (site / "wp-content/uploads/a.php").write_bytes(b"<?php echo 1;")
    (site / "wp-content/uploads/pic.jpg").write_bytes(b"GIF89a<?php system($_GET['c']);")
    (site / "wp-content/plugins/akismet/evil.php").write_bytes(SHELL)
    (site / ".sneaky").write_text("x")
    hits = file_scan(site, ns("scan"), type("R", (), {"hit": lambda *a: None})())
    rel = {p.relative_to(site).as_posix(): k for p, (k, _) in hits.items()}
    assert rel["wp-content/uploads/a.php"] == "struct"
    assert rel["wp-content/uploads/pic.jpg"] == "struct"
    assert rel["wp-content/plugins/akismet/evil.php"] == "sig"
    assert rel[".sneaky"] == "struct"
    assert "index.php" not in rel


def test_hashdb_bad_and_good(site, ns, tmp_path):
    import hashlib

    img = site / "wp-content/uploads/x.jpg"
    img.write_bytes(b"innocent looking bytes")
    shell = site / "wp-content/plugins/akismet/s.php"
    shell.write_bytes(SHELL)
    bad = tmp_path / "bad.csv"
    bad.write_text(hashlib.md5(img.read_bytes(), usedforsecurity=False).hexdigest())
    good = tmp_path / "good.txt"
    good.write_text(hashlib.sha256(shell.read_bytes()).hexdigest())
    a = ns("scan", "--hashdb", str(bad), "--hashdb-good", str(good), "--no-feeds")
    hits = file_scan(site, a, type("R", (), {"hit": lambda *a: None})())
    assert hits[img][0] == "hash"
    assert shell not in hits  # known-good hash suppresses the signature match


def test_behavior_is_review_only(site, ns):
    p = site / "wp-content/plugins/akismet/packed.php"
    p.write_bytes(b"<?php $a=gzinflate(base64_decode('" + b"QUJD" * 100 + b"'));eval($a);")  # no SIG match
    hits = file_scan(site, ns("scan", "--no-feeds"), type("R", (), {"hit": lambda *a: None})())
    assert hits[p][0] == "behavior"
    assert "behavior" not in SAFE_KINDS
    assert p not in file_scan(
        site, ns("scan", "--no-behavior", "--no-feeds"), type("R", (), {"hit": lambda *a: None})()
    )


def test_ignore_patterns(site, ns, fake_wp):
    (site / "wp-content/plugins/akismet/evil.php").write_bytes(SHELL)
    (site / "wp-content/uploads/a.php").write_bytes(b"<?php")
    assert is_ignored("wp-content/uploads/a.php", ["wp-content/uploads/*"])
    assert is_ignored("a/b/c.php", ["a"])  # a directory pattern ignores everything below it
    assert not is_ignored("ab/c.php", ["a"])
    assert is_ignored("a/b/c.php", ["a/"])
    rep = type("R", (), {"hit": lambda *a: None, "log": lambda *a: None})()
    found = find_files(site, ns("scan", "--ignore", "wp-content/uploads/*", "--no-feeds"), rep)
    assert {p.name for p in found} == {"evil.php"}


def test_recent_flag(site, ns):
    p = site / "wp-content/plugins/akismet/new.php"
    p.write_text("<?php echo 1;")
    old = site / "wp-content/plugins/akismet/old.php"
    old.write_text("<?php echo 2;")
    os.utime(old, (time.time() - 90 * 86400,) * 2)
    seen = []
    rep = type("R", (), {"hit": lambda self, *a: seen.append(a)})()
    file_scan(site, ns("scan", "--since", "7", "--no-feeds"), rep)
    assert any("new.php" in str(a[1]) for a in seen)
    assert not any("old.php" in str(a[1]) for a in seen)


def test_yara_via_cli(site, ns, bin_dir, tmp_path):
    shellfile = site / "wp-content/plugins/akismet/y.php"
    shellfile.write_text("<?php echo 1;")
    make_script(bin_dir, "yara", f'echo "WebShell_Generic {shellfile}"\n')
    rules = tmp_path / "r.yar"
    rules.write_text("rule x { condition: false }")
    hits = find_files_with_yara(site, ns("scan", "--yara", str(rules), "--no-feeds"))
    assert hits[shellfile] == ("yara", "r.yar: WebShell_Generic")


def find_files_with_yara(site, a):
    from wpguard.scanner import yara_scan

    rep = type("R", (), {"log": lambda *a: None})()
    assert build_detectors(a).yara_rules
    return yara_scan(site, a, rep)


def test_yara_missing_binary_is_reported(site, ns, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    logs = []
    rep = type("R", (), {"log": lambda self, *m: logs.append(m)})()
    rules = tmp_path / "r.yar"
    rules.write_text("x")
    from wpguard.scanner import yara_scan

    assert yara_scan(site, ns("scan", "--yara", str(rules), "--no-feeds"), rep) == {}
    assert "no `yara`" in logs[0][0]
