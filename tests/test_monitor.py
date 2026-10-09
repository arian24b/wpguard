import gzip
import os

from wpguard import monitor


def test_baseline_watch_cycle(site, ns):
    monitor.baseline(site, ns("baseline"))
    assert monitor.watch(site, ns("watch")).hits == []
    (site / "wp-content/uploads/a.php").write_bytes(b"<?php eval(base64_decode($_POST['x']));")
    (site / "index.php").write_text("changed")
    (site / "wp-content/plugins/akismet/akismet.php").unlink()
    hits = {(h["kind"], h["what"]): h["why"] for h in monitor.watch(site, ns("watch")).hits}
    assert hits[("new", "wp-content/uploads/a.php")].startswith("SIGNATURE MATCH")
    assert hits[("changed", "index.php")] == "file differs from baseline"
    assert ("removed", "wp-content/plugins/akismet/akismet.php") in hits


def test_watch_without_baseline(site, ns):
    rep = monitor.watch(site, ns("watch"))
    assert "no baseline yet" in rep.lines[0]


def test_snapshot_skips_media_cache_and_symlinks(site):
    (site / "wp-content/uploads/pic.jpg").write_text("img")
    (site / "wp-content/uploads/.htaccess").write_text("x")
    (site / "wp-content/cache").mkdir()
    (site / "wp-content/cache/c.php").write_text("c")
    os.symlink(site / "index.php", site / "link.php")
    snap = monitor.snapshot(site)
    assert "wp-content/uploads/pic.jpg" not in snap
    assert "wp-content/uploads/.htaccess" in snap
    assert "wp-content/cache/c.php" not in snap
    assert "link.php" not in snap


LOG = (
    '1.1.1.1 - - [01/Jan/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 5 "-" "ua"\n'
    '1.1.1.1 - - [01/Jan/2026:10:00:01 +0000] "POST /wp-login.php HTTP/1.1" 200 5 "-" "ua"\n'
    '2.2.2.2 - - [01/Jan/2026:10:00:02 +0000] "POST /xmlrpc.php HTTP/1.1" 200 5 "-" "ua"\n'
    '3.3.3.3 - - [01/Jan/2026:10:00:03 +0000] "GET /?cmd=cat%20/etc/passwd HTTP/1.1" 200 5 "-" "ua"\n'
    '4.4.4.4 - - [01/Jan/2026:10:00:04 +0000] "POST /wp-content/uploads/a.php HTTP/1.1" 200 5 "-" "ua"\n'
    '5.5.5.5 - - [01/Jan/2026:10:00:05 +0000] "POST /wp-content/plugins/bad/exploit.php HTTP/1.1" 200 5 "-" "ua"\n'
    '6.6.6.6 - - [01/Jan/2026:10:00:06 +0000] "GET /wp-content/plugins/akismet/evil.php HTTP/1.1" 200 5 "-" "ua"\n'
)


def test_logs_analysis_including_quarantined_shell_requests(site, ns, tmp_path):
    q = site.parent / "wpguard-quarantine" / f"{site.name}-20260101-000000" / "files/wp-content/plugins/akismet"
    q.mkdir(parents=True)
    (q / "evil.php").write_text("x")
    plain = tmp_path / "access.log"
    plain.write_text(LOG)
    gz = tmp_path / "access.log.1.gz"
    gz.write_bytes(gzip.compress(LOG.encode()))
    a = ns("logs", "--log", str(plain), "--log", str(gz))
    rep = monitor.logs([str(site)], a)
    text = "\n".join(rep.lines)
    assert "     4  1.1.1.1" in text  # 2 per file x 2 files
    assert "2.2.2.2" in text
    assert "3.3.3.3" in text
    assert "4.4.4.4 POST /wp-content/uploads/a.php -> 200" in text
    assert "/wp-content/plugins/bad/exploit.php -> 200" in text
    assert "6.6.6.6 GET /wp-content/plugins/akismet/evil.php -> 200" in text
