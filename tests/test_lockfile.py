import json

from wpguard import feeds, lockfile


def installed(fake_wp, core="6.9", plugins=None, themes=None):
    fake_wp.responses[("core", "version")] = (0, core + "\n", "")
    fake_wp.responses[("plugin", "list")] = (
        0,
        json.dumps([{"name": n, "version": v} for n, v in (plugins or {}).items()]),
        "",
    )
    fake_wp.responses[("theme", "list")] = (
        0,
        json.dumps([{"name": n, "version": v} for n, v in (themes or {}).items()]),
        "",
    )


def test_lock_write_then_check_clean(site, ns, fake_wp, tmp_path):
    installed(fake_wp, plugins={"akismet": "5.3"}, themes={"astra": "4.0"})
    a = ns("lock", "--lock-file", str(tmp_path / "wpguard.lock"))
    lockfile.lock_cmd(site, a)
    data = json.loads((tmp_path / "wpguard.lock").read_text())
    assert data["sites"]["blog"] == {"core": "6.9", "plugins": {"akismet": "5.3"}, "themes": {"astra": "4.0"}}
    rep = lockfile.lock_cmd(site, ns("lock", "--check", "--lock-file", str(tmp_path / "wpguard.lock")))
    assert rep.hits == []


def test_check_reports_drift(site, ns, fake_wp, tmp_path):
    lock = tmp_path / "wpguard.lock"
    installed(fake_wp, plugins={"akismet": "5.3", "gone": "1.0"})
    lockfile.lock_cmd(site, ns("lock", "--lock-file", str(lock)))
    installed(fake_wp, core="6.9.1", plugins={"akismet": "5.4", "new": "1.0"})
    rep = lockfile.lock_cmd(site, ns("lock", "--check", "--lock-file", str(lock)))
    why = " | ".join(h["why"] for h in rep.hits)
    assert "core 6.9 -> 6.9.1" in why
    assert "locked 5.3, installed 5.4" in why
    assert "plugin new: installed but not in lock" in why
    assert "plugin gone: in lock but not installed" in why


def test_check_without_entry(site, ns, fake_wp, tmp_path):
    installed(fake_wp)
    rep = lockfile.lock_cmd(site, ns("lock", "--check", "--lock-file", str(tmp_path / "none.lock")))
    assert "not in none.lock" in rep.hits[0]["why"]


def test_pinned_and_feed_drift(ns, tmp_path, monkeypatch):
    lock = tmp_path / "wpguard.lock"
    lockfile.write(lock, {"version": 1, "sites": {"blog": {"core": "6.4"}}, "feeds": {"f": "aaa", "g": "bbb"}})
    a = ns("scan", "--lock-file", str(lock))
    assert lockfile.pinned(a) == {"core": "6.4"}
    monkeypatch.setattr(feeds, "digests", lambda: {"f": "CHANGED", "g": "bbb"})
    assert lockfile.feed_drift(a) == ["feed f changed since lock"]
    a.site_key = "other"
    assert lockfile.pinned(a) is None


def test_path_for(ns, tmp_path):
    a = ns("scan")
    a.config_path = tmp_path / "wpguard.toml"
    assert lockfile.path_for(a) == tmp_path / "wpguard.lock"
