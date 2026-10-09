import json

from wpguard import feeds
from wpguard.signatures import build_detectors


def fake_fetch(monkeypatch, payloads):
    monkeypatch.setattr(feeds, "fetch", payloads.get)


def test_catalog_and_custom_feeds():
    cat = feeds.catalog({"mine": {"kind": "regex", "urls": ["https://x/y.txt"], "note": "n"}})
    assert {"maldet-hashes", "php-malware-finder", "signature-base-webshells", "mine"} <= set(cat)
    assert cat["php-malware-finder"].entry == ("php.yar",)
    assert cat["mine"].kind == "regex"
    assert all(u.startswith("https://") for f in cat.values() for u in f.urls)


def test_update_downloads_indexes_and_exposes_files(monkeypatch, tmp_path):
    monkeypatch.setattr(feeds, "FEED_DIR", tmp_path)
    monkeypatch.setattr(feeds, "INDEX", tmp_path / "index.json")
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    fake_fetch(monkeypatch, {
        "https://cdn.rfxn.com/downloads/rfxn.hdb": f"{md5}:0:Empty.Test\n".encode(),
        feeds.PMF + "php.yar": b"rule a { condition: false }",
        feeds.PMF + "whitelist.yar": b"rule w { condition: false }",
    })  # fmt: skip
    msgs = []
    failed = feeds.update(["maldet-hashes", "php-malware-finder"], None, msgs.append)
    assert failed == 0
    idx = json.loads((tmp_path / "index.json").read_text())
    assert idx["maldet-hashes"]["kind"] == "hash"
    assert feeds.files("hash") == [tmp_path / "maldet-hashes" / "rfxn.hdb"]
    assert {p.name for p in feeds.files("yara")} == {"php.yar", "whitelist.yar"}
    assert [p.name for p in feeds.yara_entries()] == ["php.yar"]  # whitelist is only #included
    assert set(feeds.digests()) == {"maldet-hashes", "php-malware-finder"}


def test_update_failure_is_reported_and_keeps_old_index(monkeypatch, tmp_path):
    monkeypatch.setattr(feeds, "FEED_DIR", tmp_path)
    monkeypatch.setattr(feeds, "INDEX", tmp_path / "index.json")
    fake_fetch(monkeypatch, {})
    msgs = []
    assert feeds.update(["maldet-hashes", "nope"], None, msgs.append) == 2
    assert any("FAILED" in m for m in msgs)
    assert any("unknown feed" in m for m in msgs)
    assert feeds.files("hash") == []


def test_scanner_uses_cached_feeds_unless_disabled(monkeypatch, tmp_path, ns):
    monkeypatch.setattr(feeds, "FEED_DIR", tmp_path)
    monkeypatch.setattr(feeds, "INDEX", tmp_path / "index.json")
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    fake_fetch(monkeypatch, {"https://cdn.rfxn.com/downloads/rfxn.hdb": f"{md5}:0:X\n".encode()})
    feeds.update(["maldet-hashes"], None, lambda _m: None)
    assert build_detectors(ns("scan")).bad["md5"] == {md5}
    assert build_detectors(ns("scan", "--no-feeds")).bad is None


def test_sigs_command(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(feeds, "FEED_DIR", tmp_path)
    monkeypatch.setattr(feeds, "INDEX", tmp_path / "index.json")
    assert feeds.sigs_cmd(["list"], None) == 0
    out = capsys.readouterr().out
    assert "maldet-hashes" in out
    assert "not downloaded" in out
    assert feeds.sigs_cmd(["bogus"], None) == 2


def test_feed_url_without_a_file_name_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(feeds, "FEED_DIR", tmp_path)
    monkeypatch.setattr(feeds, "INDEX", tmp_path / "index.json")
    fake_fetch(monkeypatch, {"https://x/..": b"data"})
    msgs = []
    assert feeds.update(["evil"], {"evil": {"kind": "regex", "urls": ["https://x/.."]}}, msgs.append) == 1
    assert any("cannot derive a file name" in m for m in msgs)
