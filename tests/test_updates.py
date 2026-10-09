import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from wpguard import updates
from wpguard.report import Rep


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        mode = self.server.mode
        code, body = 200, b"<html>fine</html>"
        if mode == "fatal" and self.path == "/":
            body = b"<b>Fatal error</b>: Uncaught Error in plugin.php"
        if mode == "500" and self.path == "/wp-login.php":
            code, body = 500, b"oops"
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    srv.mode = "ok"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def base(srv):
    return f"http://127.0.0.1:{srv.server_address[1]}"


def test_check_detects_fatal_and_5xx_and_unreachable(server):
    paths = ["/", "/wp-login.php"]
    assert updates.check(base(server), paths) == {}
    server.mode = "fatal"
    assert "PHP error in page" in updates.check(base(server), paths)["/"]
    server.mode = "500"
    assert updates.check(base(server), paths) == {"/wp-login.php": "HTTP 500"}
    assert "unreachable" in updates.check("http://127.0.0.1:1", ["/"], timeout=1)["/"]


def test_candidates(site, fake_wp):
    fake_wp.responses[("core", "version")] = (0, "6.8\n", "")
    fake_wp.responses[("core", "check-update")] = (0, json.dumps([{"version": "6.9"}]), "")
    fake_wp.responses[("plugin", "list")] = (
        0,
        json.dumps([{"name": "akismet", "version": "5.3", "update_version": "5.4"}]),
        "",
    )
    fake_wp.responses[("theme", "list")] = (0, "[]", "")
    assert updates.candidates(site) == [
        {"kind": "core", "name": "wordpress", "from": "6.8", "to": "6.9"},
        {"kind": "plugin", "name": "akismet", "from": "5.3", "to": "5.4"},
    ]
    fake_wp.responses[("core", "check-update")] = (0, "", "")
    assert [c["kind"] for c in updates.candidates(site)] == ["plugin"]


class FakeStage:
    """Stands in for Stage: `wp plugin update X` rewrites the plugin dir and flips the server mode."""

    def __init__(self, root, server, outcome):
        self.root, self.base, self.server, self.outcome, self.log = root, base(server), server, outcome, ""

    def wp(self, *args):
        if args[:2] == ("plugin", "update") and args[2] == "bad-plugin":
            if self.outcome == "fail":
                return subprocess.CompletedProcess(args, 1, "", "download failed")
            (self.root / "wp-content/plugins/bad-plugin/main.php").write_text("UPDATED")
            self.server.mode = self.outcome
        if args[:2] == ("plugin", "update") and args[2] == "good-plugin":
            (self.root / "wp-content/plugins/good-plugin/main.php").write_text("UPDATED")
            self.server.mode = "ok"
        return subprocess.CompletedProcess(args, 0, "", "")

    def log_text(self):
        return self.log


def stage_root(tmp_path):
    for name in ("bad-plugin", "good-plugin"):
        d = tmp_path / "stage/wp-content/plugins" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "main.php").write_text("ORIGINAL")
    return tmp_path / "stage"


@pytest.mark.parametrize(("outcome", "expected"), [("fatal", "BREAKS"), ("500", "BREAKS"), ("fail", "update-failed")])
def test_try_candidates_flags_breakage_and_restores_files(server, tmp_path, outcome, expected):
    root = stage_root(tmp_path)
    cands = [
        {"kind": "plugin", "name": "bad-plugin", "from": "1", "to": "2"},
        {"kind": "plugin", "name": "good-plugin", "from": "1", "to": "2"},
    ]
    results = updates.try_candidates(
        FakeStage(root, server, outcome), cands, ["/", "/wp-login.php"], Rep("x", quiet=True)
    )
    assert [r["result"] for r in results] == [expected, "ok"]
    # every plugin dir is rolled back after its test, so the next candidate is tested in isolation
    assert (root / "wp-content/plugins/bad-plugin/main.php").read_text() == "ORIGINAL"
    assert (root / "wp-content/plugins/good-plugin/main.php").read_text() == "ORIGINAL"


def test_php_fatals_in_server_log_count_as_breakage(server, tmp_path):
    root = stage_root(tmp_path)
    stage = FakeStage(root, server, "ok")
    original_wp = stage.wp

    def wp(*args):
        stage.log += "PHP Fatal error: Uncaught Error\n"
        return original_wp(*args)

    stage.wp = wp
    res = updates.try_candidates(
        stage, [{"kind": "plugin", "name": "bad-plugin", "from": "1", "to": "2"}], ["/"], Rep("x", quiet=True)
    )
    assert res[0]["result"] == "BREAKS"
    assert "PHP fatal(s) in server log" in res[0]["detail"]


def test_updates_command_advice_and_apply(site, fake_wp, ns, server, tmp_path, monkeypatch):
    fake_wp.responses[("core", "version")] = (0, "6.8\n", "")
    fake_wp.responses[("core", "check-update")] = (0, "", "")
    fake_wp.responses[("plugin", "list")] = (
        0,
        json.dumps(
            [
                {"name": "good-plugin", "version": "1", "update_version": "2"},
                {"name": "bad-plugin", "version": "1", "update_version": "2"},
            ]
        ),
        "",
    )
    fake_wp.responses[("theme", "list")] = (0, "[]", "")

    class StageCtx:
        def __init__(self, *_a):
            self.inner = FakeStage(stage_root(tmp_path), server, "fatal")

        def __enter__(self):
            return self.inner

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(updates, "Stage", StageCtx)

    def export(_site, *a):
        Path(a[2]).write_text("CREATE TABLE t (id int);")
        return subprocess.CompletedProcess(a, 0, "", "")

    fake_wp.responses[("db", "export")] = export
    rep = updates.updates(site, ns("updates", "--lock-file", str(tmp_path / "wpguard.lock")))
    assert [h["kind"] for h in rep.hits] == ["update-breaks"]
    assert "advice only" in rep.lines[-1]
    assert not fake_wp.ran("plugin", "update")  # nothing applied without --apply

    server.mode = "ok"  # the fake stage starts healthy again for the second run
    rep = updates.updates(
        site, ns("updates", "--apply", "--lock-file", str(tmp_path / "wpguard.lock"), "--out", str(tmp_path / "bk"))
    )
    applied = list(fake_wp.ran("plugin", "update"))
    assert applied == [("plugin", "update", "good-plugin")]  # only the safe one touches the real site
    assert list((tmp_path / "bk").glob("wpguard-backup-*.tar.zst"))


def test_updates_nothing_pending(site, fake_wp, ns):
    fake_wp.responses[("plugin", "list")] = (0, "[]", "")
    fake_wp.responses[("theme", "list")] = (0, "[]", "")
    assert "nothing to update" in updates.updates(site, ns("updates")).lines[0]


def test_staging_failure_is_reported(site, fake_wp, ns, monkeypatch):
    fake_wp.responses[("plugin", "list")] = (0, json.dumps([{"name": "p", "version": "1", "update_version": "2"}]), "")
    fake_wp.responses[("theme", "list")] = (0, "[]", "")

    class Boom:
        def __init__(self, *_a):
            pass

        def __enter__(self):
            msg = "cannot create staging database"
            raise RuntimeError(msg)

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(updates, "Stage", Boom)
    rep = updates.updates(site, ns("updates"))
    assert rep.exit == 1
    assert "staging failed" in rep.lines[-1]


def test_guard_files_block_mail_and_foreign_http():
    assert "pre_wp_mail" in updates.MU_GUARD
    assert "wordpress|w|wp" in updates.MU_GUARD  # updates must still reach wordpress.org
    assert "outgoing HTTP blocked" in updates.MU_GUARD
