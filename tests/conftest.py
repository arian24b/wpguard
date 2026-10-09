"""Shared fixtures. WPGUARD_HOME is redirected before wpguard is imported so tests never touch ~/.local."""

import os
import stat
import subprocess
import tempfile

_HOME = tempfile.mkdtemp(prefix="wpguard-test-home-")
os.environ["WPGUARD_HOME"] = _HOME

import pytest  # noqa: E402

from wpguard import wpcli  # noqa: E402
from wpguard.cli import build_parser  # noqa: E402


class FakeWP:
    """Stand-in for wpcli.wp: records calls, answers by command prefix."""

    def __init__(self):
        self.calls = []
        self.responses = {}

    def __call__(self, site, *a, load=False, cwd=None):
        self.calls.append((str(site), a))
        for key, resp in self.responses.items():
            if a[: len(key)] == key:
                if callable(resp):
                    return resp(site, *a)
                rc, out, err = resp
                return subprocess.CompletedProcess(a, rc, out, err)
        return subprocess.CompletedProcess(a, 0, "", "")

    def ran(self, *prefix):
        return [c for _, c in self.calls if c[: len(prefix)] == prefix]


@pytest.fixture
def fake_wp(monkeypatch):
    f = FakeWP()
    monkeypatch.setattr(wpcli, "wp", f)
    monkeypatch.setattr(wpcli, "need_wp", lambda: None)
    return f


@pytest.fixture
def site(tmp_path):
    root = tmp_path / "www" / "blog"
    (root / "wp-content/plugins/akismet").mkdir(parents=True)
    (root / "wp-content/uploads").mkdir(parents=True)
    (root / "wp-load.php").write_text("<?php // load")
    (root / "wp-config.php").write_text("<?php define('DB_NAME','x');")
    (root / "index.php").write_text("<?php require __DIR__ . '/wp-blog-header.php';")
    (root / "wp-content/plugins/akismet/akismet.php").write_text("<?php // akismet")
    return root


@pytest.fixture
def ns():
    """Namespace with CLI defaults for a command: ns('scan', '--since', '7')."""

    def make(cmd="scan", *extra):
        a = build_parser().parse_args([cmd, *extra])
        a.site_key, a.config_path, a._det = "blog", None, None
        return a

    return make


@pytest.fixture
def bin_dir(tmp_path, monkeypatch):
    """Directory first on PATH where tests drop fake executables (ssh, rsync, age, yara, crontab)."""
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("PATH", f"{d}{os.pathsep}{os.environ['PATH']}")
    return d


def make_script(bin_dir, name, body):
    p = bin_dir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p
