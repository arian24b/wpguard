import tomllib

import pytest

from wpguard import cli, config, discover

NGINX = """
# comment
server {
    listen 80;
    server_name blog.example.com www.blog.example.com;
    root /var/www/blog;
    location / { root /var/www/ignored; }
    location ~ \\.php$ { fastcgi_pass unix:/run/php.sock; }
}
server {
    server_name _;
    root /var/www/default;
}
server {
    server_name shop.example.org *.shop.example.org;
    root /var/www/shop/public;
}
"""
APACHE = """
<VirtualHost *:80>
    ServerName old.example.net
    ServerAlias www.old.example.net legacy.example.net
    DocumentRoot "/srv/old"
</VirtualHost>
"""
FIND = """/var/www/blog/wp-config.php
/var/www/shop/wp-config.php
/srv/old/wp-config.php
/var/www/unrelated/wp-config.php
"""


def test_parse_vhosts_nginx_and_apache():
    v = discover.parse_vhosts(NGINX + APACHE)
    assert {
        "domains": ["blog.example.com", "www.blog.example.com"],
        "root": "/var/www/blog",
    } in v  # nested location root ignored
    assert {"domains": ["shop.example.org"], "root": "/var/www/shop/public"} in v  # wildcard dropped
    assert {"domains": ["old.example.net", "www.old.example.net", "legacy.example.net"], "root": "/srv/old"} in v
    assert all("_" not in x["domains"] for x in v)


def test_match_vhost_roots_to_wordpress_roots():
    roots = ["/var/www/blog", "/var/www/shop", "/srv/old", "/var/www/unrelated"]
    sites = discover.match(discover.parse_vhosts(NGINX + APACHE), roots)
    by_path = {s["path"]: s["domains"] for s in sites}
    assert by_path["/var/www/blog"][0] == "blog.example.com"
    assert by_path["/var/www/shop"] == ["shop.example.org"]  # docroot is a child (public/) of the WP root
    assert "legacy.example.net" in by_path["/srv/old"]
    assert "/var/www/unrelated" not in by_path


@pytest.fixture
def fake_collect(monkeypatch):
    discover._cache.clear()
    calls = []

    def collect(host):
        calls.append(host)
        return NGINX + APACHE + discover.MARK + "\n" + FIND

    monkeypatch.setattr(discover, "collect", collect)
    yield calls
    discover._cache.clear()


def test_fill_resolves_domain_and_www_variants(fake_collect):
    for name in ("blog.example.com", "www.blog.example.com", "legacy.example.net"):
        t = config.Target(name, name, "", "mina", domain=name)
        discover.fill(t)
        assert t.path in {"/var/www/blog", "/srv/old"}
    assert fake_collect == ["mina"]  # one ssh round trip per host, cached
    with pytest.raises(config.ConfigError, match=r"no WordPress site for 'nope.example.com' found on mina"):
        discover.fill(config.Target("x", "x", "", "mina", domain="nope.example.com"))


def test_resolve_by_hostname_variants(tmp_path):
    cfg = config.Config(sites={
        "blog": {"path": str(tmp_path), "domain": "blog.example.com", "url": "https://www.blog.example.com/x"},
        "mina": {"ssh": "mina", "domain": "mina.example.com"},  # no path: found over ssh
    })  # fmt: skip
    t = config.resolve(cfg, "blog.example.com")
    assert (t.name, t.path, t.domain) == ("blog", str(tmp_path.resolve()), "blog.example.com")
    assert config.resolve(cfg, "www.blog.example.com").name == "blog"  # via the url's host
    m = config.resolve(cfg, "mina")
    assert (m.ssh, m.path, m.domain) == ("mina", "", "mina.example.com")
    adhoc = config.resolve(config.Config(), "mina:shop.example.org")
    assert (adhoc.ssh, adhoc.path, adhoc.domain) == ("mina", "", "shop.example.org")
    bare = config.resolve(config.Config(), "Shop.Example.org")
    assert (bare.ssh, bare.path, bare.domain, bare.key) == (None, "", "shop.example.org", "shop.example.org")


def test_existing_path_beats_domain_lookalike(tmp_path, monkeypatch):
    (tmp_path / "blog.example.com").mkdir()
    monkeypatch.chdir(tmp_path)
    t = config.resolve(config.Config(), "blog.example.com")
    assert t.path == str((tmp_path / "blog.example.com").resolve())
    assert t.domain == ""


def test_profile_needs_path_or_domain():
    with pytest.raises(config.ConfigError, match="path or a domain"):
        config.resolve(config.Config(sites={"x": {"url": "u"}}), "x")


def test_cli_scan_by_hostname_over_ssh(fake_collect, bin_dir, tmp_path):
    from conftest import make_script

    log = tmp_path / "ssh.log"
    # first ssh call is discovery (handled by fake_collect), the second is the real command
    make_script(bin_dir, "ssh", f'printf "%s\\n" "$@" > {log}; exit 0\n')
    assert cli.main(["scan", "mina:blog.example.com", "--no-net"]) == 0
    assert log.read_text().split("\n")[1] == "uvx wpguard scan /var/www/blog --no-net"


def test_cli_local_hostname_resolves_through_vhosts(fake_collect, site, monkeypatch, fake_wp, tmp_path):
    monkeypatch.setattr(
        discover,
        "collect",
        lambda _h: f"server {{ server_name blog.test; root {site}; }}\n{discover.MARK}\n{site}/wp-config.php\n",
    )
    discover._cache.clear()
    assert cli.main(["baseline", "blog.test"]) == 0


def test_unknown_hostname_is_a_clean_error(fake_collect, fake_wp):
    with pytest.raises(SystemExit, match=r"no WordPress site for 'nope.example.com'"):
        cli.main(["scan", "nope.example.com"])


def test_discover_command_lists_and_saves(fake_collect, tmp_path, capsys):
    cfg = tmp_path / "wpguard.toml"
    cfg.write_text("")
    assert cli.main(["discover", "mina", "--save", "--config", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert "blog.example.com" in out
    assert "added 3 site(s)" in out
    saved = tomllib.loads(cfg.read_text())["sites"]
    assert saved["blog-example-com"] == {"ssh": "mina", "path": "/var/www/blog", "domain": "blog.example.com"}
    # running again finds nothing new
    assert cli.main(["discover", "mina", "--save", "--config", str(cfg)]) == 0
    assert "(already in config)" in capsys.readouterr().out
    assert len(tomllib.loads(cfg.read_text())["sites"]) == 3
    # and the saved profile now works by hostname without discovery
    cfgobj = config.load(str(cfg))
    assert config.resolve(cfgobj, "shop.example.org").path == "/var/www/shop"
