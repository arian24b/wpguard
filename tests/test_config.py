import pytest

from wpguard import config
from wpguard.cli import apply_opts, build_parser, serialize

TOML = """
[defaults]
since = 14
hashdb = ["~/h.csv"]

[notify]
email = "me@example.com"

[sites.blog]
path = "{blog}"
url = "https://blog.example.com"
to = ["s3://b/blog"]

[sites.mina]
ssh = "mina"
path = "/var/www/mina"
remote_cmd = "~/bin/uvx wpguard"
since = 3

[feeds.mine]
kind = "yara"
urls = ["https://example.com/r.yar"]
"""


def write(tmp_path, blog):
    p = tmp_path / "wpguard.toml"
    p.write_text(TOML.format(blog=blog))
    return p


def test_load_and_resolve(tmp_path, site):
    cfg = config.load(str(write(tmp_path, site)))
    assert cfg.defaults["since"] == 14
    assert cfg.notify["email"] == "me@example.com"
    assert "mine" in cfg.feeds
    t = config.resolve(cfg, "blog")
    assert (t.path, t.ssh, t.key) == (str(site), None, "blog")
    assert t.opts == {"url": "https://blog.example.com", "to": ["s3://b/blog"]}
    m = config.resolve(cfg, "mina")
    assert (m.ssh, m.path, m.remote_cmd) == ("mina", "/var/www/mina", "~/bin/uvx wpguard")


def test_adhoc_ssh_target_and_plain_path(tmp_path):
    cfg = config.Config()
    t = config.resolve(cfg, "mina:/var/www/x")
    assert (t.ssh, t.path) == ("mina", "/var/www/x")
    local = config.resolve(cfg, str(tmp_path))
    assert local.ssh is None
    assert local.path == str(tmp_path.resolve())


def test_missing_and_bad_config(tmp_path):
    with pytest.raises(config.ConfigError):
        config.load(str(tmp_path / "nope.toml"))
    bad = tmp_path / "bad.toml"
    bad.write_text("[sites\n")
    with pytest.raises(config.ConfigError):
        config.load(str(bad))
    cfg = config.Config(sites={"x": {"url": "u"}})
    with pytest.raises(config.ConfigError):
        config.resolve(cfg, "x")


def test_precedence_cli_over_profile_over_defaults(tmp_path, site):
    ap = build_parser()
    cfg = config.load(str(write(tmp_path, site)))
    ns = ap.parse_args(["scan", "mina", "--since", "99"])
    apply_opts(ap, ns, cfg.defaults, "[defaults]")
    apply_opts(ap, ns, config.resolve(cfg, "mina").opts, "[sites.mina]")
    assert ns.since == 99  # the CLI wins
    assert ns.hashdb[0].endswith("h.csv")  # from defaults, ~ expanded
    ns2 = ap.parse_args(["scan", "mina"])
    apply_opts(ap, ns2, config.resolve(cfg, "mina").opts, "[sites.mina]")
    apply_opts(ap, ns2, cfg.defaults, "[defaults]")
    assert ns2.since == 3  # the profile beats [defaults] (14)
    ns3 = ap.parse_args(["scan", "blog"])
    apply_opts(ap, ns3, config.resolve(cfg, "blog").opts, "[sites.blog]")
    apply_opts(ap, ns3, cfg.defaults, "[defaults]")
    assert ns3.since == 14  # ... and defaults fill what the profile leaves unset


def test_unknown_option_is_an_error():
    ap = build_parser()
    with pytest.raises(config.ConfigError, match="unknown option"):
        apply_opts(ap, ap.parse_args(["scan"]), {"nonsense": 1}, "[defaults]")


def test_serialize_roundtrip():
    ap = build_parser()
    ns = ap.parse_args(["backup", "x", "--since", "7", "--to", "s3://b/p", "--to", "/srv", "--no-uploads", "-j", "4"])
    out = serialize(ap, ns)
    assert out == ["--since", "7", "--no-uploads", "--to", "s3://b/p", "--to", "/srv"] or set(out) >= {"--no-uploads"}
    assert "-j" not in out
    assert "--jobs" not in out
    again = ap.parse_args(["backup", "x", *out])
    assert again.since == 7
    assert again.to == ["s3://b/p", "/srv"]
    assert again.no_uploads is True


def test_ssh_host_cannot_look_like_an_ssh_option(tmp_path):
    cfg = config.Config(sites={"x": {"path": "/p", "ssh": "-oProxyCommand=evil"}})
    with pytest.raises(config.ConfigError, match="not a valid host"):
        config.resolve(cfg, "x")
    with pytest.raises(config.ConfigError, match="not a valid host"):
        config.resolve(config.Config(), "-oProxyCommand=evil:/var/www")


def test_template_is_valid_toml_and_changes_nothing(tmp_path):
    p = tmp_path / "wpguard.toml"
    assert config.write_template(p) is True
    assert config.write_template(p) is False  # never overwrites by default
    cfg = config.load(str(p))
    assert (cfg.sites, cfg.defaults, cfg.feeds) == ({}, {}, {})  # everything is commented out
    p.write_text("custom")
    assert config.write_template(p, force=True) is True
    assert p.read_text() == config.TEMPLATE


def test_ensure_default_creates_global_only_when_no_config(tmp_path, monkeypatch):
    local, global_ = tmp_path / "wpguard.toml", tmp_path / "cfg/wpguard.toml"
    monkeypatch.setattr(config, "SEARCH", (local, global_))
    assert config.ensure_default() == global_
    assert global_.exists()
    global_.unlink()
    local.write_text("")
    assert config.ensure_default() is None  # a config already exists: do nothing
    assert not global_.exists()
