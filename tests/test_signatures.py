import gzip
import json
import sqlite3

from wpguard.signatures import SIG, compile_regex_files, hash_match, judge, load_hashdb

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_signatures():
    assert SIG.search(b"<?php eval(base64_decode($x));")
    assert SIG.search(b"<?php @$_POST['a']($_POST['b']);")
    assert not SIG.search(b"<?php echo 'hello';")


def test_judge_kinds():
    assert judge("x.php", ".php", False, b"<?php eval(base64_decode($x));", None)[0] == "sig"
    assert judge("a.jpg", ".jpg", True, b"GIF89a<?php", None) == ("struct", "php code in uploads")
    assert judge(".htaccess", "", True, b"", None) == ("struct", "htaccess in uploads")
    assert judge(".htaccess", "", False, b"RewriteRule ^(.*)$ http://evil.tld/$1 [R]", None)
    assert judge(".htaccess", "", False, b"RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301]", None) is None
    assert judge("wp-config.php", ".php", False, b"<?php eval($x);", None)[0] == "struct"
    assert judge("ok.php", ".php", False, b"<?php echo 1;", None) is None


def test_regex_file_skips_blank_comment_and_invalid_lines(tmp_path):
    f = tmp_path / "sigs.txt"
    f.write_text(
        "# comment\n\nevil_fn\\(\n(unclosed\n"
    )  # blank line + invalid regex must not break or match everything
    rx = compile_regex_files([f])
    assert rx.search(b"call evil_fn(1)")
    assert not rx.search(b"harmless text")
    assert compile_regex_files([]) is None


def test_hashdb_formats(tmp_path):
    csv = tmp_path / "a.csv"
    csv.write_text(f"name,hash\nbad,{MD5}\n")
    txt = tmp_path / "b.txt"
    txt.write_text(f"{SHA256}  shell.php\n")
    js = tmp_path / "c.json"
    js.write_text(json.dumps({"hashes": [MD5]}))
    gz = tmp_path / "d.hdb.gz"
    gz.write_bytes(gzip.compress(f"{MD5}:123:Name.Of.Malware\n".encode()))
    con = sqlite3.connect(tmp_path / "e.db")
    con.execute("create table t(h text)")
    con.execute("insert into t values (?)", (SHA256,))
    con.commit()
    con.close()
    db = load_hashdb([csv, txt, js, gz, tmp_path / "e.db"])
    assert db["md5"] == {MD5}
    assert db["sha256"] == {SHA256}


def test_hash_match(tmp_path):
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    assert hash_match(empty, {"md5": {MD5}, "sha1": set(), "sha256": set()}) == "md5"
    assert hash_match(empty, {"md5": {"0" * 32}, "sha1": set(), "sha256": set()}) is None
