from wpguard.behavior import entropy, score

OBFUSCATED = b"<?php " + b"$a=base64_decode('" + b"QUJD" * 600 + b"');eval(gzinflate($a));"


def test_benign_scores_low():
    pts, _ = score(b"<?php\nfunction hello() { return 'hi'; }\n", "wp-content/plugins/x/x.php")
    assert pts == 0


def test_obfuscated_payload_scores_high():
    pts, why = score(OBFUSCATED, "wp-content/plugins/x/x.php")
    assert pts >= 5
    assert any("eval" in w for w in why)


def test_names_and_places():
    assert score(b"<?php", "wp-content/uploads/a.php.jpg")[0] >= 4
    assert score(b"<?php", "wp-includes/js/x.php")[0] >= 3
    assert score(b"<?php", "wp-content/plugins/x/wp-vcd.php")[0] >= 5


def test_timestamps():
    now = 1_700_000_000.0
    assert score(b"<?php", "a.php", mtime=now + 86400, now=now)[0] == 2  # future
    assert score(b"<?php", "a.php", mtime=now, sibling_median=now - 90 * 86400, now=now)[0] == 2
    assert score(b"<?php", "a.php", mtime=now, sibling_median=now - 86400, now=now)[0] == 0


def test_entropy():
    assert entropy(b"") == 0.0
    assert entropy(bytes(range(256)) * 4) > 7.9
