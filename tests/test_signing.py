# SPDX-License-Identifier: Apache-2.0
"""Signing and verification: a single flipped byte anywhere is refused."""

import json
import stat
from datetime import UTC, datetime

import pytest

from qet_protocol.feedgen import dump_json, generate, load_config
from qet_protocol.feedtool import main
from qet_protocol.signing import keygen, load_private, sign_feed, sign_file
from qet_protocol.verify import VerificationFailed, verify

NOW = datetime(2026, 10, 2, tzinfo=UTC)


@pytest.fixture
def keys(tmp_path):
    keygen(tmp_path / "keys", "namespace")
    keygen(tmp_path / "keys", "channel")
    return tmp_path / "keys"


@pytest.fixture
def signed(collection, config, keys, tmp_path):
    out = tmp_path / "out"
    findings, _ = generate(collection, load_config(config), out)
    assert findings == []
    sign_feed(out, keys / "namespace.key", keys / "channel.key")
    return out


def check(out, keys, **kw):
    return verify(out, keys / "namespace.pub", keys / "channel.pub", kw.pop("now", NOW), **kw)


def rejected(out, keys, match=None, **kw):
    with pytest.raises(VerificationFailed, match=match):
        check(out, keys, **kw)


def flip(path, position):
    data = bytearray(path.read_bytes())
    data[position % len(data)] ^= 0x01
    path.write_bytes(bytes(data))


def resign(out, keys, name, role):
    private, keyid = load_private(keys / f"{role}.key", role)
    sign_file(out / name, private, keyid, "feed" if role == "namespace" else "channel-index")


def test_a_signed_feed_verifies(signed, keys):
    summary = check(signed, keys)
    assert summary["elements"] == 3 and summary["library"] == "qet-test"


@pytest.mark.parametrize("target", ["feed.json", "feed.json.sig", "index/stable.json",
                                    "index/stable.json.sig", "blob"])
@pytest.mark.parametrize("position", [0, 57, -2, -1])
def test_one_flipped_byte_anywhere_is_rejected(signed, keys, target, position):
    path = next((signed / "blob").iterdir()) if target == "blob" else signed / target
    flip(path, position)
    rejected(signed, keys)


def test_wrong_public_key_is_rejected(signed, keys, tmp_path):
    keygen(tmp_path / "other", "namespace")
    with pytest.raises(VerificationFailed, match="trusted feed key"):
        verify(signed, tmp_path / "other" / "namespace.pub", keys / "channel.pub", NOW)


@pytest.mark.parametrize("target", ["feed.json.sig", "index/stable.json.sig"])
def test_every_single_byte_of_a_signature_file_matters(signed, keys, target):
    path = signed / target
    original = path.read_bytes()
    accepted = []
    for position in range(len(original)):
        flip(path, position)
        try:
            check(signed, keys)
            accepted.append(position)
        except VerificationFailed:
            pass
        path.write_bytes(original)
    assert accepted == [], f"flips accepted at {accepted}"


def test_signature_roles_are_not_interchangeable(signed, keys):
    """A feed signature cannot stand in for an index signature (domain separation)."""
    private, keyid = load_private(keys / "channel.key", "channel")
    sig = sign_file(signed / "index" / "stable.json", private, keyid, "feed")
    doc = json.loads(sig.read_text())
    doc["role"] = "channel-index"
    sig.write_text(json.dumps(doc))
    rejected(signed, keys, "signature does not verify")


def test_channel_key_cannot_introduce_content(signed, keys):
    """S4: a validly channel-signed index naming a version the feed lacks is refused."""
    index_path = signed / "index" / "stable.json"
    index = json.loads(index_path.read_text())
    index["elements"][0]["hash"] = "sha256:" + "ab" * 32
    index_path.write_bytes(dump_json(index))
    resign(signed, keys, "index/stable.json", "channel")
    rejected(signed, keys, r"not in the signed feed \(S4\)")


def test_older_index_is_refused(signed, keys):
    version = check(signed, keys)["index_version"]
    rejected(signed, keys, "rollback", trusted_index_version=version + 1)
    assert check(signed, keys, trusted_index_version=version)


def test_expired_index_is_refused(signed, keys):
    rejected(signed, keys, "freeze", now=datetime(2026, 10, 9, tzinfo=UTC))


def test_feed_without_usage_is_rejected_even_when_signed(signed, keys):
    feed = json.loads((signed / "feed.json").read_text())
    del feed["usage"]
    (signed / "feed.json").write_bytes(dump_json(feed))
    resign(signed, keys, "feed.json", "namespace")
    rejected(signed, keys, "usage")


def test_hostile_blob_with_matching_signed_hash_is_still_refused(signed, keys):
    """Step 7 of annex §8.6: a signed, hash-correct blob still gets the byte pre-check."""
    import hashlib
    evil = b'<!DOCTYPE d [<!ENTITY x "y">]><definition/>'
    feed = json.loads((signed / "feed.json").read_text())
    element = feed["elements"][0]
    (signed / "blob" / element["hash"].removeprefix("sha256:")).unlink()
    element["hash"] = "sha256:" + hashlib.sha256(evil).hexdigest()
    element["size"] = len(evil)
    (signed / "blob" / element["hash"].removeprefix("sha256:")).write_bytes(evil)
    (signed / "feed.json").write_bytes(dump_json(feed))
    resign(signed, keys, "feed.json", "namespace")
    index_path = signed / "index" / "stable.json"
    index = json.loads(index_path.read_text())
    entry = next(e for e in index["elements"] if e["uuid"] == element["uuid"])
    entry["hash"], entry["size"] = element["hash"], element["size"]
    from qet_protocol.feedgen import snapshot_of
    index["snapshot"] = snapshot_of(index["elements"])
    index_path.write_bytes(dump_json(index))
    resign(signed, keys, "index/stable.json", "channel")
    rejected(signed, keys, r"\[doctype\]")


def test_missing_blob_is_rejected(signed, keys):
    next((signed / "blob").iterdir()).unlink()
    rejected(signed, keys, "missing")


def test_signing_is_deterministic(signed, keys):
    before = (signed / "feed.json.sig").read_bytes()
    sign_feed(signed, keys / "namespace.key", keys / "channel.key")
    assert (signed / "feed.json.sig").read_bytes() == before


def test_keygen_writes_a_private_test_key(tmp_path, capsys):
    key, pub = keygen(tmp_path, "namespace")
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert json.loads(key.read_text())["test"] is True
    assert "private" not in json.loads(pub.read_text())
    assert "TEST KEY" in capsys.readouterr().err
    with pytest.raises(FileExistsError):
        keygen(tmp_path, "namespace")


def test_key_roles_are_checked(keys):
    with pytest.raises(ValueError, match="not a channel key"):
        load_private(keys / "namespace.key", "channel")


def test_cli_verify_exit_codes(signed, keys):
    args = ["verify", str(signed), "--namespace-pub", str(keys / "namespace.pub"),
            "--channel-pub", str(keys / "channel.pub"), "--now", "2026-10-02T00:00:00Z"]
    assert main(args) == 0
    flip(signed / "feed.json", 10)
    assert main(args) == 1
