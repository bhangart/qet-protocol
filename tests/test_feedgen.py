# SPDX-License-Identifier: Apache-2.0
"""qet-feedgen end to end on small committed collections."""

import filecmp
import json
import socket

import pytest
from conftest import commit_all, element, uuid_n
from test_schemas import validator

from qet_protocol.feedgen import ConfigError, generate, load_config, main


def run(collection, config, out, **kw):
    return generate(collection, load_config(config), out, **kw)


def read(out, name="feed.json"):
    return json.loads((out / name).read_text(encoding="utf-8"))


def same_tree(a, b) -> bool:
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.funny_files:
        return False
    _, mismatch, errors = filecmp.cmpfiles(a, b, cmp.common_files, shallow=False)
    return not mismatch and not errors and all(
        same_tree(a / d, b / d) for d in cmp.common_dirs)


def test_feed_index_and_blobs_are_written_and_valid(collection, config, tmp_path):
    out = tmp_path / "out"
    findings, summary = run(collection, config, out)
    assert findings == [] and summary["elements"] == 3
    feed, index = read(out), read(out, "index/stable.json")
    assert not list(validator("feed").iter_errors(feed))
    assert not list(validator("channel-index").iter_errors(index))
    assert len(list((out / "blob").iterdir())) == 3
    first = feed["elements"][0]
    blob = (out / "blob" / first["hash"].removeprefix("sha256:")).read_bytes()
    assert len(blob) == first["size"]
    assert first["names"]["pt-BR"] == "Contactor BR"
    assert first["articles"] == [{"manufacturer": "ACME", "partNumber": "X-1"}]
    assert feed["catalogueRevision"] is None
    assert index["updated"] == "2026-10-01T12:00:00Z"
    assert index["expires"] == "2026-10-08T12:00:00Z"


def test_two_runs_are_byte_identical(collection, config, tmp_path):
    run(collection, config, tmp_path / "a")
    run(collection, config, tmp_path / "b")
    assert same_tree(tmp_path / "a", tmp_path / "b")


def test_paths_are_nfc_and_sorted_bytewise(collection, config, tmp_path):
    run(collection, config, tmp_path / "out")
    paths = [e["path"] for e in read(tmp_path / "out")["elements"]]
    assert paths == sorted(paths, key=lambda p: p.encode())
    assert "10_electric/débimètre.elmt" in paths


def test_generator_makes_no_network_access(collection, config, tmp_path, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    findings, _ = run(collection, config, tmp_path / "out")
    assert findings == []


def test_rejected_element_is_reported_with_its_path_and_nothing_is_written(
        collection, config, tmp_path):
    (collection / "10_electric" / "evil.elmt").write_bytes(
        b'<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + element(uuid_n(9)))
    commit_all(collection)
    out = tmp_path / "out"
    findings, _ = run(collection, config, out)
    assert [(f.path, f.rule) for f in findings] == [("10_electric/evil.elmt", "doctype")]
    assert not out.exists()
    assert not list(tmp_path.glob(".qet-feedgen-*"))


def test_cli_exit_codes(collection, config, tmp_path, capsys):
    assert main([str(collection), "--config", str(config), "--out", str(tmp_path / "a")]) == 0
    (collection / "bad.elmt").write_bytes(b"<definition><unclosed></definition>")
    commit_all(collection)
    assert main([str(collection), "--config", str(config), "--out", str(tmp_path / "b")]) == 1
    assert "bad.elmt: [malformed]" in capsys.readouterr().err


def test_duplicate_uuid_is_rejected_unless_suppressed_with_a_reason(collection, config, tmp_path):
    (collection / "copy.elmt").write_bytes(element(uuid_n(1)))
    commit_all(collection)
    findings, _ = run(collection, config, tmp_path / "a")
    assert [(f.path, f.rule) for f in findings] == [("copy.elmt", "duplicate-uuid")]
    doc = json.loads(config.read_text())
    doc["suppress"] = [{"path": "copy.elmt", "rule": "duplicate-uuid", "reason": "test"}]
    config.write_text(json.dumps(doc))
    findings, summary = run(collection, config, tmp_path / "b")
    assert findings == [] and summary["suppressed"] == 1 and summary["elements"] == 3


def test_stale_suppression_is_reported(collection, config, tmp_path):
    doc = json.loads(config.read_text())
    doc["suppress"] = [{"path": "gone.elmt", "rule": "duplicate-uuid", "reason": "old"}]
    config.write_text(json.dumps(doc))
    findings, _ = run(collection, config, tmp_path / "out")
    assert [f.rule for f in findings] == ["stale-suppression"]


@pytest.mark.parametrize("rule", ["doctype", "entity", "size", "symlink", "depth"])
def test_security_rules_cannot_be_suppressed(config, rule):
    doc = json.loads(config.read_text())
    doc["suppress"] = [{"path": "x.elmt", "rule": rule, "reason": "please"}]
    config.write_text(json.dumps(doc))
    with pytest.raises(ConfigError, match="cannot be suppressed"):
        load_config(config)


def test_symlinked_element_is_a_security_finding(collection, config, tmp_path):
    (collection / "link.elmt").symlink_to(collection / "10_electric" / "a" / "one.elmt")
    commit_all(collection)
    findings, _ = run(collection, config, tmp_path / "out")
    assert [(f.path, f.rule) for f in findings] == [("link.elmt", "symlink")]


@pytest.mark.parametrize("missing", ["usage", "usage.train-ai", "usage.licence"])
def test_config_without_usage_has_no_default(config, missing):
    doc = json.loads(config.read_text())
    if "." in missing:
        del doc["usage"][missing.split(".")[1]]
    else:
        del doc[missing]
    config.write_text(json.dumps(doc))
    with pytest.raises(ConfigError, match="usage"):
        load_config(config)


def test_uncommitted_changes_are_refused(collection, config, tmp_path):
    (collection / "new.elmt").write_bytes(element(uuid_n(5)))
    with pytest.raises(ConfigError, match="uncommitted"):
        run(collection, config, tmp_path / "out")


def test_non_empty_output_directory_is_refused(collection, config, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "old").write_text("x")
    with pytest.raises(ConfigError, match="not empty"):
        run(collection, config, out)


def test_catalogue_names_override_element_names(collection, config, tmp_path):
    cats = tmp_path / "catalogues"
    cats.mkdir()
    (cats / "de.json").write_text(json.dumps({
        "catalogue": 1, "library": "qet-test", "language": "de", "sourceLanguage": "en",
        "entries": [
            {"scope": "element", "id": uuid_n(1), "source": "Contactor", "translation": "Schütz",
             "provenance": "human", "status": "approved"},
            {"scope": "element", "id": uuid_n(2), "source": "Coil",
             "translation": {"count": 2, "forms": {"one": "# Spule", "other": "# Spulen"}},
             "provenance": "machine", "status": "approved"},
        ]}), encoding="utf-8")
    from conftest import git
    git(cats, "init", "-q")
    commit_all(cats)
    findings, _ = run(collection, config, tmp_path / "out", catalogue_dir=cats)
    assert findings == []
    feed = read(tmp_path / "out")
    by_uuid = {e["uuid"]: e for e in feed["elements"]}
    assert by_uuid[uuid_n(1)]["names"]["de"] == "Schütz"
    assert by_uuid[uuid_n(1)]["nameProvenance"] == {"de": "human"}
    assert by_uuid[uuid_n(2)]["names"]["de"] == "2 Spulen"
    assert "de" not in by_uuid[uuid_n(3)]["names"]
    assert len(feed["catalogueRevision"]) == 40
    assert not list(validator("feed").iter_errors(feed))
