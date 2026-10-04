# SPDX-License-Identifier: Apache-2.0
"""§3.2 input rules: byte pre-checks and the bounded XML reader."""

import os

import pytest
from conftest import element, uuid_n

from qet_protocol.elmt import read_element
from qet_protocol.safety import (
    ELEMENT_MAX_BYTES,
    MAX_DEPTH,
    MAX_NODES,
    MAX_TEXT_BYTES,
    InputRejected,
    json_depth_ok,
    precheck_bytes,
    read_capped,
)


def rule_of(fn, *args) -> str:
    with pytest.raises(InputRejected) as info:
        fn(*args)
    return info.value.rule


# --- byte pre-check (S2)


@pytest.mark.parametrize(("payload", "rule"), [
    (b'<!DOCTYPE d [<!ENTITY a "x">]><definition/>', "doctype"),
    (b'<definition><!ENTITY a "x"></definition>', "entity"),
    (b"<!DOCTYPE definition SYSTEM 'file:///etc/passwd'><definition/>", "doctype"),
])
def test_doctype_and_entity_are_rejected_on_bytes(payload, rule):
    assert rule_of(precheck_bytes, payload, ELEMENT_MAX_BYTES) == rule


def test_oversize_is_rejected_before_parsing():
    assert rule_of(precheck_bytes, b" " * (ELEMENT_MAX_BYTES + 1), ELEMENT_MAX_BYTES) == "size"


def test_read_capped_refuses_symlinks(tmp_path):
    target = tmp_path / "real.elmt"
    target.write_bytes(element(uuid_n(1)))
    link = tmp_path / "link.elmt"
    link.symlink_to(target)
    assert rule_of(read_capped, link, ELEMENT_MAX_BYTES) == "symlink"


def test_read_capped_refuses_special_files(tmp_path):
    fifo = tmp_path / "pipe.elmt"
    os.mkfifo(fifo)
    assert rule_of(read_capped, fifo, ELEMENT_MAX_BYTES) == "special-file"


def test_read_capped_refuses_oversize_files(tmp_path):
    big = tmp_path / "big.elmt"
    big.write_bytes(b"<definition>" + b" " * ELEMENT_MAX_BYTES + b"</definition>")
    assert rule_of(read_capped, big, ELEMENT_MAX_BYTES) == "size"


def test_json_depth():
    deep: list = []
    node = deep
    for _ in range(MAX_DEPTH + 1):
        node.append([])
        node = node[0]
    assert not json_depth_ok(deep)
    assert json_depth_ok({"a": [1, {"b": 2}]})


# --- bounded reader


def test_reads_uuid_names_and_informations():
    info = read_element(element(uuid_n(7)))
    assert info.uuid == uuid_n(7)
    assert info.names == {"fr": "Contacteur", "en": "Contactor", "pt_BR": "Contactor BR"}
    assert info.informations == {"manufacturer": "ACME", "manufacturer_reference": "X-1"}


def test_depth_bomb_is_rejected():
    doc = b"<definition>" + b"<g>" * MAX_DEPTH + b"</g>" * MAX_DEPTH + b"</definition>"
    assert rule_of(read_element, doc) == "depth"


def test_node_bomb_is_rejected():
    doc = b"<definition>" + b"<line/>" * MAX_NODES + b"</definition>"
    assert rule_of(read_element, doc) == "nodes"


def test_long_text_node_is_rejected():
    doc = b"<definition><names><name lang='en'>" + b"x" * (MAX_TEXT_BYTES + 1) + b"</name>"
    doc += b"</names></definition>"
    assert rule_of(read_element, doc) == "text-length"


def test_undeclared_entity_is_malformed_not_resolved():
    doc = b"<definition><names><name lang='en'>&xxe;</name></names></definition>"
    assert rule_of(read_element, doc) == "malformed"


def test_wrong_root_is_rejected():
    assert rule_of(read_element, b"<project/>") == "not-an-element"


def test_truncated_xml_is_malformed():
    assert rule_of(read_element, element(uuid_n(1))[:200]) == "malformed"
