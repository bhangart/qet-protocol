# SPDX-License-Identifier: Apache-2.0
"""Catalogues are untrusted input; plurals are resolved at build time."""

import json

import pytest

from qet_protocol.catalogue import Catalogues, resolve_plural
from qet_protocol.safety import InputRejected

POLISH = {"one": "# zacisk", "few": "# zaciski", "many": "# zacisków", "other": "# zacisku"}


@pytest.mark.parametrize(("count", "text"), [
    (1, "1 zacisk"), (2, "2 zaciski"), (4, "4 zaciski"), (5, "5 zacisków"), (22, "22 zaciski"),
])
def test_polish_plural_categories(count, text):
    assert resolve_plural("pl", {"count": count, "forms": POLISH}, "t") == text


def test_german_plural_and_fallback_to_other():
    forms = {"one": "# Anschluss", "other": "# Anschlüsse"}
    assert resolve_plural("de", {"count": 1, "forms": forms}, "t") == "1 Anschluss"
    assert resolve_plural("de", {"count": 3, "forms": forms}, "t") == "3 Anschlüsse"
    assert resolve_plural("pl", {"count": 5, "forms": {"other": "# x"}}, "t") == "5 x"


def test_plural_without_other_is_rejected():
    with pytest.raises(InputRejected):
        resolve_plural("de", {"count": 1, "forms": {"one": "x"}}, "t")


def write(directory, name, doc):
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return path


def catalogue(entries, language="de"):
    return {"catalogue": 1, "library": "qet-test", "language": language, "sourceLanguage": "en",
            "entries": entries}


ENTRY = {"scope": "element", "id": "{00000000-0000-4000-8000-000000000001}",
         "source": "Contactor", "translation": "Schütz", "provenance": "human",
         "status": "approved"}


def test_lookup_ignores_uuid_braces_and_case(tmp_path):
    write(tmp_path / "c", "de.json", catalogue([ENTRY]))
    cats = Catalogues.load(tmp_path / "c", "qet-test", "en")
    hit = cats.lookup("de", "element", "00000000-0000-4000-8000-000000000001".upper(), "Contactor")
    assert hit.text == "Schütz" and hit.provenance == "human"
    assert cats.lookup("de", "element", ENTRY["id"], "Contactor (renamed)") is None


@pytest.mark.parametrize(("doc", "rule"), [
    ('<!DOCTYPE x><x/>', "doctype"),
    ('{"catalogue": 1, "catalogue": 1}', "duplicate-key"),
    ("not json", "malformed"),
    ("[" * 100 + "]" * 100, "depth"),
])
def test_hostile_catalogue_files_are_rejected(tmp_path, doc, rule):
    write(tmp_path / "c", "x.json", doc)
    with pytest.raises(InputRejected) as info:
        Catalogues.load(tmp_path / "c", "qet-test", "en")
    assert info.value.rule == rule


@pytest.mark.parametrize("change", [
    {"library": "someone-else"}, {"sourceLanguage": "fr"}, {"catalogue": 2},
])
def test_catalogue_for_another_library_or_source_is_rejected(tmp_path, change):
    write(tmp_path / "c", "de.json", {**catalogue([ENTRY]), **change})
    with pytest.raises(InputRejected):
        Catalogues.load(tmp_path / "c", "qet-test", "en")


def test_duplicate_key_entries_are_rejected(tmp_path):
    write(tmp_path / "c", "de.json", catalogue([ENTRY, {**ENTRY, "translation": "Anders"}]))
    with pytest.raises(InputRejected):
        Catalogues.load(tmp_path / "c", "qet-test", "en")


@pytest.mark.parametrize("change", [
    {"scope": "file"}, {"provenance": "ai"}, {"status": "draft"}, {"translation": ""},
    {"translation": {"count": -1, "forms": {"other": "x"}}},
])
def test_malformed_entries_are_rejected(tmp_path, change):
    write(tmp_path / "c", "de.json", catalogue([{**ENTRY, **change}]))
    with pytest.raises(InputRejected):
        Catalogues.load(tmp_path / "c", "qet-test", "en")
