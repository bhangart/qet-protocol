# SPDX-License-Identifier: Apache-2.0
"""The schemas accept what part D allows and reject what the invariants forbid."""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


def _registry() -> Registry:
    resources = []
    for path in SCHEMAS.glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


REGISTRY = _registry()


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / f"{name}-v1.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=REGISTRY)


def example(name: str) -> dict:
    return json.loads((SCHEMAS / "examples" / f"{name}.json").read_text(encoding="utf-8"))


def is_valid(name: str, doc: dict) -> bool:
    return validator(name).is_valid(doc)


@pytest.mark.parametrize("path", sorted(SCHEMAS.glob("*.schema.json")), ids=lambda p: p.name)
def test_every_schema_is_itself_valid(path):
    Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    ("schema", "doc"),
    [("feed", "feed"), ("channel-index", "channel-index"), ("pins", "pins"),
     ("catalogue", "catalogue-pl")],
)
def test_examples_validate(schema, doc):
    errors = list(validator(schema).iter_errors(example(doc)))
    assert not errors, [e.message for e in errors]


# --- usage: required at library level, optional per element, never defaulted


def test_feed_without_library_usage_is_invalid():
    feed = example("feed")
    del feed["usage"]
    assert not is_valid("feed", feed)


@pytest.mark.parametrize("term", ["licence", "train-ai", "ai-use", "search"])
def test_usage_with_a_missing_term_is_invalid(term):
    feed = example("feed")
    del feed["usage"][term]
    assert not is_valid("feed", feed)


def test_element_without_usage_inherits_and_is_valid():
    feed = example("feed")
    assert "usage" not in feed["elements"][0]
    assert is_valid("feed", feed)


def test_element_usage_override_is_valid():
    feed = example("feed")
    feed["elements"][0]["usage"] = {"licence": "CC0-1.0", "train-ai": "y", "ai-use": "y",
                                    "search": "y"}
    assert is_valid("feed", feed)


def test_schemas_declare_no_default_anywhere():
    for path in SCHEMAS.glob("*.schema.json"):
        assert '"default"' not in path.read_text(encoding="utf-8"), path.name


# --- representation is an open vocabulary


@pytest.mark.parametrize("value", ["symbol", "scheme", "geometry-2d", "terminal-view",
                                   "org.example:pid-view", "com.acme.tools:wiring-3d"])
def test_representation_accepts_core_and_namespaced_values(value):
    feed = example("feed")
    feed["elements"][0]["representation"] = value
    assert is_valid("feed", feed)


@pytest.mark.parametrize("value", ["photo", "pid-view", "Symbol", ":x"])
def test_representation_rejects_unregistered_unnamespaced_values(value):
    feed = example("feed")
    feed["elements"][0]["representation"] = value
    assert not is_valid("feed", feed)


# --- S1 / S8: the core is closed, contact is a relay


@pytest.mark.parametrize("field", ["thumbnail", "clientId", "url"])
def test_unknown_core_fields_are_rejected(field):
    feed = example("feed")
    feed["elements"][0][field] = "x"
    assert not is_valid("feed", feed)
    feed = example("feed")
    feed[field] = "x"
    assert not is_valid("feed", feed)


def test_extensions_take_namespaced_keys_only():
    feed = example("feed")
    feed["elements"][0]["extensions"] = {"x-example.org": {"anything": 1}}
    assert is_valid("feed", feed)
    feed["elements"][0]["extensions"] = {"tracking": {}}
    assert not is_valid("feed", feed)


@pytest.mark.parametrize("contact", ["mailto:someone@example.org", "someone@example.org",
                                     "http://example.org/c/1", "https://user@example.org/"])
def test_contact_must_be_an_https_relay_not_an_address(contact):
    feed = example("feed")
    feed["contact"] = contact
    assert not is_valid("feed", feed)


# --- paths


@pytest.mark.parametrize("path", ["/etc/passwd.elmt", "../x.elmt", "a/../b.elmt", "a/./b.elmt",
                                  "a\\b.elmt", "a/b.xml", "a/\x01.elmt"])
def test_unsafe_paths_are_rejected(path):
    feed = example("feed")
    feed["elements"][0]["path"] = path
    assert not is_valid("feed", feed)


def test_non_ascii_path_is_accepted():
    feed = example("feed")
    feed["elements"][0]["path"] = "10_electric/endress+hauser-débimétre.elmt"
    assert is_valid("feed", feed)


# --- lifecycle and provenance


def test_article_lifecycle_state_is_closed():
    feed = example("feed")
    feed["elements"][0]["articles"][0]["lifecycle"]["state"] = "obsolete"
    assert not is_valid("feed", feed)


def test_lifecycle_successor_is_an_article_not_a_uuid():
    feed = example("feed")
    feed["elements"][0]["articles"][0]["lifecycle"]["successor"] = {"uuid": "x"}
    assert not is_valid("feed", feed)


def test_derived_provenance_requires_derived_from():
    feed = example("feed")
    feed["elements"][0]["provenance"] = {"kind": "derived"}
    assert not is_valid("feed", feed)
    feed["elements"][0]["provenance"]["derived_from"] = (
        "{8f1c2a3b-0000-4000-8000-000000000001}@2.1.0")
    assert is_valid("feed", feed)


# --- channel index


@pytest.mark.parametrize("field", ["version", "expires", "snapshot"])
def test_index_requires_the_rollback_and_freeze_fields(field):
    index = example("channel-index")
    del index[field]
    assert not is_valid("channel-index", index)


def test_withdrawn_entry_needs_a_class_and_carries_no_size():
    index = example("channel-index")
    tomb = index["elements"][1]
    del tomb["withdrawal_class"]
    assert not is_valid("channel-index", index)
    index = example("channel-index")
    index["elements"][1]["size"] = 1
    assert not is_valid("channel-index", index)


def test_namespaced_channel_is_accepted_and_bare_one_is_not():
    index = example("channel-index")
    index["channel"] = "com.example:pilot"
    assert is_valid("channel-index", index)
    index["channel"] = "pilot"
    assert not is_valid("channel-index", index)


# --- pins


def test_pin_names_a_library_not_a_url():
    pins = example("pins")
    pins["elements"][0]["source"] = "https://library.example.org/feed.json"
    assert not is_valid("pins", pins)


def test_forked_pin_requires_lineage_and_detached_requires_a_reason():
    pins = example("pins")
    pins["elements"][0]["state"] = "forked"
    assert not is_valid("pins", pins)
    pins = example("pins")
    pins["elements"][0]["state"] = "detached"
    assert not is_valid("pins", pins)


# --- catalogue


def test_plural_translation_requires_other():
    cat = example("catalogue-pl")
    del cat["entries"][1]["translation"]["forms"]["other"]
    assert not is_valid("catalogue", cat)


def test_plural_rejects_unknown_categories():
    cat = example("catalogue-pl")
    cat["entries"][1]["translation"]["forms"]["several"] = "x"
    assert not is_valid("catalogue", cat)


def test_catalogue_entry_needs_provenance_and_status():
    for field in ("provenance", "status"):
        cat = copy.deepcopy(example("catalogue-pl"))
        del cat["entries"][0][field]
        assert not is_valid("catalogue", cat)
