# SPDX-License-Identifier: Apache-2.0
"""Translation catalogues: untrusted input, resolved to finished strings.

Plural forms are evaluated here, at build time, so that no client ever
evaluates a message format (annex §8.1). The feed receives exactly one
string per language.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from babel import Locale, UnknownLocaleError

from .safety import CATALOGUE_MAX_BYTES, InputRejected, json_depth_ok, read_capped

PLURAL_CATEGORIES = ("zero", "one", "two", "few", "many", "other")
SCOPES = ("element", "category", "rule", "library")


@dataclass(frozen=True)
class Translation:
    text: str
    provenance: str


def normalise_id(scope: str, value: str) -> str:
    """Element ids are UUIDs; compare them without braces and case."""
    return value.strip("{}").lower() if scope == "element" else value


def _no_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise InputRejected("duplicate-key", f"duplicate JSON key {key!r}")
        seen[key] = value
    return seen


def _string(entry: dict, key: str, where: str, limit: int = 1024) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value or len(value) > limit:
        raise InputRejected("catalogue-structure",
                            f"{where}: '{key}' must be a string of 1-{limit}")
    return value


def resolve_plural(language: str, translation: dict, where: str) -> str:
    count = translation.get("count")
    forms = translation.get("forms")
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 1_000_000:
        raise InputRejected("catalogue-structure", f"{where}: plural 'count' must be 0-1000000")
    if not isinstance(forms, dict) or "other" not in forms:
        raise InputRejected("catalogue-structure", f"{where}: plural needs 'forms' with 'other'")
    for key, value in forms.items():
        if key not in PLURAL_CATEGORIES or not isinstance(value, str) or not value:
            raise InputRejected("catalogue-structure", f"{where}: bad plural form {key!r}")
    try:
        category = Locale.parse(language.replace("-", "_")).plural_form(count)
    except (UnknownLocaleError, ValueError):
        raise InputRejected("catalogue-language",
                            f"{where}: no plural rules for {language}") from None
    text = forms.get(category, forms["other"])
    return text.replace("#", str(count))


class Catalogues:
    """All catalogues of one library, indexed by (language, scope, id, source)."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str, str, str], Translation] = {}
        self.languages: list[str] = []

    def lookup(self, language: str, scope: str, ident: str, source: str) -> Translation | None:
        return self._entries.get((language, scope, normalise_id(scope, ident), source))

    @classmethod
    def load(cls, directory: Path, library: str, source_language: str) -> Catalogues:
        result = cls()
        for path in sorted(directory.glob("*.json")):
            result._load_file(path, library, source_language)
        return result

    def _load_file(self, path: Path, library: str, source_language: str) -> None:
        data = read_capped(path, CATALOGUE_MAX_BYTES)
        try:
            doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise InputRejected("malformed", f"{path.name}: not valid UTF-8 JSON: {exc}") from None
        if not json_depth_ok(doc):
            raise InputRejected("depth", f"{path.name}: nesting too deep")
        if not isinstance(doc, dict) or doc.get("catalogue") != 1:
            raise InputRejected("catalogue-structure", f"{path.name}: not a version 1 catalogue")
        if doc.get("library") != library:
            raise InputRejected("catalogue-structure", f"{path.name}: belongs to another library")
        if doc.get("sourceLanguage") != source_language:
            raise InputRejected("catalogue-structure", f"{path.name}: wrong sourceLanguage")
        language = _string(doc, "language", path.name, 35)
        if language in self.languages:
            raise InputRejected("catalogue-structure", f"{path.name}: second file for {language}")
        entries = doc.get("entries")
        if not isinstance(entries, list):
            raise InputRejected("catalogue-structure", f"{path.name}: 'entries' must be a list")
        self.languages.append(language)
        for number, entry in enumerate(entries):
            where = f"{path.name} entry {number}"
            if not isinstance(entry, dict):
                raise InputRejected("catalogue-structure", f"{where}: not an object")
            scope = entry.get("scope")
            if scope not in SCOPES:
                raise InputRejected("catalogue-structure", f"{where}: unknown scope")
            ident = normalise_id(scope, _string(entry, "id", where, 256))
            source = _string(entry, "source", where)
            provenance = entry.get("provenance")
            if provenance not in ("human", "machine"):
                raise InputRejected("catalogue-structure", f"{where}: bad provenance")
            if entry.get("status") not in ("approved", "needs-review"):
                raise InputRejected("catalogue-structure", f"{where}: bad status")
            translation = entry.get("translation")
            if isinstance(translation, dict):
                text = resolve_plural(language, translation, where)
            else:
                text = _string(entry, "translation", where)
            key = (language, scope, ident, source)
            if key in self._entries:
                raise InputRejected("catalogue-structure",
                                    f"{where}: duplicate (scope, id, source)")
            self._entries[key] = Translation(text, provenance)
