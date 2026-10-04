# SPDX-License-Identifier: Apache-2.0
"""Read the few fields a feed needs from a .elmt file, under hard limits.

Streaming expat parse: depth, node count and per-node text length are
enforced while parsing. Nothing in the document is ever resolved — there is
no DOCTYPE by the time this runs (safety.precheck_bytes), external entity
references are refused, and the bytes are never re-serialised.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.parsers import expat

from .safety import MAX_DEPTH, MAX_NODES, MAX_TEXT_BYTES, InputRejected

_NAMES = ("definition", "names", "name")
_INFO = ("definition", "elementInformations", "elementInformation")
_UUID = ("definition", "uuid")


@dataclass
class ElementInfo:
    uuid: str | None = None
    names: dict[str, str] = field(default_factory=dict)
    informations: dict[str, str] = field(default_factory=dict)


class _Reader:
    def __init__(self) -> None:
        self.info = ElementInfo()
        self.stack: list[str] = []
        self.attrs: list[dict[str, str]] = []
        self.text: list[str] = []
        self.text_len = 0
        self.nodes = 0

    def start(self, tag: str, attrs: dict[str, str]) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise InputRejected("nodes", f"more than {MAX_NODES} elements")
        self.stack.append(tag)
        if len(self.stack) > MAX_DEPTH:
            raise InputRejected("depth", f"nesting deeper than {MAX_DEPTH}")
        if len(self.stack) == 1 and tag != "definition":
            raise InputRejected("not-an-element", f"root is <{tag}>, not <definition>")
        if tuple(self.stack) == _UUID and self.info.uuid is None:
            self.info.uuid = attrs.get("uuid")
        self.attrs.append(attrs)
        self.text = []
        self.text_len = 0

    def chars(self, data: str) -> None:
        self.text_len += len(data.encode("utf-8"))
        if self.text_len > MAX_TEXT_BYTES:
            raise InputRejected("text-length", f"a text node exceeds {MAX_TEXT_BYTES} bytes")
        self.text.append(data)

    def end(self, tag: str) -> None:
        path = tuple(self.stack)
        attrs = self.attrs.pop()
        if path in (_NAMES, _INFO):
            text = "".join(self.text).strip()
            if path == _NAMES:
                lang = attrs.get("lang", "")
                if lang and text:
                    self.info.names.setdefault(lang, text)
            else:
                name = attrs.get("name", "")
                if name and text:
                    self.info.informations.setdefault(name, text)
        self.stack.pop()
        self.text = []
        self.text_len = 0


def _refuse_external(*_args) -> int:
    raise InputRejected("entity", "external entity reference")


def read_element(data: bytes) -> ElementInfo:
    """Parse already pre-checked bytes. Raises InputRejected on any failure."""
    reader = _Reader()
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.ExternalEntityRefHandler = _refuse_external
    parser.StartElementHandler = reader.start
    parser.EndElementHandler = reader.end
    parser.CharacterDataHandler = reader.chars
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise InputRejected("malformed", f"not well-formed XML: {exc}") from None
    return reader.info
