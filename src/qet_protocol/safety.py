# SPDX-License-Identifier: Apache-2.0
"""Input rules that apply before any parser runs (implementation plan §3.2).

Every component that reads protocol input — elements, feeds, indexes,
catalogues — goes through these checks first. The DOCTYPE/entity rule is a
byte scan, not a parser setting, so it holds whatever parser runs next (S2).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

ELEMENT_MAX_BYTES = 2 * 1024 * 1024
CATALOGUE_MAX_BYTES = 16 * 1024 * 1024
FEED_MAX_BYTES = 64 * 1024 * 1024
SIGNATURE_MAX_BYTES = 4096

MAX_DEPTH = 32
MAX_NODES = 50_000
MAX_TEXT_BYTES = 64 * 1024

FORBIDDEN_MARKERS = ((b"<!DOCTYPE", "doctype"), (b"<!ENTITY", "entity"))

# Rules whose failure is a security finding. These are never suppressible.
SECURITY_RULES = frozenset(
    {"size", "doctype", "entity", "depth", "nodes", "text-length", "symlink", "special-file"}
)


class InputRejected(Exception):
    """Raised when input fails a rule. `rule` names which one."""

    def __init__(self, rule: str, message: str):
        super().__init__(f"[{rule}] {message}")
        self.rule = rule
        self.message = message


def precheck_bytes(data: bytes, max_bytes: int) -> None:
    """Size cap and forbidden markers, on raw bytes, before any parsing."""
    if len(data) > max_bytes:
        raise InputRejected("size", f"{len(data)} bytes exceeds the cap of {max_bytes}")
    for marker, rule in FORBIDDEN_MARKERS:
        if marker in data:
            raise InputRejected(rule, f"contains {marker.decode()}")


def read_capped(path: Path, max_bytes: int) -> bytes:
    """Read a regular file, refusing symlinks and anything over the cap.

    The size is checked on the open file descriptor and again on the bytes
    read, so a file that grows between the two cannot slip through.
    """
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise InputRejected("symlink", "is a symbolic link")
    if not stat.S_ISREG(st.st_mode):
        raise InputRejected("special-file", "is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        if os.fstat(fh.fileno()).st_size > max_bytes:
            raise InputRejected("size", f"exceeds the cap of {max_bytes} bytes")
        data = fh.read(max_bytes + 1)
    precheck_bytes(data, max_bytes)
    return data


def json_depth_ok(value: object, limit: int = MAX_DEPTH) -> bool:
    """Iterative depth check for parsed JSON (no recursion on untrusted input)."""
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > limit:
            return False
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    return True
