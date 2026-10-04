# SPDX-License-Identifier: Apache-2.0
"""qet-feed verify: check a signed feed directory, independently of the generator.

This is a separate code path from generation on purpose: it shares only the
byte-level input rules (safety.py) and the bounded element reader. It follows
the client's verification order (annex §8.6): byte pre-check, signature,
then parse; index version and expiry; every index entry must exist in the
namespace-signed feed (S4); then each blob — size, hash, byte pre-check,
bounded parse. Nothing is parsed before its signature has been checked.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .elmt import read_element
from .safety import (
    ELEMENT_MAX_BYTES,
    FEED_MAX_BYTES,
    SIGNATURE_MAX_BYTES,
    InputRejected,
    json_depth_ok,
    read_capped,
)
from .signing import DOMAIN, key_id

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID_RE = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
PATH_RE = re.compile(r"^(?!/)(?!.*(^|/)\.{1,2}(/|$))[^\\\x00-\x1f]+\.elmt$")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class VerificationFailed(Exception):
    pass


def load_public(path: Path, role: str) -> tuple[Ed25519PublicKey, str]:
    doc = json.loads(read_capped(path, SIGNATURE_MAX_BYTES).decode("utf-8"))
    if doc.get("key") != 1 or doc.get("role") != role:
        raise VerificationFailed(f"{path} is not a {role} public key")
    raw = base64.b64decode(doc["public"], validate=True)
    if doc.get("keyid") != key_id(raw):
        raise VerificationFailed(f"{path}: keyid does not match the key")
    return Ed25519PublicKey.from_public_bytes(raw), doc["keyid"]


def _strict_json(data: bytes, what: str) -> object:
    def no_dupes(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise VerificationFailed(f"{what}: duplicate JSON key")
        return dict(pairs)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=no_dupes)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise VerificationFailed(f"{what}: not valid UTF-8 JSON ({exc})") from None
    if not json_depth_ok(value):
        raise VerificationFailed(f"{what}: nesting too deep")
    return value


def verified_bytes(path: Path, key: tuple[Ed25519PublicKey, str], signed_as: str) -> bytes:
    """Steps 1-2 of annex §8.6: pre-check the bytes, then verify the signature."""
    what = path.name
    try:
        data = read_capped(path, FEED_MAX_BYTES)
        sig_doc = _strict_json(read_capped(path.with_name(path.name + ".sig"),
                                           SIGNATURE_MAX_BYTES), what + ".sig")
    except (InputRejected, OSError) as exc:
        raise VerificationFailed(f"{what}: {exc}") from None
    if not isinstance(sig_doc, dict) or sig_doc.get("signature") != 1 \
            or sig_doc.get("alg") != "ed25519" or sig_doc.get("role") != signed_as:
        raise VerificationFailed(f"{what}.sig: not an ed25519 '{signed_as}' signature")
    public, expected_keyid = key
    if set(sig_doc) != {"signature", "alg", "role", "keyid", "sig"} \
            or sig_doc["keyid"] != expected_keyid:
        raise VerificationFailed(f"{what}.sig: not made by the trusted {signed_as} key")
    try:
        encoded = str(sig_doc["sig"])
        signature = base64.b64decode(encoded, validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
            raise binascii.Error("non-canonical signature encoding")
        public.verify(signature, DOMAIN + signed_as.encode("ascii") + b"\x00" + data)
    except (binascii.Error, InvalidSignature):
        raise VerificationFailed(f"{what}: signature does not verify") from None
    return data


def _check_usage(usage: object) -> None:
    """A feed without a library-level usage block is rejected, never defaulted."""
    if not isinstance(usage, dict) or not isinstance(usage.get("licence"), str) or any(
            usage.get(term) not in ("y", "n") for term in ("train-ai", "ai-use", "search")):
        raise VerificationFailed("feed.json: library-level 'usage' block missing or incomplete")


def _snapshot(entries: list[dict]) -> str:
    lines = sorted(
        f"{e['uuid']} {e['version']} "
        f"{'withdrawn' if e.get('status') == 'withdrawn' else e['hash']}\n" for e in entries)
    return "sha256:" + hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def verify(out: Path, namespace_pub: Path, channel_pub: Path, now: datetime | None = None,
           trusted_index_version: int = 0, channel: str = "stable") -> dict:
    """Raise VerificationFailed on the first failure; return a summary on success."""
    now = now or datetime.now(UTC)
    feed = _strict_json(verified_bytes(out / "feed.json", load_public(namespace_pub, "namespace"),
                                       "feed"), "feed.json")
    if not isinstance(feed, dict) or feed.get("feed") != 1:
        raise VerificationFailed("feed.json: not a version 1 feed")
    _check_usage(feed.get("usage"))
    elements = feed.get("elements")
    if not isinstance(elements, list):
        raise VerificationFailed("feed.json: 'elements' must be a list")
    signed: dict[str, tuple[str, str, int]] = {}
    paths: set[str] = set()
    for e in elements:
        if not (isinstance(e, dict) and isinstance(e.get("path"), str)
                and PATH_RE.match(e["path"]) and UUID_RE.match(str(e.get("uuid")))
                and VERSION_RE.match(str(e.get("version"))) and HASH_RE.match(str(e.get("hash")))
                and isinstance(e.get("size"), int) and 0 < e["size"] <= ELEMENT_MAX_BYTES):
            raise VerificationFailed(f"feed.json: malformed element entry {str(e)[:120]}")
        if e["uuid"] in signed or e["path"] in paths:
            raise VerificationFailed(f"feed.json: duplicate uuid or path {e['path']}")
        signed[e["uuid"]] = (e["version"], e["hash"], e["size"])
        paths.add(e["path"])

    index_path = out / "index" / f"{channel.replace(':', '~')}.json"
    index = _strict_json(verified_bytes(index_path, load_public(channel_pub, "channel"),
                                        "channel-index"), index_path.name)
    if not isinstance(index, dict) or index.get("index") != 1 or index.get("channel") != channel:
        raise VerificationFailed(f"{index_path.name}: not a version 1 index for {channel}")
    if index.get("library") != feed.get("library"):
        raise VerificationFailed(f"{index_path.name}: belongs to another library")
    version = index.get("version")
    if not isinstance(version, int) or version < max(1, trusted_index_version):
        raise VerificationFailed(f"{index_path.name}: version {version} is older than the "
                                 f"trusted {trusted_index_version} (rollback)")
    try:
        expires = datetime.strptime(str(index.get("expires")), TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        raise VerificationFailed(f"{index_path.name}: bad 'expires'") from None
    if expires <= now:
        raise VerificationFailed(f"{index_path.name}: expired at {index['expires']} (freeze)")
    entries = index.get("elements")
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise VerificationFailed(f"{index_path.name}: 'elements' must be a list of objects")
    for entry in entries:
        uuid = entry.get("uuid")
        if entry.get("status") == "withdrawn":
            if uuid in signed:
                raise VerificationFailed(f"{index_path.name}: withdrawn {uuid} is still in feed")
            continue
        if signed.get(uuid) != (entry.get("version"), entry.get("hash"), entry.get("size")):
            raise VerificationFailed(
                f"{index_path.name}: {uuid} {entry.get('version')} is not in the signed feed (S4)")
    if index.get("snapshot") != _snapshot(entries):
        raise VerificationFailed(f"{index_path.name}: snapshot does not match its entries")

    for e in elements:
        blob = out / "blob" / e["hash"].removeprefix("sha256:")
        try:
            data = read_capped(blob, e["size"])
        except FileNotFoundError:
            raise VerificationFailed(f"blob missing for {e['path']}") from None
        except InputRejected as exc:
            raise VerificationFailed(f"blob for {e['path']}: {exc}") from None
        if len(data) != e["size"] or "sha256:" + hashlib.sha256(data).hexdigest() != e["hash"]:
            raise VerificationFailed(f"blob for {e['path']}: hash mismatch, not parsed")
        try:
            read_element(data)
        except InputRejected as exc:
            raise VerificationFailed(f"blob for {e['path']}: {exc}") from None
    return {"library": feed["library"], "revision": feed.get("revision"), "elements": len(signed),
            "index": channel, "index_version": version, "expires": index["expires"]}
