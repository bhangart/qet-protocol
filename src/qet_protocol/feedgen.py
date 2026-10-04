# SPDX-License-Identifier: Apache-2.0
"""qet-feedgen: build a library feed from a checkout of an element collection.

Deterministic: two runs over the same commit with the same configuration
produce byte-identical output. Elements are read one at a time and only a
small record of each is kept, so memory stays bounded on the full
collection. No network access anywhere (S1); the only subprocess is `git`,
run locally to read the commit being published.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess  # noqa: S404 - local git only, fixed argument lists
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .catalogue import Catalogues
from .elmt import read_element
from .safety import (
    ELEMENT_MAX_BYTES,
    SECURITY_RULES,
    InputRejected,
    json_depth_ok,
    read_capped,
)

UUID_RE = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$")
LANGUAGE_RE = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$")
LIBRARY_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,126}[a-z0-9])?$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
LICENCE_RE = re.compile(r"^[A-Za-z0-9.+() -]{1,128}$")
MAX_NAME = 1024


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    path: str
    rule: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: [{self.rule}] {self.message}"


# --- configuration -----------------------------------------------------------


def load_config(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from None
    if not isinstance(config, dict):
        raise ConfigError("configuration must be a JSON object")
    if not LIBRARY_RE.match(str(config.get("library", ""))):
        raise ConfigError("'library' must be a namespace identifier")
    if not LANGUAGE_RE.match(str(config.get("sourceLanguage", ""))):
        raise ConfigError("'sourceLanguage' must be a BCP 47 tag")
    if not VERSION_RE.match(str(config.get("initialVersion", ""))):
        raise ConfigError("'initialVersion' must be major.minor.patch")
    days = config.get("expiresDays")
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 90:
        raise ConfigError("'expiresDays' must be an integer from 1 to 90")
    config.setdefault("channel", "stable")
    _check_usage(config.get("usage"))
    for item in config.setdefault("suppress", []):
        if not (isinstance(item, dict) and item.get("path") and item.get("rule")
                and item.get("reason")):
            raise ConfigError("every suppression needs 'path', 'rule' and 'reason'")
        if item["rule"] in SECURITY_RULES:
            raise ConfigError(f"security rule {item['rule']!r} cannot be suppressed")
    return config


def _check_usage(usage: object) -> None:
    """The library-level usage block is mandatory and never defaulted."""
    if not isinstance(usage, dict):
        raise ConfigError("'usage' is required at library level; there is no default")
    if not LICENCE_RE.match(str(usage.get("licence", ""))):
        raise ConfigError("'usage.licence' must be an SPDX licence expression")
    for term in ("train-ai", "ai-use", "search"):
        if usage.get(term) not in ("y", "n"):
            raise ConfigError(f"'usage.{term}' must be 'y' or 'n'; there is no default")
    unknown = set(usage) - {"licence", "train-ai", "ai-use", "search", "policy"}
    if unknown:
        raise ConfigError(f"unknown 'usage' fields: {sorted(unknown)}")


# --- git ---------------------------------------------------------------------


def _git(root: Path, *args: str) -> str:
    git = shutil.which("git")
    if git is None:
        raise ConfigError("git is not installed")
    result = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [git, "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise ConfigError(f"git {' '.join(args)} failed in {root}: {result.stderr.strip()}")
    return result.stdout.strip()


def source_state(root: Path, allow_dirty: bool) -> tuple[str, int]:
    """Commit hash and commit time of a checkout; refuses uncommitted changes."""
    revision = _git(root, "rev-parse", "HEAD")
    if _git(root, "status", "--porcelain") and not allow_dirty:
        raise ConfigError(f"{root} has uncommitted changes; 'revision' would not describe them")
    epoch = os.environ.get("SOURCE_DATE_EPOCH") or _git(root, "log", "-1", "--format=%ct", "HEAD")
    return revision, int(epoch)


# --- walking -----------------------------------------------------------------


def element_paths(root: Path, findings: list[Finding]) -> list[str]:
    """Every .elmt below root, as NFC POSIX paths in a platform-independent order."""
    paths = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        kept = []
        for name in dirnames:
            if name.startswith("."):
                continue
            if (here / name).is_symlink():
                rel = (here / name).relative_to(root).as_posix()
                findings.append(Finding(rel, "symlink", "symbolic link to a directory"))
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            if name.endswith(".elmt") and not name.startswith("."):
                rel = (here / name).relative_to(root).as_posix()
                paths.append(unicodedata.normalize("NFC", rel))
    return sorted(paths, key=lambda p: p.encode("utf-8"))


def _fs_path(root: Path, nfc_path: str) -> Path:
    """Map an NFC path back to the file on disk (macOS may store NFD)."""
    candidate = root / nfc_path
    if os.path.lexists(candidate):
        return candidate
    return root / unicodedata.normalize("NFD", nfc_path)


# --- one element -------------------------------------------------------------


def build_record(rel: str, data: bytes, config: dict, catalogues: Catalogues | None) -> dict:
    """Feed entry for one element. Raises InputRejected for data problems."""
    info = read_element(data)
    uuid = (info.uuid or "").lower()
    if not uuid:
        raise InputRejected("missing-uuid", "no <uuid> in <definition>")
    if not UUID_RE.match(uuid):
        raise InputRejected("bad-uuid", f"malformed UUID {info.uuid!r}")
    names: dict[str, str] = {}
    for lang, text in info.names.items():
        tag = lang.replace("_", "-")
        if not LANGUAGE_RE.match(tag):
            raise InputRejected("bad-language", f"language tag {lang!r}")
        if len(text) > MAX_NAME:
            raise InputRejected("name-too-long", f"{tag} name exceeds {MAX_NAME} characters")
        names[tag] = text
    if not names:
        raise InputRejected("no-names", "no non-empty <name>")
    provenance: dict[str, str] = {}
    source = names.get(config["sourceLanguage"])
    if catalogues is not None and source is not None:
        for lang in catalogues.languages:
            hit = catalogues.lookup(lang, "element", uuid, source)
            if hit is not None:
                names[lang] = hit.text
                provenance[lang] = hit.provenance
    record = {
        "path": rel,
        "uuid": uuid,
        "version": config["initialVersion"],
        "hash": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "names": names,
    }
    if provenance:
        record["nameProvenance"] = provenance
    article = {}
    for key, out, limit in (("manufacturer", "manufacturer", 256),
                            ("manufacturer_reference", "partNumber", 128)):
        value = info.informations.get(key)
        if value:
            if len(value) > limit:
                raise InputRejected("article-too-long", f"{key} exceeds {limit} characters")
            article[out] = value
    if article:
        record["articles"] = [article]
    return record


# --- output ------------------------------------------------------------------


def dump_json(value: object) -> bytes:
    """The one serialisation used for every output file."""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


def snapshot_of(entries: list[dict]) -> str:
    lines = []
    for entry in sorted(entries, key=lambda e: e["uuid"]):
        third = "withdrawn" if entry.get("status") == "withdrawn" else entry["hash"]
        lines.append(f"{entry['uuid']} {entry['version']} {third}\n")
    return "sha256:" + hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def _timestamp(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate(source: Path, config: dict, out: Path, catalogue_dir: Path | None = None,
             allow_dirty: bool = False) -> tuple[list[Finding], dict]:
    """Build the feed into `out`. Returns (findings, summary); writes nothing on error."""
    if out.exists() and any(out.iterdir()):
        raise ConfigError(f"{out} is not empty")
    revision, epoch = source_state(source, allow_dirty)
    catalogues = None
    catalogue_revision = None
    if catalogue_dir is not None:
        catalogue_revision, _ = source_state(catalogue_dir, allow_dirty)
        catalogues = Catalogues.load(catalogue_dir, config["library"], config["sourceLanguage"])

    findings: list[Finding] = []
    suppress = {(s["path"], s["rule"]): s["reason"] for s in config["suppress"]}
    used_suppressions: set[tuple[str, str]] = set()
    records: list[dict] = []
    seen_uuid: dict[str, str] = {}
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".qet-feedgen-", dir=out.parent))
    try:
        (staging / "blob").mkdir()
        for rel in element_paths(source, findings):
            try:
                data = read_capped(_fs_path(source, rel), ELEMENT_MAX_BYTES)
                record = build_record(rel, data, config, catalogues)
                if record["uuid"] in seen_uuid:
                    raise InputRejected(
                        "duplicate-uuid", f"same UUID as {seen_uuid[record['uuid']]}")
            except InputRejected as exc:
                key = (rel, exc.rule)
                if key in suppress and exc.rule not in SECURITY_RULES:
                    used_suppressions.add(key)
                    continue
                findings.append(Finding(rel, exc.rule, exc.message))
                continue
            seen_uuid[record["uuid"]] = rel
            blob = staging / "blob" / record["hash"].removeprefix("sha256:")
            if not blob.exists():
                blob.write_bytes(data)
            records.append(record)
        for key in sorted(set(suppress) - used_suppressions):
            findings.append(Finding(key[0], "stale-suppression",
                                    f"suppressed rule {key[1]!r} no longer fires; remove it"))
        if findings:
            return findings, {}

        feed = {
            "feed": 1,
            "library": config["library"],
            "revision": revision,
            "catalogueRevision": catalogue_revision,
            "sourceLanguage": config["sourceLanguage"],
            "usage": config["usage"],
            "elements": records,
        }
        if config.get("contact"):
            feed["contact"] = config["contact"]
        entries = sorted(({k: r[k] for k in ("uuid", "version", "hash", "size")}
                          for r in records), key=lambda e: e["uuid"])
        index = {
            "index": 1,
            "channel": config["channel"],
            "library": config["library"],
            "version": epoch,
            "updated": _timestamp(epoch),
            "expires": _timestamp(epoch + config["expiresDays"] * 86400),
            "snapshot": snapshot_of(entries),
            "elements": entries,
        }
        assert json_depth_ok(feed) and json_depth_ok(index)
        (staging / "feed.json").write_bytes(dump_json(feed))
        (staging / "index").mkdir()
        (staging / "index" / f"{config['channel'].replace(':', '~')}.json").write_bytes(
            dump_json(index))
        for path in staging.rglob("*"):
            path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
                       | (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH if path.is_dir() else 0))
        if out.exists():
            out.rmdir()
        staging.rename(out)
        staging = None
        summary = {
            "elements": len(records),
            "blobs": sum(1 for _ in (out / "blob").iterdir()),
            "languages": len({lang for r in records for lang in r["names"]}),
            "suppressed": len(used_suppressions),
            "revision": revision,
        }
        return [], summary
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="qet-feedgen", description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path, help="checkout of the element collection")
    parser.add_argument("--config", type=Path, required=True, help="library configuration")
    parser.add_argument("--out", type=Path, required=True, help="output directory (new or empty)")
    parser.add_argument("--catalogues", type=Path, help="directory of translation catalogues")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="accept uncommitted changes in the source (not for publishing)")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        findings, summary = generate(args.source, config, args.out, args.catalogues,
                                     args.allow_dirty)
    except (ConfigError, InputRejected) as exc:
        print(f"qet-feedgen: {exc}", file=sys.stderr)
        return 2
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        print(f"qet-feedgen: {len(findings)} element(s) rejected; nothing written",
              file=sys.stderr)
        return 1
    print("qet-feedgen: " + ", ".join(f"{k} {v}" for k, v in summary.items()), file=sys.stderr)
    return 0
