# SPDX-License-Identifier: Apache-2.0
import json
import os
import shutil
import subprocess  # noqa: S404
from pathlib import Path

import pytest

GIT = shutil.which("git")

ELEMENT = """<definition version="0.100.0" type="element" width="20" height="20" hotspot_x="10" \
hotspot_y="10" link_type="simple">
    <uuid uuid="{uuid}"/>
    <names>
        <name lang="fr">{fr}</name>
        <name lang="en">{en}</name>
        <name lang="pt_BR">{en} BR</name>
    </names>
    <elementInformations>
        <elementInformation show="1" name="manufacturer">ACME</elementInformation>
        <elementInformation show="1" name="manufacturer_reference">X-1</elementInformation>
    </elementInformations>
    <description>
        <line x1="0" y1="0" x2="10" y2="10" end1="none" end2="none" length1="1.5" length2="1.5"/>
        <terminal x="0" y="0" orientation="n" type="Generic"
                  uuid="{{00000000-0000-4000-8000-0000000000aa}}"/>
    </description>
</definition>
"""


def element(uuid: str, fr: str = "Contacteur", en: str = "Contactor") -> bytes:
    return ELEMENT.format(uuid=uuid, fr=fr, en=en).encode("utf-8")


def uuid_n(n: int) -> str:
    return f"{{00000000-0000-4000-8000-{n:012d}}}"


def git(root: Path, *args: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
           "GIT_AUTHOR_DATE": "2026-10-01T12:00:00Z", "GIT_COMMITTER_DATE": "2026-10-01T12:00:00Z"}
    subprocess.run([GIT, "-C", str(root), *args], check=True, capture_output=True, env=env)  # noqa: S603


def commit_all(root: Path) -> None:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fixture")


@pytest.fixture
def collection(tmp_path: Path) -> Path:
    """A three-element collection in a committed git repository."""
    root = tmp_path / "elements"
    (root / "10_electric" / "a").mkdir(parents=True)
    (root / "10_electric" / "a" / "one.elmt").write_bytes(element(uuid_n(1)))
    (root / "10_electric" / "a" / "two.elmt").write_bytes(element(uuid_n(2), "Bobine", "Coil"))
    (root / "10_electric" / "débimètre.elmt").write_bytes(element(uuid_n(3), "Débit", "Flow"))
    (root / "10_electric" / "qet_directory").write_text("<qet-directory/>")
    git(root, "init", "-q")
    commit_all(root)
    return root


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "library.json"
    path.write_text(json.dumps({
        "library": "qet-test", "sourceLanguage": "en", "initialVersion": "1.0.0",
        "expiresDays": 7,
        "usage": {"licence": "CC-BY-3.0", "train-ai": "n", "ai-use": "y", "search": "y"},
        "suppress": [],
    }))
    return path
