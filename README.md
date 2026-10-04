# qet-protocol

An open protocol for shared [QElectroTech](https://qelectrotech.org) element
libraries: signed, static, versioned feeds that any static host can serve and
that QElectroTech can verify before it loads a single element.

This repository holds:

| Path | Contents | Licence |
|---|---|---|
| `spec/` | the specification text | CC-BY-4.0 |
| `schemas/` | JSON Schemas for the feed, the channel index, the project pin list and the translation catalogue | Apache-2.0 |
| `src/qet_protocol/` | `qet-feedgen` (feed generator) and `qet-feed` (signing and verification) | Apache-2.0 |
| `tests/` | unit tests, later the conformance suite | Apache-2.0 |

See [LICENSES.md](LICENSES.md) for the exact split.

## Status

Early work in a personal account. Nothing here is endorsed by the
QElectroTech project yet. Keys used anywhere in this repository are **test
keys**.

## Security invariants

Every component in this repository is held to nine invariants (S1–S9). The
two that shape the code most:

- **S1 — No execution, no fetching.** No element, feed, manifest or metadata
  file may cause code to run, a command to execute or a resource to be
  fetched. The generator and the verifier make no network access.
- **S2 — No `<!DOCTYPE`, no entity declarations**, rejected by a byte-level
  check before any parser runs.

## Building and verifying a feed

```sh
# from a committed checkout of qelectrotech-elements
qet-feedgen ../qelectrotech-elements --config examples/qet-official.library.json --out out/

# TEST keys only — real namespace keys are offline (security annex §11.1)
qet-feed keygen --role namespace --dir keys/
qet-feed keygen --role channel   --dir keys/
qet-feed sign out/ --namespace-key keys/namespace.key --channel-key keys/channel.key

qet-feed verify out/ --namespace-pub keys/namespace.pub --channel-pub keys/channel.pub
```

`out/` then holds `feed.json` (signed by the namespace key), `index/stable.json`
(signed by the channel key) and `blob/<sha256>` per element. Generation is
deterministic: the same commit and keys give byte-identical output.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/pytest
```

Contributions require a DCO sign-off; see [CONTRIBUTING.md](CONTRIBUTING.md).
