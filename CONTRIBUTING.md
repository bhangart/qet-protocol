# Contributing

## Sign-off (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/),
not a contributor licence agreement. You keep your copyright; you certify that
you have the right to submit the change under this repository's licences
(see [LICENSES.md](LICENSES.md)).

Every commit must carry a sign-off line with your real name:

```text
Signed-off-by: Jane Doe <jane@example.org>
```

`git commit -s` adds it.

## Branches and commits

- Branch names: `feat/…`, `fix/…`, `chore/…`, `test/…`, `docs/…`.
- One-line commit messages for small changes. For bigger ones: a summary
  line, a blank line, then a paragraph explaining why.
- One concern per pull request. A refactor and a feature are two pull
  requests.

## Before opening a pull request

```sh
.venv/bin/ruff check .
.venv/bin/pytest
```

Both run in CI on every push.

Every change that reads untrusted input (an element, a feed, an index, a
catalogue) applies the input rules in `src/qet_protocol/safety.py` before
parsing anything, and its pull request says which security invariant it
enforces.

## Keys

Never commit a private key, and never use a real signing key with these
tools during development. `qet-feed keygen` produces **test keys only**.
