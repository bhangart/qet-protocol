# SPDX-License-Identifier: Apache-2.0
"""qet-feed: generate test keys, sign a generated feed, verify a signed one."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from .signing import KEY_ROLES, keygen, sign_feed
from .verify import VerificationFailed, verify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qet-feed", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="write a TEST key pair (<role>.key, <role>.pub)")
    p.add_argument("--role", choices=KEY_ROLES, required=True)
    p.add_argument("--dir", type=Path, required=True)

    p = sub.add_parser("sign", help="sign feed.json (namespace key) and indexes (channel key)")
    p.add_argument("feed_dir", type=Path)
    p.add_argument("--namespace-key", type=Path, required=True)
    p.add_argument("--channel-key", type=Path, required=True)

    p = sub.add_parser("verify", help="verify a signed feed directory")
    p.add_argument("feed_dir", type=Path)
    p.add_argument("--namespace-pub", type=Path, required=True)
    p.add_argument("--channel-pub", type=Path, required=True)
    p.add_argument("--channel", default="stable")
    p.add_argument("--trusted-index-version", type=int, default=0,
                   help="refuse an index older than this (rollback protection)")
    p.add_argument("--now", help="check expiry against this UTC time (YYYY-MM-DDTHH:MM:SSZ)")

    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            for path in keygen(args.dir, args.role):
                print(path)
        elif args.command == "sign":
            for path in sign_feed(args.feed_dir, args.namespace_key, args.channel_key):
                print(path)
        else:
            now = (datetime.strptime(args.now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
                   if args.now else None)
            summary = verify(args.feed_dir, args.namespace_pub, args.channel_pub, now,
                             args.trusted_index_version, args.channel)
            print("qet-feed: verified: " + ", ".join(f"{k} {v}" for k, v in summary.items()))
    except VerificationFailed as exc:
        print(f"qet-feed: REJECTED: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"qet-feed: {exc}", file=sys.stderr)
        return 2
    return 0
