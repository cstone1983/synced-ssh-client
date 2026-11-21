"""Admin CLI.  `sshsync enroll-code`  or  `python -m app.cli enroll-code`."""

from __future__ import annotations

import argparse

from .config import Settings
from .db import Database
from .main import print_enrollment_code
from .security import create_enrollment_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sshsync", description="sshsync server admin")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("enroll-code", help="create and print a one-time enrollment code")
    parser.parse_args(argv)

    settings = Settings.from_env()
    db = Database(settings.db_path)
    try:
        with db.tx() as s:
            code, _ = create_enrollment_code(s, settings.code_ttl_seconds)
    finally:
        db.close()
    print_enrollment_code(code, settings.code_ttl_seconds, "New enrollment code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
