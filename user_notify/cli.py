"""Run a notification for one incident from the command line.

python -m user_notify --incident 2101 --profile atypical_travel --dry-run
"""

from __future__ import annotations

import argparse
import logging
import os
from datetime import timedelta

from .config import ariel_from_env, servicenow_from_env, soar_from_env, target_from_env
from .notify import notify_user
from .profiles import PROFILES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="user_notify",
        description="Notify the affected user of an identity alert via ServiceNow",
    )
    parser.add_argument("--incident", type=int, required=True, help="SOAR incident ID")
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument(
        "--window-minutes", type=int, default=10, help="AQL window around the discovery time"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="collect and render, but do not write anything"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    result = notify_user(
        args.incident,
        PROFILES[args.profile],
        soar=soar_from_env(),
        ariel=ariel_from_env(),
        servicenow=None if args.dry_run else servicenow_from_env(),
        target=target_from_env(),
        recipient_property=os.environ.get("SOAR_RECIPIENT_PROPERTY", "qradar_user_email"),
        window=timedelta(minutes=args.window_minutes),
        dry_run=args.dry_run,
    )
    print(f"Recipient: {result.recipient}\nNew artifacts: {result.artifacts_added}")
    if args.dry_run:
        print(result.body)
    else:
        print(f"ServiceNow record: {result.record.get('number') or result.record.get('sys_id')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
