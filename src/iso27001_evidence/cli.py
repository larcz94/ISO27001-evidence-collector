"""Command-line entry point.

    iso27001-evidence collect --source aws --region eu-central-1
    iso27001-evidence collect --source lightsail --region eu-central-1
    iso27001-evidence list-checks --source aws
"""

from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .collectors import AVAILABLE, get_collector
from .models import Status
from .report import load_mapping, write_reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iso27001-evidence",
                                     description="ISO 27001 Annex A evidence collector")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="Run checks and write an evidence report")
    c.add_argument("--source", choices=AVAILABLE, default="aws")
    c.add_argument("--region", help="AWS region (default: from your AWS config)")
    c.add_argument("--mapping", help="Custom mapping YAML (default: built-in Annex A mapping)")
    c.add_argument("--out", default="reports")
    c.add_argument("--fail-on-gap", action="store_true",
                   help="Exit with code 1 if any check FAILs (useful in CI)")
    c.add_argument("-v", "--verbose", action="store_true")

    ls = sub.add_parser("list-checks", help="List available checks")
    ls.add_argument("--source", choices=AVAILABLE, default="aws")
    ls.add_argument("--region")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if getattr(args, "verbose", False) else logging.WARNING,
                        format="%(levelname)s %(message)s")

    kwargs = {"region": args.region} if args.source in ("aws", "lightsail") else {}
    collector = get_collector(args.source, **kwargs)

    if args.command == "list-checks":
        for check_id in sorted(collector.checks()):
            print(check_id)
        return 0

    evidence = collector.run()
    paths = write_reports(evidence, load_mapping(args.mapping), args.out)
    for e in evidence:
        print(f"{e.status.value:<5} {e.check_id:<40} {e.summary}")
    print(f"\nReport: {paths['markdown']}\nJSON:   {paths['json']}")

    if args.fail_on_gap and any(e.status == Status.FAIL for e in evidence):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
