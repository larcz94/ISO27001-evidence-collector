"""Command-line entry point.

    iso27001-evidence collect --source aws --region eu-central-1
    iso27001-evidence collect --source lightsail --region eu-west-3 eu-central-1
    iso27001-evidence collect --source lightsail --all-regions
    iso27001-evidence collect --source all --region eu-central-1
    iso27001-evidence list-checks --source aws
"""

from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .collectors import AVAILABLE, collector_class, get_collector
from .models import Evidence, Status
from .report import load_mapping, write_reports


def _add_region_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--region", nargs="+", metavar="REGION",
                       help="One or more AWS regions (default: from your AWS config)")
    group.add_argument("--all-regions", action="store_true",
                       help="Check every region the service is available in")


def _split_regions(values: list[str] | None) -> list[str]:
    """Accept both '--region a b' and '--region a,b'. Keep order, drop repeats."""
    regions: list[str] = []
    for value in values or []:
        for region in value.split(","):
            region = region.strip()
            if region and region not in regions:
                regions.append(region)
    return regions


def _all_regions(source: str) -> list[str]:
    """Ask AWS for the region list, or stop with a message a user can act on."""
    try:
        return collector_class(source).available_regions()
    except Exception as exc:  # noqa: BLE001 - any failure here means we cannot continue
        raise SystemExit(
            f"Could not list the regions for '{source}': {type(exc).__name__}: {exc}\n"
            f"--all-regions needs the lightsail:GetRegions or ec2:DescribeRegions "
            f"permission. Update the role from the files in policies/, or name the "
            f"regions yourself with --region."
        ) from exc


def collect(sources: list[str], regions: list[str], all_regions: bool) -> list[Evidence]:
    """Run every source in every requested region and return all evidence.

    Account-wide checks (for example IAM) run only in the first region of a
    source, so they appear once in the report.
    """
    evidence: list[Evidence] = []
    for source in sources:
        targets: list[str | None] = _all_regions(source) if all_regions else list(regions)
        if not targets:
            targets = [None]   # let boto3 pick the default region
        scope = None
        for index, region in enumerate(targets):
            if len(targets) > 1:
                print(f"Checking {source} in {region} ({index + 1}/{len(targets)})",
                      file=sys.stderr)
            collector = get_collector(source, region=region, scope=scope)
            scope = collector.scope   # look the account ID up once per source
            evidence += collector.run(include_global=index == 0)
    return evidence


def _print_results(evidence: list[Evidence]) -> None:
    regions = {e.region for e in evidence if e.region and e.region != "global"}
    if len(regions) <= 1:
        for e in evidence:
            print(f"{e.status.value:<5} {e.check_id:<42} {e.summary}")
        return
    # Many regions: most results are "nothing here", so only show the rest.
    width = max(len(r) for r in regions | {"global"})
    skipped = 0
    for e in evidence:
        if e.status == Status.NOT_APPLICABLE:
            skipped += 1
            continue
        print(f"{e.status.value:<5} {e.region:<{width}} {e.check_id:<42} {e.summary}")
    if skipped:
        print(f"\n{skipped} N/A result(s) not shown: nothing to check there. "
              f"The report lists them per region.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iso27001-evidence",
                                     description="ISO 27001 Annex A evidence collector")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="Run checks and write an evidence report")
    c.add_argument("--source", choices=[*AVAILABLE, "all"], default="aws",
                   help="System to check, or 'all' for one combined report")
    _add_region_args(c)
    c.add_argument("--mapping", help="Custom mapping YAML (default: built-in Annex A mapping)")
    c.add_argument("--out", default="reports")
    c.add_argument("--fail-on-gap", action="store_true",
                   help="Exit with code 1 if any check FAILs (useful in CI)")
    c.add_argument("-v", "--verbose", action="store_true")

    ls = sub.add_parser("list-checks", help="List available checks (needs no credentials)")
    ls.add_argument("--source", choices=[*AVAILABLE, "all"], default="aws")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if getattr(args, "verbose", False) else logging.WARNING,
                        format="%(levelname)s %(message)s")

    sources = AVAILABLE if args.source == "all" else [args.source]

    if args.command == "list-checks":
        for check_id in sorted(cid for s in sources for cid in collector_class(s).check_ids()):
            print(check_id)
        return 0

    evidence = collect(sources, _split_regions(args.region), args.all_regions)
    paths = write_reports(evidence, load_mapping(args.mapping), args.out)
    _print_results(evidence)
    failed = sum(e.status == Status.FAIL for e in evidence)
    if failed:
        print(f"\n{failed} finding(s) to fix. The report lists the affected resources "
              f"and how to fix each one.")
    print(f"\nMarkdown: {paths['markdown']}\nHTML:     {paths['html']}"
          f"\nJSON:     {paths['json']}")

    if args.fail_on_gap and failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
