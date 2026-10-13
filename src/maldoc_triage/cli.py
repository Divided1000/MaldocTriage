"""Command-line interface for MaldocTriage."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .engine import scan_paths
from .models import Report, band_rank
from .report import render_json, render_text

# Exit codes (see README).
EXIT_CLEAN = 0
EXIT_MEDIUM = 1
EXIT_HIGH = 2
EXIT_USAGE = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="maldoc-triage",
        description=(
            "Static-only triage for suspicious documents (OOXML, OLE, PDF, RTF). "
            "Reads and parses files; never executes macros or payloads."
        ),
    )
    parser.add_argument("paths", nargs="*", help="Files or directories to triage.")
    parser.add_argument(
        "-r", "--recursive", action="store_true",
        help="Recurse into directories.",
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="Emit machine-readable JSON instead of text.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show finding details, evidence, and info-level findings.",
    )
    parser.add_argument(
        "--min-severity",
        choices=["clean", "low", "medium", "high", "critical"],
        default="clean",
        help="Only report files at or above this risk band.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    return parser


def _exit_code(reports: List[Report]) -> int:
    worst = 0
    for r in reports:
        worst = max(worst, band_rank(r.risk))
    if worst >= band_rank("high"):
        return EXIT_HIGH
    if worst >= band_rank("medium"):
        return EXIT_MEDIUM
    return EXIT_CLEAN


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.paths:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    reports = scan_paths(args.paths, recursive=args.recursive)

    if not reports:
        print("No files to scan.", file=sys.stderr)
        return EXIT_USAGE

    threshold = band_rank(args.min_severity)
    filtered = [r for r in reports if band_rank(r.risk) >= threshold]

    if args.as_json:
        print(render_json(filtered))
    else:
        if not filtered:
            print(
                f"No files at or above '{args.min_severity}' risk "
                f"({len(reports)} scanned).",
                file=sys.stderr,
            )
        else:
            print(render_text(filtered, stream=sys.stdout, verbose=args.verbose))

    # Exit code reflects the worst result across ALL scanned files, not just
    # the filtered view, so CI gates stay honest.
    return _exit_code(reports)


if __name__ == "__main__":
    raise SystemExit(main())
