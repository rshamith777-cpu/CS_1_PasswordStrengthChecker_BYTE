"""Command-line interface for SentinelPass."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .analyzer import analyze_password, load_policy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelpass",
        description="Local-first, explainable password strength assessment.",
    )
    parser.add_argument("--policy", help="Path to a custom policy JSON file.")
    parser.add_argument("--json", dest="json_output", help="Write the report to this JSON file.")
    parser.add_argument("--show-checks", action="store_true", help="Print every rule result.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Policy error: {exc}", file=sys.stderr)
        return 2

    try:
        password = getpass.getpass("Password (input hidden): ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 130

    report = analyze_password(password, policy)
    # Do not include the password or a password hash in the report.
    if args.json_output:
        try:
            Path(args.json_output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)
            return 2

    print("\nSENTINELPASS | SECURITY ASSESSMENT")
    print("─" * 38)
    print(f"Category             : {report['category']}")
    print(f"Heuristic score      : {report['score']}/100")
    print(f"Length               : {report['length']} characters")
    print(f"Entropy estimate     : {report['estimated_entropy_bits']} bits (assumptions apply)")
    print("\nFindings")
    for finding in report["findings"]:
        print(f"  • {finding}")
    if args.show_checks:
        print("\nRule checks")
        for key, passed in report["checks"].items():
            print(f"  {'PASS' if passed else 'FAIL'}  {key}")
    print("\nRecommendations")
    for recommendation in report["recommendations"]:
        print(f"  • {recommendation}")
    print(f"\nNote: {report['disclaimer']}")
    if args.json_output:
        print(f"\nJSON report saved to: {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
