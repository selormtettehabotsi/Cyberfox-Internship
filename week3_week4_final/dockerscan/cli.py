import argparse
import sys

from . import __version__
from .engine import RuleError, load_rules, scan_path
from .models import SEVERITY_ORDER
from .reporters import to_html, to_json, to_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="dockerscan",
        description="Static security scanner for Dockerfiles and docker-compose files.",
    )
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("--format", choices=["text", "json", "html"], default="text", help="output format (default: text)")
    p.add_argument("-o", "--output", help="write the report to this file instead of printing it")
    p.add_argument(
        "--min-severity", choices=list(SEVERITY_ORDER), default="low",
        help="hide findings below this severity (default: low, show everything)",
    )
    p.add_argument(
        "--fail-on", choices=list(SEVERITY_ORDER) + ["never"], default="high",
        help="exit with status 1 if a finding at or above this severity exists (default: high)",
    )
    p.add_argument("--version", action="version", version="dockerscan " + __version__)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules()
    except RuleError as exc:
        print("rule error: " + str(exc), file=sys.stderr)
        return 2
    findings, errors, scanned = scan_path(args.path, rules)
    if scanned == 0:
        print("no Dockerfiles or compose files found in " + args.path, file=sys.stderr)
        return 2
    floor = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= floor]
    render = {"json": to_json, "html": to_html}.get(args.format, to_text)
    report = render(findings, errors, scanned)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0
