import argparse
import sys

from . import __version__
from .engine import RuleError, load_rules, scan_path
from .models import SEVERITY_ORDER
from .reporters import to_json, to_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="dockerscan",
        description="Static security scanner for Dockerfiles and docker-compose files.",
    )
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("--format", choices=["text", "json"], default="text", help="output format (default: text)")
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
    render = to_json if args.format == "json" else to_text
    print(render(findings, errors, scanned))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0
