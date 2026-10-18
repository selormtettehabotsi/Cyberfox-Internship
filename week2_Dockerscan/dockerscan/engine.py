import os
import re
from pathlib import Path

import yaml

from .checks import COMPOSE_CHECKS, DOCKERFILE_CHECKS, ComposeCtx, DockerfileCtx
from .models import SEVERITY_ORDER, Finding, Rule
from .parsers import ParseError, load_compose, parse_dockerfile

RULES_DIR = Path(__file__).parent / "rules"
MAX_FILE_BYTES = 1_000_000  # refuse very large inputs
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
COMPOSE_NAME = re.compile(r"^(docker-)?compose([.-].+)?\.ya?ml$", re.IGNORECASE)

REGISTRIES = {"dockerfile": DOCKERFILE_CHECKS, "compose": COMPOSE_CHECKS}
REQUIRED = ("id", "title", "severity", "check", "risk", "fix", "reference")


class RuleError(Exception):
    pass


def load_rules(rules_dir=RULES_DIR):
    """Load and validate all YAML rule files in a directory."""
    rules = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        applies_to = path.stem  # dockerfile.yml -> dockerfile, compose.yml -> compose
        if applies_to not in REGISTRIES:
            raise RuleError(path.name + ": unknown rule file type")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for item in data:
            missing = [f for f in REQUIRED if f not in item]
            if missing:
                raise RuleError(path.name + ": rule missing " + ", ".join(missing))
            if item["severity"] not in SEVERITY_ORDER:
                raise RuleError(item["id"] + ": invalid severity " + str(item["severity"]))
            if item["check"] not in REGISTRIES[applies_to]:
                raise RuleError(item["id"] + ": unknown check " + str(item["check"]))
            rules.append(
                Rule(
                    id=item["id"], title=item["title"], applies_to=applies_to,
                    severity=item["severity"], check=item["check"],
                    params=item.get("params") or {}, risk=" ".join(str(item["risk"]).split()),
                    fix=item["fix"], reference=item["reference"],
                )
            )
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise RuleError("duplicate rule IDs")
    return rules


def classify(name):
    low = name.lower()
    if low in ("dockerfile", "containerfile") or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
        return "dockerfile"
    if COMPOSE_NAME.match(name):
        return "compose"
    return None


def discover(path):
    """Yield (file_path, kind) for scannable files under a path. Symlinks are skipped."""
    p = Path(path)
    if p.is_file():
        kind = classify(p.name)
        if kind:
            yield p, kind
        return
    for root, dirs, files in os.walk(p):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            fp = Path(root) / name
            kind = classify(name)
            if kind and not fp.is_symlink():
                yield fp, kind


def scan_file(path, kind, rules):
    """Scan one file. Returns (findings, error_message_or_None)."""
    path = Path(path)
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [], "file larger than " + str(MAX_FILE_BYTES) + " bytes, skipped"
        text = path.read_text(encoding="utf-8", errors="replace")
        if kind == "dockerfile":
            ctx = DockerfileCtx(parse_dockerfile(text))
        else:
            ctx = ComposeCtx(*load_compose(text))
    except ParseError as exc:
        return [], str(exc)
    except OSError as exc:
        return [], "cannot read file: " + exc.strerror

    findings = []
    for rule in rules:
        if rule.applies_to != kind:
            continue
        for hit in REGISTRIES[kind][rule.check](ctx, rule.params):
            findings.append(
                Finding(rule.id, rule.title, rule.severity, str(path), hit.line,
                        hit.target, hit.evidence, rule.risk, rule.fix, rule.reference)
            )
    return findings, None


def scan_path(path, rules):
    """Scan a file or directory. Returns (findings, errors) where errors is a list of (file, message)."""
    findings, errors, scanned = [], [], 0
    for fp, kind in discover(path):
        scanned += 1
        found, err = scan_file(fp, kind, rules)
        findings.extend(found)
        if err:
            errors.append((str(fp), err))
    findings.sort(key=lambda f: (f.file, -SEVERITY_ORDER[f.severity], f.line or 0, f.rule_id))
    return findings, errors, scanned
