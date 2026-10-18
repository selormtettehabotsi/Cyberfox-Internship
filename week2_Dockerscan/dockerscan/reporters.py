import json
from collections import Counter

from .models import SEVERITY_ORDER


def summarize(findings):
    counts = Counter(f.severity for f in findings)
    return {s: counts.get(s, 0) for s in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True)}


def to_text(findings, errors, scanned):
    out = []
    current = None
    for f in findings:
        if f.file != current:
            current = f.file
            out.append("")
            out.append(current)
        loc = f.file + (":" + str(f.line) if f.line else "")
        out.append("  [" + f.severity.upper() + "] " + f.rule_id + " " + f.title + "  (" + loc + ")")
        out.append("      Found: " + f.evidence)
        out.append("      Risk:  " + f.risk)
        out.append("      Fix:   " + f.fix)
        out.append("      Ref:   " + f.reference)
    for file, message in errors:
        out.append("")
        out.append("WARNING " + file + ": " + message)
    out.append("")
    counts = summarize(findings)
    parts = [str(n) + " " + s for s, n in counts.items()]
    out.append("Scanned " + str(scanned) + " file(s): " + str(len(findings)) + " finding(s) (" + ", ".join(parts) + ")")
    return "\n".join(out).lstrip("\n")


def to_json(findings, errors, scanned):
    return json.dumps(
        {
            "scanned_files": scanned,
            "summary": summarize(findings),
            "findings": [f.to_dict() for f in findings],
            "errors": [{"file": f, "message": m} for f, m in errors],
        },
        indent=2,
    )
