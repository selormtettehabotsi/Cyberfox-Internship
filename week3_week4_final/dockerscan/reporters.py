import html
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


_COLORS = {"critical": "#8b0000", "high": "#c0392b", "medium": "#b9770e", "low": "#2e6da4"}


def to_html(findings, errors, scanned):
    """Self-contained HTML report. Every dynamic value is escaped; the page has no scripts."""
    e = html.escape
    counts = summarize(findings)
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>dockerscan report</title>",
        "<style>body{font-family:Arial,sans-serif;margin:24px;color:#222;max-width:960px}"
        "h1{color:#1f3864}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #ccc;padding-bottom:4px;word-break:break-all}"
        ".sum span{display:inline-block;margin-right:12px;padding:4px 10px;border-radius:4px;color:#fff;font-size:13px}"
        ".f{border:1px solid #ddd;border-radius:6px;padding:10px 14px;margin:10px 0}"
        ".b{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold}"
        ".m{color:#555;font-size:13px}dt{font-weight:bold;float:left;width:60px}dd{margin:0 0 4px 70px}"
        ".w{background:#fff3cd;border:1px solid #e0c36a;padding:8px;border-radius:4px}</style>",
        "</head><body>",
        "<h1>dockerscan report</h1>",
        "<p>Scanned " + str(scanned) + " file(s), " + str(len(findings)) + " finding(s).</p>",
        '<p class="sum">'
        + "".join(
            '<span style="background:' + _COLORS[s] + '">' + e(s.capitalize()) + ": " + str(n) + "</span>"
            for s, n in counts.items()
        )
        + "</p>",
    ]
    current = None
    for f in findings:
        if f.file != current:
            current = f.file
            parts.append("<h2>" + e(f.file) + "</h2>")
        loc = "line " + str(f.line) if f.line else "file level"
        parts.append(
            '<div class="f"><span class="b" style="background:' + _COLORS[f.severity] + '">' + e(f.severity.upper())
            + "</span> <strong>" + e(f.rule_id) + " " + e(f.title) + '</strong> <span class="m">(' + e(loc) + ", "
            + e(f.target) + ")</span><dl>"
            + "<dt>Found</dt><dd>" + e(f.evidence) + "</dd>"
            + "<dt>Risk</dt><dd>" + e(f.risk) + "</dd>"
            + "<dt>Fix</dt><dd>" + e(f.fix) + "</dd>"
            + "<dt>Ref</dt><dd>" + e(f.reference) + "</dd></dl></div>"
        )
    for file, message in errors:
        parts.append('<p class="w">Warning: ' + e(file) + ": " + e(message) + "</p>")
    parts.append("</body></html>")
    return "\n".join(parts)
