"""Check implementations. Each check takes (ctx, params) and returns a list of Hit.

Rules in rules/*.yml choose a check by name and supply parameters, so adding a
rule that reuses an existing check needs no Python code.
"""
import re

from .models import Hit
from .parsers import final_stage, parse_kv

SECRET_NAME = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)", re.IGNORECASE
)
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}


# ---------------------------------------------------------------- helpers
SECRET_FILE_PREFIXES = ("/run/secrets/", "/var/run/secrets/", "file://")


def _is_secret_literal(key, value):
    """True when key looks like a secret name and the value is a hardcoded literal.

    Keys ending in _FILE and values that point to a secret file (for example
    /run/secrets/db-password) are the recommended pattern, so they are not flagged.
    """
    key = str(key)
    if not SECRET_NAME.search(key) or key.upper().endswith("_FILE"):
        return False
    if not _is_literal(value):
        return False
    return not str(value).strip().strip("\"'").startswith(SECRET_FILE_PREFIXES)


def _is_literal(value):
    """True for a hardcoded value, False for empty values or variable references."""
    if value is None:
        return False
    v = str(value).strip().strip("\"'")
    return bool(v) and not v.startswith("$")


def _image_is_unpinned(image, known_stages=()):
    """Return True when an image reference has no tag, or uses the latest tag."""
    image = str(image).strip()
    if not image or "$" in image or image.lower() == "scratch" or image in known_stages:
        return False
    if "@sha256:" in image:
        return False
    last_segment = image.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return True
    return last_segment.split(":", 1)[1].lower() == "latest"


class DockerfileCtx:
    def __init__(self, instructions):
        self.instructions = instructions
        self.final = final_stage(instructions)


class ComposeCtx:
    def __init__(self, data, lines):
        self.data = data
        self.lines = lines
        services = data.get("services") or {}
        self.services = {k: v for k, v in services.items() if isinstance(v, dict)}

    def line(self, service, key=None):
        return self.lines.get(("services", service, key)) or self.lines.get(("services", service))


# ------------------------------------------------------- Dockerfile checks
def no_nonroot_user(ctx, params):
    users = [i for i in ctx.final if i.cmd == "USER"]
    first = ctx.final[0]
    if not users:
        return [Hit(first.line, "final stage", "no USER instruction, container runs as root")]
    last = users[-1]
    name = last.args.split(":", 1)[0].strip().lower()
    if name in ("root", "0"):
        return [Hit(last.line, "USER", "last USER instruction is " + last.args.strip())]
    return []


def missing_instruction(ctx, params):
    want = params["instruction"].upper()
    present = [i for i in ctx.final if i.cmd == want and i.args.strip().upper() != "NONE"]
    if present:
        return []
    return [Hit(ctx.final[0].line, "final stage", "no " + want + " instruction")]


def unpinned_base_image(ctx, params):
    hits, stages = [], set()
    for ins in ctx.instructions:
        if ins.cmd != "FROM":
            continue
        tokens = [t for t in ins.args.split() if not t.startswith("--")]
        if not tokens:
            continue
        image = tokens[0]
        if _image_is_unpinned(image, stages):
            hits.append(Hit(ins.line, "FROM", "base image '" + image + "' is not pinned to a version"))
        if len(tokens) >= 3 and tokens[1].upper() == "AS":
            stages.add(tokens[2])
    return hits


def secret_assignment_dockerfile(ctx, params):
    wanted = {c.upper() for c in params.get("instructions", ["ENV", "ARG"])}
    hits = []
    for ins in ctx.instructions:
        if ins.cmd not in wanted:
            continue
        for key, value in parse_kv(ins.args):
            if _is_secret_literal(key, value):
                hits.append(Hit(ins.line, ins.cmd + " " + key, "hardcoded value assigned to '" + key + "'"))
    return hits


def regex_instruction(ctx, params):
    wanted = {c.upper() for c in params["instructions"]}
    pattern = re.compile(params["pattern"], re.IGNORECASE)
    return [
        Hit(i.line, i.cmd, i.cmd + " " + i.args[:80])
        for i in ctx.instructions
        if i.cmd in wanted and pattern.search(i.args)
    ]


# ---------------------------------------------------------- Compose checks
def key_equals(ctx, params):
    key, expected = params["key"], params["value"]
    hits = []
    for name, svc in ctx.services.items():
        actual = svc.get(key)
        if isinstance(expected, bool):
            ok = actual is expected or str(actual).lower() == str(expected).lower()
        else:
            ok = str(actual).lower() == str(expected).lower()
        if actual is not None and ok:
            hits.append(Hit(ctx.line(name, key), name, key + ": " + str(actual)))
    return hits


def list_contains_any(ctx, params):
    key = params["key"]
    bad = {str(v).upper() for v in params["values"]}
    hits = []
    for name, svc in ctx.services.items():
        values = svc.get(key) or []
        if not isinstance(values, list):
            continue
        found = sorted(str(v).upper() for v in values if str(v).upper() in bad)
        if found:
            hits.append(Hit(ctx.line(name, key), name, key + " includes " + ", ".join(found)))
    return hits


def _volume_source(entry):
    if isinstance(entry, dict):
        return str(entry.get("source", ""))
    return str(entry).split(":", 1)[0]


def volume_source_matches(ctx, params):
    pattern = re.compile(params["pattern"])
    hits = []
    for name, svc in ctx.services.items():
        for entry in svc.get("volumes") or []:
            if pattern.search(_volume_source(entry)):
                hits.append(Hit(ctx.line(name, "volumes"), name, "volume source " + _volume_source(entry)))
    return hits


def _env_items(env):
    if isinstance(env, dict):
        return list(env.items())
    if isinstance(env, list):
        out = []
        for item in env:
            k, sep, v = str(item).partition("=")
            out.append((k, v if sep else None))
        return out
    return []


def secret_assignment_compose(ctx, params):
    hits = []
    for name, svc in ctx.services.items():
        for key, value in _env_items(svc.get("environment")):
            if _is_secret_literal(key, value):
                hits.append(Hit(ctx.line(name, "environment"), name, "hardcoded value for '" + str(key) + "'"))
    return hits


def _parse_port(entry):
    """Return (host_ip, published, target) for a compose port entry."""
    if isinstance(entry, dict):
        return entry.get("host_ip"), entry.get("published"), entry.get("target")
    s = str(entry).split("/")[0]
    host_ip = None
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            return None, None, None
        host_ip, s = s[1:end], s[end + 2:]
        parts = s.split(":")
    else:
        parts = s.split(":")
        if len(parts) == 3:
            host_ip, parts = parts[0], parts[1:]
    if len(parts) == 2:
        return host_ip, parts[0], parts[1]
    return host_ip, None, parts[0]


def _to_int(value):
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def published_ports_exposed(ctx, params):
    sensitive = set(params["ports"])
    hits = []
    for name, svc in ctx.services.items():
        for entry in svc.get("ports") or []:
            host_ip, published, target = _parse_port(entry)
            if published is None:
                continue  # not published to the host
            if str(host_ip or "").lower() in LOCAL_HOSTS:
                continue
            if _to_int(published) in sensitive or _to_int(target) in sensitive:
                where = host_ip or "all interfaces"
                hits.append(Hit(ctx.line(name, "ports"), name, "port " + str(entry) + " published on " + where))
    return hits


def key_missing(ctx, params):
    key = params["key"]
    return [
        Hit(ctx.line(name), name, "service has no '" + key + "' setting")
        for name, svc in ctx.services.items()
        if not svc.get(key)
    ]


def list_missing_value(ctx, params):
    key, wanted = params["key"], params["value"].lower()
    hits = []
    for name, svc in ctx.services.items():
        values = [str(v).lower().replace("=", ":") for v in (svc.get(key) or [])]
        ok = any(v == wanted + ":true" or v == wanted for v in values)
        if not ok:
            hits.append(Hit(ctx.line(name, key), name, key + " does not include " + params["value"]))
    return hits


def image_unpinned(ctx, params):
    hits = []
    for name, svc in ctx.services.items():
        image = svc.get("image")
        if image and _image_is_unpinned(image):
            hits.append(Hit(ctx.line(name, "image"), name, "image '" + str(image) + "' is not pinned to a version"))
    return hits


DOCKERFILE_CHECKS = {
    "no_nonroot_user": no_nonroot_user,
    "missing_instruction": missing_instruction,
    "unpinned_base_image": unpinned_base_image,
    "secret_assignment": secret_assignment_dockerfile,
    "regex_instruction": regex_instruction,
}

COMPOSE_CHECKS = {
    "key_equals": key_equals,
    "list_contains_any": list_contains_any,
    "volume_source_matches": volume_source_matches,
    "secret_assignment": secret_assignment_compose,
    "published_ports_exposed": published_ports_exposed,
    "key_missing": key_missing,
    "list_missing_value": list_missing_value,
    "image_unpinned": image_unpinned,
}
