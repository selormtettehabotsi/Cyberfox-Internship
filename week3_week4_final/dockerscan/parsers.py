import shlex
from dataclasses import dataclass

import yaml


class ParseError(Exception):
    pass


@dataclass(frozen=True)
class Instruction:
    line: int
    cmd: str
    args: str


def parse_dockerfile(text):
    """Parse a Dockerfile into a list of Instruction objects.

    Handles comments, blank lines and backslash line continuations.
    """
    lines = text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        start = i + 1
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        buf = stripped
        while buf.endswith("\\"):
            buf = buf[:-1].rstrip()
            i += 1
            if i >= len(lines):
                break
            nxt = lines[i].strip()
            if nxt.startswith("#"):
                buf += " \\"  # comment inside a continuation: keep going
                continue
            buf += " " + nxt
        parts = buf.split(None, 1)
        out.append(Instruction(start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        i += 1
    if not out:
        raise ParseError("no instructions found")
    return out


def final_stage(instructions):
    """Return the instructions belonging to the last build stage (from the last FROM)."""
    last_from = max((idx for idx, ins in enumerate(instructions) if ins.cmd == "FROM"), default=0)
    return instructions[last_from:]


def parse_kv(args):
    """Parse ENV/ARG arguments into (key, value) pairs. value is None when absent."""
    args = args.strip()
    if not args:
        return []
    first = args.split(None, 1)[0]
    if "=" in first:
        try:
            tokens = shlex.split(args, posix=True)
        except ValueError:
            tokens = args.split()
        pairs = []
        for tok in tokens:
            k, sep, v = tok.partition("=")
            pairs.append((k, v if sep else None))
        return pairs
    parts = args.split(None, 1)
    return [(parts[0], parts[1] if len(parts) > 1 else None)]


def load_compose(text):
    """Parse a compose file safely. Returns (data, line_map).

    line_map maps key paths such as ("services", "web", "privileged") to line numbers.
    """
    try:
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ParseError("invalid YAML: " + str(exc).splitlines()[0]) from exc
    if not isinstance(data, dict):
        raise ParseError("compose file must be a YAML mapping")
    lines = {}

    def walk(n, path):
        if isinstance(n, yaml.MappingNode):
            for k, v in n.value:
                p = path + (getattr(k, "value", None),)
                lines[p] = k.start_mark.line + 1
                walk(v, p)
        elif isinstance(n, yaml.SequenceNode):
            for idx, item in enumerate(n.value):
                p = path + (idx,)
                lines[p] = item.start_mark.line + 1
                walk(item, p)

    walk(node, ())
    return data, lines
