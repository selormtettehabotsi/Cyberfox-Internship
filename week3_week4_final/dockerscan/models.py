from dataclasses import dataclass, asdict
from typing import Optional

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    applies_to: str  # "dockerfile" or "compose"
    severity: str
    check: str
    params: dict
    risk: str
    fix: str
    reference: str


@dataclass(frozen=True)
class Hit:
    """A raw match produced by a check, before rule metadata is attached."""
    line: Optional[int]
    target: str  # e.g. the service name or instruction
    evidence: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: Optional[int]
    target: str
    evidence: str
    risk: str
    fix: str
    reference: str

    def to_dict(self):
        return asdict(self)
