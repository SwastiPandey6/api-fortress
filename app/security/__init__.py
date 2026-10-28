"""Security controls applied by the gateway to live requests."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Violation:
    """A single rule violation found while evaluating a request.

    `mandatory` violations are blocked in every mode (e.g. authentication
    failures). Non-mandatory violations are blocked only in Enforce mode.
    """

    rule_id: str
    name: str
    reason: str
    status_code: int
    severity: int  # 0 info .. 4 critical
    category: str
    mandatory: bool = False
    headers: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "reason": self.reason,
            "severity": self.severity,
            "category": self.category,
            "mandatory": self.mandatory,
        }
