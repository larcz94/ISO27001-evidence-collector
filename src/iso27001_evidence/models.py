"""Core data model: one Evidence record per check result."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"            # control requirement met
    FAIL = "FAIL"            # gap found
    INFO = "INFO"            # informational evidence, no pass/fail judgement
    NOT_APPLICABLE = "N/A"   # service not in use / nothing to check
    ERROR = "ERROR"          # check could not run (permissions, API error)


@dataclass
class Evidence:
    check_id: str                     # e.g. "aws.iam.root_mfa"
    source: str                       # e.g. "aws"
    status: Status
    summary: str                      # one human-readable line for the auditor
    details: dict[str, Any] = field(default_factory=dict)
    scope: str = ""                   # e.g. AWS account ID / tenant ID
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data
