"""Core data model: one Evidence record per check result."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# Worst first. Used to sort findings in reports.
SEVERITIES = ("critical", "high", "medium", "low")


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
    remediation: str = ""             # how to fix it, set when a check fails
    title: str = ""                   # plain-English name of the check
    severity: str = ""                # critical, high, medium or low
    scope: str = ""                   # e.g. AWS account ID / tenant ID
    region: str = ""                  # e.g. "eu-west-3", or "global" for account-wide checks
    # Set when the accepted risk register matches this result. "state" is
    # "accepted", "expired" or "partial". Empty when nothing matched.
    accepted_risk: dict[str, Any] = field(default_factory=dict)
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data
