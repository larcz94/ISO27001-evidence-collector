"""Accepted risk register: findings the organization has decided to accept.

ISO 27001 does not ask for zero findings. It asks that every risk is either
treated or accepted on purpose (clause 6.1.3, risk treatment). This module
reads a small YAML file of accepted findings and marks the matching results.

An accepted finding keeps its FAIL status, because the gap is real. It is only
moved out of "Findings to fix" and shown with the reason, the approver and the
expiry date, which is the evidence an auditor asks for.

Example file:

    accepted_risks:
      - check: lightsail.instance.auto_snapshots
        region: eu-west-3              # optional, default: any region
        resources: [test-instance]     # optional, default: every resource
        reason: Test instance, no data worth backing up.
        approved_by: Jane Doe (ISMS lead)
        expires: 2027-05-31            # last day the acceptance is valid
        ticket: RISK-42                # optional reference
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from .models import Evidence, Status

REQUIRED = ("check", "reason", "approved_by", "expires")
OPTIONAL = ("region", "resources", "ticket")

# Values of Evidence.accepted_risk["state"].
ACCEPTED = "accepted"   # active acceptance covers every affected resource
EXPIRED = "expired"     # matched, but the expiry date has passed
PARTIAL = "partial"     # active, but some affected resources are not named in it


class AcceptedRiskError(ValueError):
    """The register file cannot be used. The message says what to fix."""


@dataclass
class AcceptedRisk:
    check: str
    reason: str
    approved_by: str
    expires: date
    region: str = ""
    resources: list[str] = field(default_factory=list)
    ticket: str = ""
    used: bool = False   # set when the entry matched at least one result

    def label(self) -> str:
        where = f" in {self.region}" if self.region else ""
        return f"{self.check}{where}"


def _parse_date(value: object, where: str) -> date:
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise AcceptedRiskError(
            f"{where}: 'expires' must be a date like 2027-05-31, got {value!r}") from exc


def load_accepted_risks(path: str | Path, known_checks: Iterable[str]) -> list[AcceptedRisk]:
    """Read and validate the register. Every problem stops the run.

    A typo that silently matched nothing would leave a real finding visible,
    or worse, look like it was accepted when it was not. So unknown keys,
    unknown check IDs and missing fields are errors, not warnings.
    """
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise AcceptedRiskError(f"Cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise AcceptedRiskError(f"{path} is not valid YAML: {exc}") from exc

    entries = data.get("accepted_risks") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise AcceptedRiskError(f"{path} must have a top-level list named 'accepted_risks'.")

    known = set(known_checks)
    risks = []
    for number, entry in enumerate(entries, 1):
        where = f"{path}, entry {number}"
        if not isinstance(entry, dict):
            raise AcceptedRiskError(f"{where}: each entry must be a mapping of fields.")
        unknown = set(entry) - set(REQUIRED) - set(OPTIONAL)
        if unknown:
            raise AcceptedRiskError(f"{where}: unknown field(s) {', '.join(sorted(unknown))}. "
                                    f"Allowed: {', '.join(REQUIRED + OPTIONAL)}.")
        missing = [k for k in REQUIRED if not str(entry.get(k) or "").strip()]
        if missing:
            raise AcceptedRiskError(f"{where}: missing {', '.join(missing)}.")
        check = str(entry["check"]).strip()
        if check not in known:
            raise AcceptedRiskError(f"{where}: unknown check '{check}'. "
                                    f"Run 'iso27001-evidence list-checks --source all'.")
        resources = entry.get("resources") or []
        if isinstance(resources, str):
            resources = [resources]
        if not isinstance(resources, list):
            raise AcceptedRiskError(f"{where}: 'resources' must be a list of names.")
        risks.append(AcceptedRisk(
            check=check,
            reason=str(entry["reason"]).strip(),
            approved_by=str(entry["approved_by"]).strip(),
            expires=_parse_date(entry["expires"], where),
            region=str(entry.get("region") or "").strip(),
            resources=[str(r).strip() for r in resources if str(r).strip()],
            ticket=str(entry.get("ticket") or "").strip(),
        ))
    return risks


def _affected_items(details: dict) -> list[set[str]]:
    """Each affected resource as the set of names that identify it.

    {"exposed_admin_ports": [{"instance": "web-1", "port": 22}]} gives
    [{"web-1", "22"}], so naming "web-1" in the register covers that item.
    """
    items = []
    for value in details.values():
        if not isinstance(value, list):
            continue
        for item in value:
            if isinstance(item, dict):
                items.append({str(v) for v in item.values() if not isinstance(v, (list, dict))})
            else:
                items.append({str(item)})
    return items


def apply_accepted_risks(evidence: list[Evidence], risks: list[AcceptedRisk],
                         today: date | None = None) -> None:
    """Mark failed results that an entry in the register covers.

    The first matching entry wins. Sets Evidence.accepted_risk and the "used"
    flag on each entry that matched something.
    """
    today = today or date.today()
    for e in evidence:
        if e.status != Status.FAIL:
            continue
        for risk in risks:
            if risk.check != e.check_id or (risk.region and risk.region != e.region):
                continue
            risk.used = True
            items = _affected_items(e.details)
            named = set(risk.resources)
            not_covered = [] if not named else [
                sorted(item)[0] for item in items if not item & named]
            if risk.resources and not items:
                # The check lists no resources, so a resource-level acceptance
                # cannot be confirmed. Keep it visible.
                not_covered = ["(this check does not list resources)"]
            if today > risk.expires:
                state = EXPIRED
            elif not_covered:
                state = PARTIAL
            else:
                state = ACCEPTED
            e.accepted_risk = {
                "state": state,
                "reason": risk.reason,
                "approved_by": risk.approved_by,
                "expires": risk.expires.isoformat(),
                "ticket": risk.ticket,
                "resources": list(risk.resources),
                "not_covered": not_covered,
            }
            break


def is_accepted(e: Evidence) -> bool:
    """True for a failed result that is fully covered by an active acceptance."""
    return e.status == Status.FAIL and e.accepted_risk.get("state") == ACCEPTED
