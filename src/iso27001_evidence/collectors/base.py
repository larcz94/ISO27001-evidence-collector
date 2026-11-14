"""Base class every collector (AWS, Microsoft 365, GitLab, Linux, ...) extends."""

from __future__ import annotations

import logging
from collections.abc import Callable

from ..models import Evidence, Status

log = logging.getLogger(__name__)

CheckFn = Callable[[], Evidence]


class BaseCollector:
    """A collector groups read-only checks for one source system.

    Subclasses register checks with the @check decorator. Each check returns
    one Evidence record. A failing check never stops the run: exceptions are
    turned into ERROR evidence so the report always shows what was attempted.
    """

    source: str = "base"
    # check_id -> how to fix a FAIL. Shown in the report next to the finding.
    remediation: dict[str, str] = {}
    # check_id -> (title, severity). The title says what should be true, in plain
    # English ("X should ..."), like AWS Security Hub and CIS do. The severity
    # says how bad a FAIL is: critical, high, medium or low.
    check_info: dict[str, tuple[str, str]] = {}
    # Checks that cover the whole account, not one region. In a multi-region
    # run they are executed once instead of once per region.
    global_checks: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self.scope = ""
        self.region = ""

    @classmethod
    def check_ids(cls) -> list[str]:
        """All check IDs of this collector. Needs no credentials."""
        ids = (getattr(getattr(cls, name), "_check_id", None) for name in dir(cls))
        return sorted(i for i in ids if i)

    @classmethod
    def available_regions(cls, session=None) -> list[str]:
        """Regions this collector can check. Used by --all-regions."""
        raise NotImplementedError(f"{cls.source} does not support --all-regions")

    def checks(self) -> dict[str, CheckFn]:
        found: dict[str, CheckFn] = {}
        for name in dir(type(self)):
            fn = getattr(type(self), name)
            check_id = getattr(fn, "_check_id", None)
            if check_id:
                found[check_id] = getattr(self, name)
        return found

    def run(self, only: set[str] | None = None, include_global: bool = True) -> list[Evidence]:
        results: list[Evidence] = []
        for check_id, fn in sorted(self.checks().items()):
            if only and check_id not in only:
                continue
            if not include_global and check_id in self.global_checks:
                continue
            log.info("Running %s", check_id)
            try:
                ev = fn()
            except Exception as exc:  # noqa: BLE001 - report, don't crash
                ev = Evidence(
                    check_id=check_id,
                    source=self.source,
                    status=Status.ERROR,
                    summary=f"Check failed: {type(exc).__name__}: {exc}",
                )
            ev.scope = ev.scope or self.scope
            title, severity = self.check_info.get(check_id, ("", ""))
            ev.title = ev.title or title
            ev.severity = ev.severity or severity
            ev.region = ev.region or (
                "global" if check_id in self.global_checks else self.region)
            if ev.status == Status.FAIL and not ev.remediation:
                ev.remediation = self.remediation.get(check_id, "")
            results.append(ev)
        return results


def check(check_id: str) -> Callable[[Callable], Callable]:
    """Mark a collector method as a check with a stable ID."""

    def wrap(fn: Callable) -> Callable:
        fn._check_id = check_id  # type: ignore[attr-defined]
        return fn

    return wrap
