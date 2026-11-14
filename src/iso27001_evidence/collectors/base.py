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

    def __init__(self) -> None:
        self.scope = ""

    def checks(self) -> dict[str, CheckFn]:
        found: dict[str, CheckFn] = {}
        for name in dir(type(self)):
            fn = getattr(type(self), name)
            check_id = getattr(fn, "_check_id", None)
            if check_id:
                found[check_id] = getattr(self, name)
        return found

    def run(self, only: set[str] | None = None) -> list[Evidence]:
        results: list[Evidence] = []
        for check_id, fn in sorted(self.checks().items()):
            if only and check_id not in only:
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
            results.append(ev)
        return results


def check(check_id: str) -> Callable[[Callable], Callable]:
    """Mark a collector method as a check with a stable ID."""

    def wrap(fn: Callable) -> Callable:
        fn._check_id = check_id  # type: ignore[attr-defined]
        return fn

    return wrap
