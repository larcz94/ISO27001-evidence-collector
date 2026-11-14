"""Turn Evidence records into an audit-ready report grouped by Annex A control."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

import yaml

from .models import Evidence, Status


def load_mapping(path: str | Path | None = None) -> dict:
    """Load a control mapping. Without a path, use the one shipped in the package."""
    if path is None:
        mapping_file = resources.files("iso27001_evidence.mappings") / "annex_a.yaml"
        text = mapping_file.read_text(encoding="utf-8")
        return yaml.safe_load(text)
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def control_status(results: list[Evidence]) -> Status | None:
    if not results:
        return None
    statuses = {r.status for r in results}
    for s in (Status.FAIL, Status.ERROR, Status.PASS, Status.INFO):
        if s in statuses:
            return s
    return Status.NOT_APPLICABLE


def build_markdown(evidence: list[Evidence], mapping: dict) -> str:
    by_check = {e.check_id: e for e in evidence}
    scopes = sorted({e.scope for e in evidence if e.scope})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(e.status for e in evidence)

    lines = [
        "# ISO 27001 Evidence Report",
        "",
        f"- **Framework:** {mapping.get('framework', 'ISO/IEC 27001:2022')}",
        f"- **Generated:** {now}",
        f"- **Scope:** {', '.join(scopes) or 'n/a'}",
        f"- **Checks run:** {len(evidence)} "
        f"(PASS {counts[Status.PASS]}, FAIL {counts[Status.FAIL]}, "
        f"ERROR {counts[Status.ERROR]}, N/A {counts[Status.NOT_APPLICABLE]})",
        "",
        "> Automated evidence supports, but does not replace, documented policies,",
        "> procedures and records. See the notes under each control.",
        "",
        "## Summary by control",
        "",
        "| Control | Title | Status | Checks |",
        "|---|---|---|---|",
    ]
    controls = mapping.get("controls", {})
    for cid, ctl in controls.items():
        results = [by_check[c] for c in ctl.get("checks", []) if c in by_check]
        st = control_status(results)
        if st:
            label = f"**{st.value}**"
        elif ctl.get("checks"):
            label = "not checked in this run"
        else:
            label = "not automated yet"
        lines.append(f"| {cid} | {ctl['title']} | {label} | {len(results)} |")

    lines += ["", "## Evidence detail", ""]
    for cid, ctl in controls.items():
        results = [by_check[c] for c in ctl.get("checks", []) if c in by_check]
        if not results:
            continue
        lines += [f"### {cid} {ctl['title']}", ""]
        for r in results:
            lines.append(f"- **{r.status.value}** `{r.check_id}`: {r.summary}  ")
            lines.append(f"  _collected {r.collected_at}, scope {r.scope}_")
        if ctl.get("note"):
            lines += ["", f"**Also provide:** {ctl['note']}"]
        lines.append("")
    return "\n".join(lines)


def write_reports(evidence: list[Evidence], mapping: dict, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = out / f"evidence-{stamp}.md"
    json_path = out / f"evidence-{stamp}.json"
    md_path.write_text(build_markdown(evidence, mapping), encoding="utf-8")
    json_path.write_text(
        json.dumps([e.to_dict() for e in evidence], indent=2, default=str),
        encoding="utf-8",
    )
    return {"markdown": md_path, "json": json_path}
