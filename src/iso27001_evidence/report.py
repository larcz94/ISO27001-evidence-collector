"""Turn Evidence records into an audit-ready report grouped by Annex A control."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from html import escape
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


HTML_STYLE = """
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; color: #1f2933;
       max-width: 60rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
h1 { font-size: 1.6rem; } h2 { font-size: 1.25rem; margin-top: 2rem; }
h3 { font-size: 1.05rem; margin: 1.5rem 0 .5rem; }
.meta { color: #52606d; margin: 0; padding: 0; list-style: none; }
.notice { background: #f5f7fa; border-left: 4px solid #9aa5b1; padding: .6rem 1rem; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #e4e7eb;
         vertical-align: top; }
th { background: #f5f7fa; }
.badge { display: inline-block; min-width: 3.2rem; text-align: center; padding: .1rem .45rem;
         border-radius: .25rem; font-size: .8rem; font-weight: 600; border: 1px solid; }
.PASS { color: #0b6b3a; background: #e6f6ec; } .FAIL { color: #a61b1b; background: #fdecec; }
.ERROR { color: #8a5300; background: #fff4e0; } .INFO { color: #1d4f91; background: #e8f1fb; }
.NA { color: #52606d; background: #f0f2f5; } .muted { color: #7b8794; }
code { font-family: ui-monospace, Consolas, monospace; font-size: .9em; }
.collected { color: #7b8794; font-size: .85rem; }
@media print { body { margin: 0; max-width: none; } h3 { break-after: avoid; } }
"""


def _badge(status: Status) -> str:
    css = "NA" if status == Status.NOT_APPLICABLE else status.name
    return f'<span class="badge {css}">{escape(status.value)}</span>'


def build_html(evidence: list[Evidence], mapping: dict) -> str:
    """One self-contained HTML file: inline CSS, no scripts, no external files.

    Every value from the scanned account is escaped, because resource names
    and summaries are untrusted input.
    """
    by_check = {e.check_id: e for e in evidence}
    scopes = sorted({e.scope for e in evidence if e.scope})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(e.status for e in evidence)
    controls = mapping.get("controls", {})

    summary_rows, detail = [], []
    for cid, ctl in controls.items():
        results = [by_check[c] for c in ctl.get("checks", []) if c in by_check]
        st = control_status(results)
        if st:
            label = _badge(st)
        elif ctl.get("checks"):
            label = '<span class="muted">not checked in this run</span>'
        else:
            label = '<span class="muted">not automated yet</span>'
        summary_rows.append(
            f"<tr><td>{escape(cid)}</td><td>{escape(ctl['title'])}</td>"
            f"<td>{label}</td><td>{len(results)}</td></tr>")
        if not results:
            continue
        detail.append(f"<h3>{escape(cid)} {escape(ctl['title'])}</h3>\n<table>")
        for r in results:
            detail.append(
                f"<tr><td>{_badge(r.status)}</td><td><code>{escape(r.check_id)}</code><br>"
                f"{escape(r.summary)}<br><span class=\"collected\">collected "
                f"{escape(r.collected_at)}, scope {escape(r.scope)}</span></td></tr>")
        detail.append("</table>")
        if ctl.get("note"):
            detail.append(f"<p><strong>Also provide:</strong> {escape(ctl['note'])}</p>")

    framework = escape(mapping.get("framework", "ISO/IEC 27001:2022"))
    return "\n".join([
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>ISO 27001 Evidence Report</title>",
        f"<style>{HTML_STYLE}</style></head><body>",
        "<h1>ISO 27001 Evidence Report</h1>",
        '<ul class="meta">',
        f"<li><strong>Framework:</strong> {framework}</li>",
        f"<li><strong>Generated:</strong> {now}</li>",
        f"<li><strong>Scope:</strong> {escape(', '.join(scopes) or 'n/a')}</li>",
        f"<li><strong>Checks run:</strong> {len(evidence)} (PASS {counts[Status.PASS]}, "
        f"FAIL {counts[Status.FAIL]}, ERROR {counts[Status.ERROR]}, "
        f"N/A {counts[Status.NOT_APPLICABLE]})</li>",
        "</ul>",
        '<p class="notice">Automated evidence supports, but does not replace, documented '
        "policies, procedures and records. See the notes under each control.</p>",
        "<h2>Summary by control</h2>",
        "<table><tr><th>Control</th><th>Title</th><th>Status</th><th>Checks</th></tr>",
        *summary_rows,
        "</table>",
        "<h2>Evidence detail</h2>",
        *detail,
        "</body></html>",
        "",
    ])


def write_reports(evidence: list[Evidence], mapping: dict, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = out / f"evidence-{stamp}.md"
    html_path = out / f"evidence-{stamp}.html"
    json_path = out / f"evidence-{stamp}.json"
    md_path.write_text(build_markdown(evidence, mapping), encoding="utf-8")
    html_path.write_text(build_html(evidence, mapping), encoding="utf-8")
    json_path.write_text(
        json.dumps([e.to_dict() for e in evidence], indent=2, default=str),
        encoding="utf-8",
    )
    return {"markdown": md_path, "html": html_path, "json": json_path}
