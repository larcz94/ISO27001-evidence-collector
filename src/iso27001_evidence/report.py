"""Turn Evidence records into an audit-ready report grouped by Annex A control."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from html import escape
from importlib import resources
from pathlib import Path

import yaml

from . import __version__
from .accepted_risks import EXPIRED, PARTIAL, is_accepted
from .models import SEVERITIES, Evidence, Status

REPORT_TITLE = "ISO/IEC 27001:2022 Evidence Report"
DISCLAIMER = ("Automated evidence supports, but does not replace, documented policies, "
              "procedures and records. See the notes under each control.")
FIX_NOTE = ("Fix suggestions are general guidance. Review them against your own "
            "policies and test before you change a production system.")
ACCEPTED_NOTE = ("These findings are still gaps, so their status stays FAIL. They are "
                 "listed here because the organization decided to accept them for a time. "
                 "Review each one before it expires.")
ERROR_NOTE = ("These checks could not run, so they prove nothing either way. The usual "
              "cause is a missing permission. Compare the role with the files in policies/.")


# ---------------------------------------------------------------- shared helpers
def load_mapping(path: str | Path | None = None) -> dict:
    """Load a control mapping. Without a path, use the one shipped in the package."""
    if path is None:
        mapping_file = resources.files("iso27001_evidence.mappings") / "annex_a.yaml"
        text = mapping_file.read_text(encoding="utf-8")
        return yaml.safe_load(text)
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def control_status(results: list[Evidence]) -> Status | None:
    """The worst status wins: one FAIL makes the whole control FAIL."""
    if not results:
        return None
    statuses = {r.status for r in results}
    for s in (Status.FAIL, Status.ERROR, Status.PASS, Status.INFO):
        if s in statuses:
            return s
    return Status.NOT_APPLICABLE


def controls_by_check(mapping: dict) -> dict[str, list[str]]:
    """Reverse the mapping: check ID -> the Annex A controls it supports."""
    out: dict[str, list[str]] = {}
    for cid, ctl in mapping.get("controls", {}).items():
        for check_id in ctl.get("checks", []):
            out.setdefault(check_id, []).append(cid)
    return out


def group_by_check(evidence: list[Evidence]) -> dict[str, list[Evidence]]:
    """A multi-region run has several results per check, one per region."""
    out: dict[str, list[Evidence]] = {}
    for e in evidence:
        out.setdefault(e.check_id, []).append(e)
    return out


def control_results(ctl: dict, by_check: dict[str, list[Evidence]]) -> list[Evidence]:
    return [e for check_id in ctl.get("checks", []) for e in by_check.get(check_id, [])]


def regions_checked(evidence: list[Evidence]) -> list[str]:
    return sorted({e.region for e in evidence if e.region and e.region != "global"})


def _where(e: Evidence) -> str:
    """' (eu-west-3)' for regional results, '' for account-wide ones."""
    return f" ({e.region})" if e.region and e.region != "global" else ""


def _severity_rank(e: Evidence) -> int:
    return SEVERITIES.index(e.severity) if e.severity in SEVERITIES else len(SEVERITIES)


def findings(evidence: list[Evidence]) -> list[Evidence]:
    """Failed checks that still need fixing, worst severity first.

    Accepted risks are left out. They are listed by accepted() instead.
    """
    failed = (e for e in evidence if e.status == Status.FAIL and not is_accepted(e))
    return sorted(failed, key=lambda e: (_severity_rank(e), e.check_id, e.region))


def accepted(evidence: list[Evidence]) -> list[Evidence]:
    """Failed checks covered by an active acceptance, soonest expiry first."""
    return sorted((e for e in evidence if is_accepted(e)),
                  key=lambda e: (e.accepted_risk["expires"], e.check_id, e.region))


def risk_note(e: Evidence) -> str:
    """One sentence about an acceptance that no longer covers a finding."""
    risk = e.accepted_risk
    if risk.get("state") == EXPIRED:
        return f"An accepted risk for this finding expired on {risk['expires']}."
    if risk.get("state") == PARTIAL:
        return ("An accepted risk exists, but it does not name "
                f"{', '.join(risk['not_covered'])}.")
    return ""


def acceptance_text(e: Evidence) -> str:
    risk = e.accepted_risk
    ticket = f", ticket {risk['ticket']}" if risk.get("ticket") else ""
    return (f"Accepted by {risk['approved_by']} until {risk['expires']}{ticket}. "
            f"Reason: {risk['reason']}")


def errors(evidence: list[Evidence]) -> list[Evidence]:
    return sorted((e for e in evidence if e.status == Status.ERROR),
                  key=lambda e: (e.check_id, e.region))


def severity_counts(failed: list[Evidence]) -> list[tuple[str, int]]:
    counts = Counter(e.severity for e in failed)
    return [(s, counts[s]) for s in SEVERITIES if counts[s]]


def detail_rows(results: list[Evidence]) -> list[tuple[Status, str, str, str, str]]:
    """Rows for the evidence detail: (status, check ID, text, collection note, title).

    When a check found nothing to check in several regions, those N/A results
    become one row that names the regions. A run over all regions would
    otherwise be mostly "nothing here" lines.
    """
    not_applicable: dict[str, list[Evidence]] = {}
    for r in results:
        if r.status == Status.NOT_APPLICABLE:
            not_applicable.setdefault(r.check_id, []).append(r)

    rows, collapsed = [], set()
    for r in results:
        group = not_applicable.get(r.check_id, [])
        if r.status == Status.NOT_APPLICABLE and len(group) > 1:
            if r.check_id in collapsed:
                continue
            collapsed.add(r.check_id)
            names = ", ".join(sorted(x.region for x in group))
            rows.append((r.status, r.check_id,
                         f"Nothing to check in {len(group)} regions: {names}",
                         f"collected {r.collected_at}, scope {r.scope}", r.title))
        else:
            region = f", region {r.region}" if r.region else ""
            text = r.summary
            if is_accepted(r):
                text += f" (risk accepted until {r.accepted_risk['expires']})"
            rows.append((r.status, r.check_id, text,
                         f"collected {r.collected_at}, scope {r.scope}{region}", r.title))
    return rows


def _label(key: str) -> str:
    return key.replace("_", " ")


def _value(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def affected_resources(details: dict) -> list[tuple[str, list[str]]]:
    """Turn the non-empty lists in a check's details into readable lines.

    {"exposed_admin_ports": [{"instance": "web-1", "port": 22}]}
    becomes [("exposed admin ports", ["instance: web-1; port: 22"])].
    """
    groups = []
    for key, value in details.items():
        if not isinstance(value, list) or not value:
            continue
        items = []
        for item in value:
            if isinstance(item, dict):
                items.append("; ".join(f"{_label(k)}: {_value(v)}" for k, v in item.items()))
            else:
                items.append(str(item))
        groups.append((_label(key), items))
    return groups


def _control_label(st: Status | None, ctl: dict) -> str:
    if st:
        return st.value
    return "not checked in this run" if ctl.get("checks") else "not automated yet"


# ---------------------------------------------------------------- Markdown
def _markdown_findings(evidence: list[Evidence], mapping: dict) -> list[str]:
    by_control = controls_by_check(mapping)
    failed, failed_to_run = findings(evidence), errors(evidence)

    lines = ["", f"## Findings to fix ({len(failed)})", ""]
    if not failed:
        lines += ["No failed checks in this run.", ""]
    else:
        by_severity = ", ".join(f"{n} {s}" for s, n in severity_counts(failed))
        if by_severity:
            lines += [f"By severity: {by_severity}.", ""]
        lines += [f"> {FIX_NOTE}", ""]
    for n, e in enumerate(failed, 1):
        severity = f"[{e.severity.upper()}] " if e.severity else ""
        lines += [f"### {n}. {severity}{e.title or e.check_id}{_where(e)}", "",
                  f"- **Check:** `{e.check_id}`",
                  f"- **Finding:** {e.summary}"]
        if _where(e):
            lines.append(f"- **Region:** {e.region}")
        if by_control.get(e.check_id):
            lines.append(f"- **Controls:** {', '.join(by_control[e.check_id])}")
        for label, items in affected_resources(e.details):
            lines.append(f"- **Affected ({label}):**")
            lines += [f"  - {item}" for item in items]
        if e.remediation:
            lines.append(f"- **How to fix:** {e.remediation}")
        if risk_note(e):
            lines.append(f"- **Note:** {risk_note(e)}")
        lines.append("")
    risks = accepted(evidence)
    if risks:
        lines += [f"## Accepted risks ({len(risks)})", "", f"> {ACCEPTED_NOTE}", ""]
        for e in risks:
            severity = f"[{e.severity.upper()}] " if e.severity else ""
            lines += [f"- {severity}{e.title or e.check_id}{_where(e)} (`{e.check_id}`): "
                      f"{e.summary}  ", f"  {acceptance_text(e)}"]
        lines.append("")
    if failed_to_run:
        lines += [f"## Checks that could not run ({len(failed_to_run)})", "",
                  f"> {ERROR_NOTE}", ""]
        lines += [f"- `{e.check_id}`{_where(e)}: {e.summary}" for e in failed_to_run]
        lines.append("")
    return lines


def build_markdown(evidence: list[Evidence], mapping: dict) -> str:
    by_check = group_by_check(evidence)
    scopes = sorted({e.scope for e in evidence if e.scope})
    regions = regions_checked(evidence)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(e.status for e in evidence)

    lines = [
        f"# {REPORT_TITLE}",
        "",
        f"- **Framework:** {mapping.get('framework', 'ISO/IEC 27001:2022')}",
        f"- **Generated:** {now}",
        f"- **Scope:** {', '.join(scopes) or 'n/a'}",
        f"- **Regions ({len(regions)}):** {', '.join(regions) or 'n/a'}",
        f"- **Checks run:** {len(evidence)} "
        f"(PASS {counts[Status.PASS]}, FAIL {counts[Status.FAIL]}, "
        f"ERROR {counts[Status.ERROR]}, N/A {counts[Status.NOT_APPLICABLE]})",
        f"- **Accepted risks:** {len(accepted(evidence))} of the FAIL results",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Summary by control",
        "",
        "| Control | Title | Status | Results |",
        "|---|---|---|---|",
    ]
    controls = mapping.get("controls", {})
    for cid, ctl in controls.items():
        results = control_results(ctl, by_check)
        st = control_status(results)
        label = f"**{st.value}**" if st else _control_label(st, ctl)
        lines.append(f"| {cid} | {ctl['title']} | {label} | {len(results)} |")

    lines += _markdown_findings(evidence, mapping)
    lines += ["## Evidence detail", ""]
    for cid, ctl in controls.items():
        results = control_results(ctl, by_check)
        if not results:
            continue
        lines += [f"### {cid} {ctl['title']}", ""]
        for status, check_id, text, note, title in detail_rows(results):
            name = f"{title} (`{check_id}`)" if title else f"`{check_id}`"
            lines.append(f"- **{status.value}** {name}: {text}  ")
            lines.append(f"  _{note}_")
        if ctl.get("note"):
            lines += ["", f"**Also provide:** {ctl['note']}"]
        lines.append("")
    lines += ["---", f"Generated by iso27001-evidence-collector {__version__}", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- HTML
# One self-contained file: inline CSS, no scripts, no external files, so it can
# be opened offline, attached to an audit ticket or printed to PDF.
# Status colors are never the only signal: every badge also carries its label.
HTML_STYLE = """
:root {
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #4a4a47; --ink-3: #6f6e69;
  --line: #e1e0d9; --line-2: #c3c2b7;
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
  --neutral: #8a8a84; --info: #3d7dd8;
  --good-bg: #e7f5e7; --warning-bg: #fef4dc; --serious-bg: #fdebe3; --critical-bg: #fae6e6;
  --neutral-bg: #efeeea; --info-bg: #e6eefa; --fix-bg: #eef6ee;
}
@media (prefers-color-scheme: dark) {
  :root {
    --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --ink-3: #9a9992;
    --line: #2c2c2a; --line-2: #383835;
    --good-bg: #12301a; --warning-bg: #3a2f10; --serious-bg: #3a231a; --critical-bg: #3a1a1a;
    --neutral-bg: #262624; --info-bg: #16263d; --fix-bg: #14261a;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink); line-height: 1.5;
       font-family: system-ui, -apple-system, "Segoe UI", sans-serif; font-size: 15px; }
.wrap { max-width: 64rem; margin: 0 auto; padding: 2rem 1rem 3rem; }
header h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
.sub { color: var(--ink-2); margin: 0; }
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(10.5rem, 1fr));
        gap: .25rem 1.5rem; margin: 1rem 0 0; }
.meta div { min-width: 0; }
.meta dt { font-size: .75rem; text-transform: uppercase; letter-spacing: .04em;
           color: var(--ink-3); }
.meta dd { margin: 0; overflow-wrap: anywhere; }
h2 { font-size: 1.2rem; margin: 2.5rem 0 .75rem; }
h3 { font-size: 1rem; margin: 0; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr));
         gap: .75rem; margin-top: 1.5rem; }
.tile { padding: .9rem 1rem; }
.tile .num { font-size: 2rem; font-weight: 650; line-height: 1.1; }
.tile .lbl { color: var(--ink-2); font-size: .85rem; }
.tile .hint { color: var(--ink-3); font-size: .75rem; }
.tile.alert { border-top: 3px solid var(--critical); }
.tile.ok { border-top: 3px solid var(--good); }
.bar { display: flex; gap: 2px; height: 14px; margin: 1.25rem 0 .5rem; }
.bar span { border-radius: 4px; min-width: 4px; }
.legend { display: flex; flex-wrap: wrap; gap: .25rem 1.25rem; font-size: .85rem;
          color: var(--ink-2); padding: 0; margin: 0; list-style: none; }
.dot { display: inline-block; width: .65rem; height: .65rem; border-radius: 2px;
       margin-right: .4rem; }
.bg-PASS { background: var(--good); } .bg-FAIL { background: var(--critical); }
.bg-ERROR { background: var(--warning); } .bg-NA { background: var(--neutral); }
.bg-INFO { background: var(--info); } .bg-ACCEPTED { background: var(--info); }
.badge { display: inline-flex; align-items: center; gap: .35rem; white-space: nowrap;
         padding: .1rem .55rem; border-radius: 999px; font-size: .78rem; font-weight: 600;
         color: var(--ink); background: var(--neutral-bg); }
.badge::before { content: ""; width: .5rem; height: .5rem; border-radius: 50%;
                 background: var(--neutral); }
.badge.PASS { background: var(--good-bg); } .badge.PASS::before { background: var(--good); }
.badge.FAIL { background: var(--critical-bg); }
.badge.FAIL::before { background: var(--critical); }
.badge.ERROR { background: var(--warning-bg); }
.badge.ERROR::before { background: var(--warning); }
.badge.INFO { background: var(--info-bg); } .badge.INFO::before { background: var(--info); }
.badge.critical { background: var(--critical-bg); }
.badge.critical::before { background: var(--critical); }
.badge.high { background: var(--serious-bg); }
.badge.high::before { background: var(--serious); }
.badge.medium { background: var(--warning-bg); }
.badge.medium::before { background: var(--warning); }
.muted { color: var(--ink-3); }
.notice { color: var(--ink-2); border-left: 3px solid var(--line-2); padding: .1rem 0 .1rem .9rem;
          margin: .75rem 0; }
.finding { padding: 1rem 1.1rem; margin: .75rem 0; border-left: 4px solid var(--neutral);
           break-inside: avoid; }
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--serious); }
.finding.medium { border-left-color: var(--warning); }
.finding .top { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem .75rem; }
.finding .id, .accepted .id { color: var(--ink-3); font-size: .8rem; margin: .2rem 0 .6rem; }
.finding dl { margin: 0; display: grid; grid-template-columns: 7.5rem 1fr; gap: .45rem 1rem; }
.finding dt { color: var(--ink-3); font-size: .85rem; }
.finding dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.finding ul { margin: 0; padding-left: 1.1rem; }
.fix { background: var(--fix-bg); border-radius: 6px; padding: .5rem .75rem; }
.risk-note { background: var(--warning-bg); border-radius: 6px; padding: .5rem .75rem; }
.accepted { padding: .8rem 1.1rem; margin: .6rem 0; border-left: 4px solid var(--info);
            break-inside: avoid; }
.accepted .top { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem .75rem; }
.accepted p { margin: .35rem 0 0; }
.chip { display: inline-block; border: 1px solid var(--line-2); border-radius: 4px;
        padding: 0 .4rem; font-size: .8rem; margin-right: .3rem; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: var(--ink-3);
     font-weight: 600; }
tr:last-child td { border-bottom: 0; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; }
code { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: .85em; }
details.card { margin: .6rem 0; }
details summary { cursor: pointer; padding: .7rem 1rem; display: flex; align-items: center;
                  gap: .75rem; font-weight: 600; }
details summary .grow { flex: 1; }
details .body { border-top: 1px solid var(--line); }
details .also { padding: .6rem 1rem; color: var(--ink-2); border-top: 1px solid var(--line); }
.small { font-size: .8rem; color: var(--ink-3); }
footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--ink-3); font-size: .85rem; }
@media (max-width: 40rem) { .finding dl { grid-template-columns: 1fr; gap: .1rem; }
                            .finding dt { margin-top: .5rem; } }
@media print {
  body { background: #fff; font-size: 12px; } .wrap { max-width: none; padding: 0; }
  .card { border-color: #bbb; } h2 { break-after: avoid; } details { break-inside: avoid; }
}
"""


def _css(status: Status | str) -> str:
    if isinstance(status, str) and not isinstance(status, Status):
        return status   # "ACCEPTED" is a report-only group, not a check status
    return "NA" if status == Status.NOT_APPLICABLE else status.name


def _badge(status: Status) -> str:
    return f'<span class="badge {_css(status)}">{escape(status.value)}</span>'


def _severity_badge(severity: str) -> str:
    if not severity:
        return ""
    return f'<span class="badge {escape(severity)}">{escape(severity.capitalize())}</span>'


def _tile(number: int, label: str, hint: str = "", css: str = "") -> str:
    hint_html = f'<div class="hint">{escape(hint)}</div>' if hint else ""
    return (f'<div class="card tile {css}"><div class="num">{number}</div>'
            f'<div class="lbl">{escape(label)}</div>{hint_html}</div>')


def _html_overview(evidence: list[Evidence], mapping: dict) -> list[str]:
    counts = Counter(e.status for e in evidence)
    by_check = group_by_check(evidence)
    statuses = [control_status(control_results(ctl, by_check))
                for ctl in mapping.get("controls", {}).values()]
    checked = [s for s in statuses if s]
    with_gaps = sum(s == Status.FAIL for s in checked)
    risks = len(accepted(evidence))
    failed = counts[Status.FAIL] - risks

    out = ['<div class="tiles">',
           _tile(failed, "Findings to fix", "failed checks", "alert" if failed else "ok"),
           *([_tile(risks, "Accepted risks", "documented exceptions")] if risks else []),
           _tile(counts[Status.PASS], "Passed"),
           _tile(counts[Status.NOT_APPLICABLE], "Not applicable", "nothing to check"),
           _tile(counts[Status.ERROR], "Could not run", "check permissions"),
           _tile(with_gaps, "Controls with gaps", f"of {len(checked)} controls checked"),
           "</div>"]

    # One bar for the split of all results. Labels and counts are in the legend,
    # so the colors never carry the meaning alone.
    sizes = {**counts, Status.FAIL: failed, "ACCEPTED": risks}
    order = [(Status.FAIL, "Failed"), ("ACCEPTED", "Accepted risk"),
             (Status.ERROR, "Could not run"), (Status.PASS, "Passed"),
             (Status.NOT_APPLICABLE, "Not applicable")]
    parts = [(s, label, sizes[s]) for s, label in order if sizes.get(s)]
    if parts:
        out.append('<div class="bar" role="img" aria-label="Results by status">')
        out += [f'<span class="bg-{_css(s)}" style="flex:{n}" title="{escape(label)}: {n}">'
                f"</span>" for s, label, n in parts]
        out.append('</div><ul class="legend">')
        out += [f'<li><span class="dot bg-{_css(s)}"></span>{escape(label)} {n}</li>'
                for s, label, n in parts]
        out.append("</ul>")
    return out


def _html_findings(evidence: list[Evidence], mapping: dict) -> list[str]:
    by_control = controls_by_check(mapping)
    failed, failed_to_run = findings(evidence), errors(evidence)

    out = [f"<h2>Findings to fix ({len(failed)})</h2>"]
    if not failed:
        out.append("<p>No failed checks in this run.</p>")
    else:
        badges = " ".join(f"{_severity_badge(s)} {n}" for s, n in severity_counts(failed))
        if badges:
            out.append(f"<p>{badges}</p>")
        out.append(f'<p class="notice">{escape(FIX_NOTE)}</p>')
    for n, e in enumerate(failed, 1):
        out.append(f'<div class="card finding {escape(e.severity)}"><div class="top">'
                   f"{_severity_badge(e.severity)}"
                   f"<h3>{n}. {escape(e.title or e.check_id)}</h3></div>"
                   f'<div class="id"><code>{escape(e.check_id)}</code>{escape(_where(e))}</div>'
                   f"<dl>")
        out.append(f"<dt>Finding</dt><dd>{escape(e.summary)}</dd>")
        if _where(e):
            out.append(f"<dt>Region</dt><dd>{escape(e.region)}</dd>")
        if by_control.get(e.check_id):
            chips = "".join(f'<span class="chip">{escape(c)}</span>'
                            for c in by_control[e.check_id])
            out.append(f"<dt>Controls</dt><dd>{chips}</dd>")
        for label, items in affected_resources(e.details):
            rows = "".join(f"<li>{escape(item)}</li>" for item in items)
            out.append(f"<dt>Affected</dt><dd><span class=\"small\">{escape(label)}</span>"
                       f"<ul>{rows}</ul></dd>")
        if e.remediation:
            out.append(f'<dt>How to fix</dt><dd><div class="fix">{escape(e.remediation)}'
                       f"</div></dd>")
        if risk_note(e):
            out.append(f'<dt>Note</dt><dd><div class="risk-note">{escape(risk_note(e))}'
                       f"</div></dd>")
        out.append("</dl></div>")
    risks = accepted(evidence)
    if risks:
        out.append(f"<h2>Accepted risks ({len(risks)})</h2>")
        out.append(f'<p class="notice">{escape(ACCEPTED_NOTE)}</p>')
        for e in risks:
            out.append(f'<div class="card accepted"><div class="top">'
                       f"{_severity_badge(e.severity)}"
                       f"<h3>{escape(e.title or e.check_id)}</h3></div>"
                       f'<div class="id"><code>{escape(e.check_id)}</code>'
                       f"{escape(_where(e))}</div>"
                       f"<p>{escape(e.summary)}</p>"
                       f'<p class="small">{escape(acceptance_text(e))}</p></div>')
    if failed_to_run:
        out.append(f"<h2>Checks that could not run ({len(failed_to_run)})</h2>")
        out.append(f'<p class="notice">{escape(ERROR_NOTE)}</p><div class="card scroll"><table>')
        out += [f"<tr><td>{_badge(e.status)}</td><td><code>{escape(e.check_id)}</code>"
                f"{escape(_where(e))}<br>{escape(e.summary)}</td></tr>" for e in failed_to_run]
        out.append("</table></div>")
    return out


def build_html(evidence: list[Evidence], mapping: dict) -> str:
    """Build the HTML report.

    Every value from the scanned account is escaped, because resource names
    and summaries are untrusted input.
    """
    by_check = group_by_check(evidence)
    scopes = sorted({e.scope for e in evidence if e.scope})
    regions = regions_checked(evidence)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    controls = mapping.get("controls", {})

    summary_rows, detail = [], []
    for cid, ctl in controls.items():
        results = control_results(ctl, by_check)
        st = control_status(results)
        label = _badge(st) if st else f'<span class="muted">{_control_label(st, ctl)}</span>'
        summary_rows.append(
            f"<tr><td>{escape(cid)}</td><td>{escape(ctl['title'])}</td>"
            f'<td>{label}</td><td class="num">{len(results)}</td></tr>')
        if not results:
            continue
        # Open by default: a closed section would be missing from a printed PDF.
        detail.append(f'<details class="card" open><summary><span>{escape(cid)}</span>'
                      f'<span class="grow">{escape(ctl["title"])}</span>{_badge(st)}</summary>'
                      f'<div class="body scroll"><table>')
        for status, check_id, text, note, title in detail_rows(results):
            name = f"{escape(title)}<br>" if title else ""
            detail.append(
                f"<tr><td>{_badge(status)}</td><td>{name}"
                f'<code class="small">{escape(check_id)}</code></td>'
                f'<td>{escape(text)}<br><span class="small">{escape(note)}</span></td></tr>')
        detail.append("</table></div>")
        if ctl.get("note"):
            detail.append(f'<div class="also"><strong>Also provide:</strong> '
                          f"{escape(ctl['note'])}</div>")
        detail.append("</details>")

    framework = escape(mapping.get("framework", "ISO/IEC 27001:2022"))
    return "\n".join([
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(REPORT_TITLE)}</title>",
        f'<style>{HTML_STYLE}</style></head><body><div class="wrap">',
        f"<header><h1>{escape(REPORT_TITLE)}</h1>",
        '<p class="sub">Automated, read-only evidence for Annex A controls</p>',
        '<dl class="meta">',
        f"<div><dt>Framework</dt><dd>{framework}</dd></div>",
        f"<div><dt>Generated</dt><dd>{now}</dd></div>",
        f"<div><dt>Scope</dt><dd>{escape(', '.join(scopes) or 'n/a')}</dd></div>",
        f"<div><dt>Regions ({len(regions)})</dt>"
        f"<dd>{escape(', '.join(regions) or 'n/a')}</dd></div>",
        f"<div><dt>Checks run</dt><dd>{len(evidence)}</dd></div>",
        "</dl></header>",
        *_html_overview(evidence, mapping),
        f'<p class="notice">{escape(DISCLAIMER)}</p>',
        *_html_findings(evidence, mapping),
        "<h2>Summary by control</h2>",
        '<div class="card scroll"><table><tr><th>Control</th><th>Title</th><th>Status</th>'
        '<th style="text-align:right">Results</th></tr>',
        *summary_rows,
        "</table></div>",
        "<h2>Evidence detail</h2>",
        *detail,
        f"<footer>Generated by iso27001-evidence-collector {escape(__version__)}. "
        f"Read-only collection, no changes were made to the account.</footer>",
        "</div></body></html>",
        "",
    ])


# ---------------------------------------------------------------- files
def report_basename(evidence: list[Evidence], when: datetime | None = None) -> str:
    """File name without extension: what it is, which source, and when (UTC).

    Example: iso27001-evidence_lightsail_2026-11-14_212941Z
    The date comes first in ISO order, so files sort by time in any folder view.
    """
    when = when or datetime.now(timezone.utc)
    sources = "-".join(sorted({e.source for e in evidence if e.source})) or "none"
    return f"iso27001-evidence_{sources}_{when.strftime('%Y-%m-%d_%H%M%S')}Z"


def write_reports(evidence: list[Evidence], mapping: dict, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = report_basename(evidence)
    md_path = out / f"{base}.md"
    html_path = out / f"{base}.html"
    json_path = out / f"{base}.json"
    md_path.write_text(build_markdown(evidence, mapping), encoding="utf-8")
    html_path.write_text(build_html(evidence, mapping), encoding="utf-8")
    json_path.write_text(
        json.dumps([e.to_dict() for e in evidence], indent=2, default=str),
        encoding="utf-8",
    )
    return {"markdown": md_path, "html": html_path, "json": json_path}
