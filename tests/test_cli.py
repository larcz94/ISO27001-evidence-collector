"""CLI tests: run the real entry point against mocked AWS."""

import json

import pytest
from moto import mock_aws

from iso27001_evidence.cli import main
from iso27001_evidence.models import Evidence, Status
from iso27001_evidence.report import build_html, load_mapping


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "eu-central-1"}.items():
        monkeypatch.setenv(k, v)


@mock_aws
def test_collect_writes_reports_with_builtin_mapping(tmp_path, capsys):
    assert main(["collect", "--source", "aws", "--out", str(tmp_path)]) == 0
    md = list(tmp_path.glob("iso27001-evidence_*.md"))
    js = list(tmp_path.glob("iso27001-evidence_*.json"))
    assert len(md) == 1 and len(js) == 1
    assert "A.8.15" in md[0].read_text(encoding="utf-8")
    assert all("check_id" in e for e in json.loads(js[0].read_text(encoding="utf-8")))


@mock_aws
def test_fail_on_gap_returns_exit_code_1(tmp_path):
    # An empty mocked account has gaps (no root MFA, no CloudTrail).
    assert main(["collect", "--out", str(tmp_path), "--fail-on-gap"]) == 1


@mock_aws
def test_collect_also_writes_html_report(tmp_path):
    main(["collect", "--source", "aws", "--out", str(tmp_path)])
    html = list(tmp_path.glob("iso27001-evidence_*.html"))
    assert len(html) == 1
    text = html[0].read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "A.8.15" in text and "<script" not in text


def test_html_report_escapes_untrusted_values():
    ev = [Evidence(check_id="lightsail.bucket.public_access", source="lightsail",
                   status=Status.FAIL, summary='bucket <script>alert("x")</script> is public',
                   scope="aws:<b>scope</b>")]
    html = build_html(ev, load_mapping())
    assert "<script>" not in html and "<b>scope</b>" not in html
    assert "&lt;script&gt;" in html


@mock_aws
def test_list_checks_all_lists_every_source(capsys):
    assert main(["list-checks", "--source", "all"]) == 0
    lines = capsys.readouterr().out.split()
    assert any(c.startswith("aws.") for c in lines)
    assert any(c.startswith("lightsail.") for c in lines)
    assert len(lines) == len(set(lines)) == 18
