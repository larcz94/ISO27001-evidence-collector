"""CLI tests: run the real entry point against mocked AWS."""

import json

import pytest
from moto import mock_aws

from iso27001_evidence.cli import main


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "eu-central-1"}.items():
        monkeypatch.setenv(k, v)


@mock_aws
def test_collect_writes_reports_with_builtin_mapping(tmp_path, capsys):
    assert main(["collect", "--source", "aws", "--out", str(tmp_path)]) == 0
    md = list(tmp_path.glob("evidence-*.md"))
    js = list(tmp_path.glob("evidence-*.json"))
    assert len(md) == 1 and len(js) == 1
    assert "A.8.15" in md[0].read_text(encoding="utf-8")
    assert all("check_id" in e for e in json.loads(js[0].read_text(encoding="utf-8")))


@mock_aws
def test_fail_on_gap_returns_exit_code_1(tmp_path):
    # An empty mocked account has gaps (no root MFA, no CloudTrail).
    assert main(["collect", "--out", str(tmp_path), "--fail-on-gap"]) == 1
