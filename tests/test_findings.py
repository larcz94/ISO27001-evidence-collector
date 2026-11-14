"""Findings in the report: affected resources and how to fix them."""

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from iso27001_evidence.collectors.aws import AWSCollector
from iso27001_evidence.collectors.lightsail import LightsailCollector
from iso27001_evidence.models import Evidence, Status
from iso27001_evidence.report import (
    affected_resources,
    build_html,
    build_markdown,
    controls_by_check,
    load_mapping,
)

REGION = "eu-central-1"

SSH_FINDING = Evidence(
    check_id="lightsail.instance.admin_ports_restricted", source="lightsail",
    status=Status.FAIL, summary="1 admin port(s) open to the internet across 1 instance(s)",
    details={"exposed_admin_ports": [
        {"instance": "web-1", "port": 22, "service": "SSH", "open_to": ["0.0.0.0/0", "::/0"]}]},
    remediation="Restrict the SSH rule to your own IP addresses.",
    scope="aws:123456789012/eu-central-1",
)


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)


@mock_aws
def test_every_check_has_a_fix_suggestion():
    session = boto3.Session(region_name=REGION)
    for collector in (AWSCollector(session=session),
                      LightsailCollector(session=session, region=REGION)):
        missing = set(collector.checks()) - set(collector.remediation)
        unknown = set(collector.remediation) - set(collector.checks())
        assert not missing, f"checks without a fix suggestion: {missing}"
        assert not unknown, f"fix suggestions for unknown checks: {unknown}"


@mock_aws
def test_only_failed_checks_get_a_fix_suggestion():
    session = boto3.Session(region_name=REGION)
    client = session.client("lightsail", region_name=REGION)
    collector = LightsailCollector(session=session, region=REGION, client=client)
    with Stubber(client) as stub:
        stub.add_response("get_instances", {"instances": [
            {"name": "web-1", "addOns": [], "metadataOptions": {"httpTokens": "required"}}]})
        results = {e.check_id: e for e in collector.run(only={
            "lightsail.instance.auto_snapshots", "lightsail.instance.imdsv2_required"})}
    failed = results["lightsail.instance.auto_snapshots"]
    passed = results["lightsail.instance.imdsv2_required"]
    assert failed.status == Status.FAIL and "automatic snapshots" in failed.remediation
    assert passed.status == Status.PASS and passed.remediation == ""
    assert failed.to_dict()["remediation"] == failed.remediation


def test_affected_resources_reads_lists_and_skips_the_rest():
    details = {"instances_total": 2, "exposed_admin_ports": [
        {"instance": "web-1", "port": 22, "open_to": ["0.0.0.0/0", "::/0"]}],
        "users_without_mfa": ["alice", "bob"], "empty": [], "policy": {"a": 1}}
    assert affected_resources(details) == [
        ("exposed admin ports", ["instance: web-1; port: 22; open to: 0.0.0.0/0, ::/0"]),
        ("users without mfa", ["alice", "bob"]),
    ]


def test_controls_by_check_reverses_the_mapping():
    by_check = controls_by_check(load_mapping())
    assert by_check["lightsail.instance.admin_ports_restricted"] == ["A.8.20"]
    assert by_check["aws.iam.root_mfa"] == ["A.5.17", "A.8.2", "A.8.5"]


@pytest.mark.parametrize("build", [build_markdown, build_html])
def test_report_shows_affected_resource_and_fix(build):
    report = build([SSH_FINDING], load_mapping())
    assert "Findings to fix (1)" in report
    assert "web-1" in report and "port: 22" in report and "0.0.0.0/0, ::/0" in report
    assert "A.8.20" in report
    assert "Restrict the SSH rule to your own IP addresses." in report


@pytest.mark.parametrize("build", [build_markdown, build_html])
def test_report_without_failures_says_so(build):
    ok = Evidence(check_id="lightsail.instance.imdsv2_required", source="lightsail",
                  status=Status.PASS, summary="1 of 1 instances require IMDSv2")
    report = build([ok], load_mapping())
    assert "Findings to fix (0)" in report and "No failed checks in this run." in report


@pytest.mark.parametrize("build", [build_markdown, build_html])
def test_report_lists_checks_that_could_not_run(build):
    err = Evidence(check_id="lightsail.bucket.public_access", source="lightsail",
                   status=Status.ERROR, summary="Check failed: AccessDeniedException")
    report = build([err], load_mapping())
    assert "Checks that could not run (1)" in report and "AccessDeniedException" in report


def test_html_escapes_resource_names_in_findings():
    evil = Evidence(check_id="lightsail.instance.auto_snapshots", source="lightsail",
                    status=Status.FAIL, summary="0 of 1 instances have snapshots",
                    details={"instances_without_auto_snapshots": ["<img src=x onerror=alert(1)>"]},
                    remediation="Turn on <b>snapshots</b>.")
    html = build_html([evil], load_mapping())
    assert "<img" not in html and "<b>snapshots</b>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
