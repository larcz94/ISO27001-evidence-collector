"""Accepted risk register: loading, matching, reports and the CLI."""

import json
from datetime import date

import pytest
from moto import mock_aws

from iso27001_evidence.accepted_risks import (
    ACCEPTED,
    EXPIRED,
    PARTIAL,
    AcceptedRisk,
    AcceptedRiskError,
    apply_accepted_risks,
    is_accepted,
    load_accepted_risks,
)
from iso27001_evidence.cli import main
from iso27001_evidence.models import Evidence, Status
from iso27001_evidence.report import accepted, build_html, build_markdown, findings, load_mapping

KNOWN = {"lightsail.instance.auto_snapshots", "lightsail.instance.admin_ports_restricted",
         "aws.iam.root_mfa"}
TODAY = date(2026, 11, 18)


def risk(**kw):
    values = {"check": "lightsail.instance.auto_snapshots", "reason": "Test box, no data.",
              "approved_by": "ISMS lead", "expires": date(2027, 5, 31)}
    values.update(kw)
    return AcceptedRisk(**values)


def snapshots_fail(names=("test-box",), region="eu-west-3"):
    return Evidence("lightsail.instance.auto_snapshots", "lightsail", Status.FAIL,
                    f"0 of {len(names)} instances have automatic snapshots enabled",
                    details={"instances_total": len(names),
                             "instances_without_auto_snapshots": list(names)},
                    title="Instances should have automatic snapshots", severity="medium",
                    region=region, scope="aws:123456789012")


def write(tmp_path, text):
    path = tmp_path / "accepted-risks.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------- loading
def test_load_valid_file(tmp_path):
    path = write(tmp_path, """
accepted_risks:
  - check: lightsail.instance.auto_snapshots
    region: eu-west-3
    resources: [test-box]
    reason: Test box, no data.
    approved_by: ISMS lead
    expires: 2027-05-31
    ticket: RISK-42
""")
    [r] = load_accepted_risks(path, KNOWN)
    assert (r.check, r.region, r.resources, r.ticket) == (
        "lightsail.instance.auto_snapshots", "eu-west-3", ["test-box"], "RISK-42")
    assert r.expires == date(2027, 5, 31)


def test_single_resource_may_be_a_string(tmp_path):
    path = write(tmp_path, """
accepted_risks:
  - {check: aws.iam.root_mfa, reason: r, approved_by: a, expires: "2027-01-01", resources: x}
""")
    assert load_accepted_risks(path, KNOWN)[0].resources == ["x"]


@pytest.mark.parametrize("text, message", [
    ("accepted_risks:\n  - {check: lightsail.instance.auto_snapshot, reason: r, "
     "approved_by: a, expires: 2027-01-01}", "unknown check 'lightsail.instance.auto_snapshot'"),
    ("accepted_risks:\n  - {check: aws.iam.root_mfa, reason: r, expires: 2027-01-01}",
     "missing approved_by"),
    ("accepted_risks:\n  - {check: aws.iam.root_mfa, reason: r, approved_by: a, "
     "expires: next year}", "'expires' must be a date"),
    ("accepted_risks:\n  - {check: aws.iam.root_mfa, reason: r, approved_by: a, "
     "expires: 2027-01-01, owner: b}", "unknown field(s) owner"),
    ("accepted_risks:\n  - {check: aws.iam.root_mfa, reason: '  ', approved_by: a, "
     "expires: 2027-01-01}", "missing reason"),
    ("risks: []", "top-level list named 'accepted_risks'"),
    ("accepted_risks: [: bad", "not valid YAML"),
])
def test_invalid_file_stops_with_a_clear_message(tmp_path, text, message):
    with pytest.raises(AcceptedRiskError, match="entry|YAML|top-level") as info:
        load_accepted_risks(write(tmp_path, text), KNOWN)
    assert message in str(info.value)


def test_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(AcceptedRiskError, match="Cannot read"):
        load_accepted_risks(tmp_path / "nope.yaml", KNOWN)


# ---------------------------------------------------------------- matching
def test_active_acceptance_covers_the_finding():
    ev = [snapshots_fail()]
    apply_accepted_risks(ev, [risk(region="eu-west-3", resources=["test-box"])], TODAY)
    assert is_accepted(ev[0]) and ev[0].accepted_risk["state"] == ACCEPTED
    assert ev[0].status == Status.FAIL   # the gap is still reported as a gap


def test_acceptance_without_resources_covers_every_resource():
    ev = [snapshots_fail(names=("a", "b"))]
    apply_accepted_risks(ev, [risk()], TODAY)
    assert is_accepted(ev[0])


def test_new_resource_is_not_hidden_by_an_old_acceptance():
    ev = [snapshots_fail(names=("test-box", "new-prod-box"))]
    apply_accepted_risks(ev, [risk(resources=["test-box"])], TODAY)
    assert not is_accepted(ev[0])
    assert ev[0].accepted_risk["state"] == PARTIAL
    assert ev[0].accepted_risk["not_covered"] == ["new-prod-box"]


def test_resource_inside_a_detail_record_is_matched_by_name():
    ev = [Evidence("lightsail.instance.admin_ports_restricted", "lightsail", Status.FAIL, "s",
                   details={"exposed_admin_ports": [
                       {"instance": "bastion", "port": 22, "service": "SSH",
                        "open_to": ["0.0.0.0/0"]}]}, region="eu-west-3")]
    apply_accepted_risks(ev, [risk(check="lightsail.instance.admin_ports_restricted",
                                   resources=["bastion"])], TODAY)
    assert is_accepted(ev[0])


def test_expired_acceptance_turns_back_into_a_finding():
    ev = [snapshots_fail()]
    apply_accepted_risks(ev, [risk(expires=date(2026, 11, 17))], TODAY)
    assert not is_accepted(ev[0]) and ev[0].accepted_risk["state"] == EXPIRED


def test_acceptance_is_valid_through_its_expiry_day():
    ev = [snapshots_fail()]
    apply_accepted_risks(ev, [risk(expires=TODAY)], TODAY)
    assert is_accepted(ev[0])


def test_region_must_match_when_given():
    ev = [snapshots_fail(region="eu-central-1")]
    risks = [risk(region="eu-west-3")]
    apply_accepted_risks(ev, risks, TODAY)
    assert ev[0].accepted_risk == {} and not risks[0].used


def test_only_failed_results_are_matched():
    ev = [Evidence("lightsail.instance.auto_snapshots", "lightsail", Status.PASS, "ok")]
    risks = [risk()]
    apply_accepted_risks(ev, risks, TODAY)
    assert ev[0].accepted_risk == {} and not risks[0].used


def test_resource_acceptance_on_a_check_without_resource_list_stays_visible():
    ev = [Evidence("aws.iam.root_mfa", "aws", Status.FAIL, "Root MFA off", region="global")]
    apply_accepted_risks(ev, [risk(check="aws.iam.root_mfa", resources=["root"])], TODAY)
    assert ev[0].accepted_risk["state"] == PARTIAL


# ---------------------------------------------------------------- reports
@pytest.mark.parametrize("build", [build_markdown, build_html])
def test_report_moves_accepted_finding_to_its_own_section(build):
    ev = [snapshots_fail()]
    apply_accepted_risks(ev, [risk(ticket="RISK-42")], TODAY)
    report = build(ev, load_mapping())
    assert "Findings to fix (0)" in report and "Accepted risks (1)" in report
    assert "ISMS lead" in report and "2027-05-31" in report and "RISK-42" in report
    assert findings(ev) == [] and accepted(ev) == ev


@pytest.mark.parametrize("build", [build_markdown, build_html])
def test_report_explains_an_expired_acceptance(build):
    ev = [snapshots_fail()]
    apply_accepted_risks(ev, [risk(expires=date(2026, 1, 31))], TODAY)
    report = build(ev, load_mapping())
    assert "Findings to fix (1)" in report
    assert "expired on 2026-01-31" in report


def test_html_escapes_the_reason_text():
    ev = [snapshots_fail()]
    apply_accepted_risks(ev, [risk(reason="<script>alert(1)</script>")], TODAY)
    html = build_html(ev, load_mapping())
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_json_carries_the_acceptance():
    ev = [snapshots_fail()]
    apply_accepted_risks(ev, [risk()], TODAY)
    data = json.loads(json.dumps(ev[0].to_dict(), default=str))
    assert data["status"] == "FAIL" and data["accepted_risk"]["state"] == "accepted"


# ---------------------------------------------------------------- CLI
@pytest.fixture
def aws_env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "eu-central-1"}.items():
        monkeypatch.setenv(k, v)


def test_bad_register_stops_before_any_aws_call(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr("iso27001_evidence.cli.collect", lambda *a, **k: called.append(1))
    path = write(tmp_path, "accepted_risks:\n  - {check: nope, reason: r, approved_by: a, "
                           "expires: 2027-01-01}")
    with pytest.raises(SystemExit, match="Accepted risk register"):
        main(["collect", "--accepted-risks", str(path)])
    assert called == []


@mock_aws
def test_fail_on_gap_ignores_accepted_risks(tmp_path, aws_env, capsys):
    # An empty mocked account fails root MFA, password policy, CloudTrail, EBS,
    # Security Hub and Config. Accept all of them, then the run must pass.
    failing = ["aws.iam.root_mfa", "aws.iam.password_policy",
               "aws.cloudtrail.multi_region_logging", "aws.ec2.ebs_default_encryption",
               "aws.securityhub.findings_summary", "aws.config.recorder_and_compliance"]
    entries = "\n".join(f"  - {{check: {c}, reason: test, approved_by: ISMS lead, "
                        f"expires: 2099-12-31}}" for c in failing)
    path = write(tmp_path, f"accepted_risks:\n{entries}\n  - {{check: aws.s3.bucket_protection, "
                           f"reason: test, approved_by: a, expires: 2099-12-31}}\n")
    code = main(["collect", "--out", str(tmp_path), "--fail-on-gap",
                 "--accepted-risks", str(path)])
    out = capsys.readouterr().out
    assert code == 0, out
    assert f"{len(failing)} accepted risk(s)" in out
    assert "aws.s3.bucket_protection matched no failed check" in out
