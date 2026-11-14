"""Tests run against moto's mocked AWS - no real account or credentials needed."""

import boto3
import pytest
from moto import mock_aws

from iso27001_evidence.collectors.aws import AWSCollector
from iso27001_evidence.models import Status
from iso27001_evidence.report import build_markdown, load_mapping

REGION = "eu-central-1"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def collector():
    with mock_aws():
        yield AWSCollector(session=boto3.Session(region_name=REGION))


def by_id(results):
    return {r.check_id: r for r in results}


def test_console_user_without_mfa_fails(collector):
    iam = collector.session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r-Secret-Passw0rd!")
    ev = collector.console_users_mfa()
    assert ev.status == Status.FAIL
    assert ev.details["users_without_mfa"] == ["alice"]


def test_missing_password_policy_fails_then_strong_policy_passes(collector):
    assert collector.password_policy().status == Status.FAIL
    collector.session.client("iam").update_account_password_policy(
        MinimumPasswordLength=14, PasswordReusePrevention=24)
    assert collector.password_policy().status == Status.PASS


def test_unprotected_bucket_fails(collector):
    collector.session.client("s3").create_bucket(
        Bucket="audit-test", CreateBucketConfiguration={"LocationConstraint": REGION})
    ev = collector.s3_bucket_protection()
    assert ev.status == Status.FAIL
    assert ev.details["non_compliant"][0]["public_access_blocked"] is False


def test_no_cloudtrail_fails(collector):
    assert collector.cloudtrail_logging().status == Status.FAIL


def test_multi_region_trail_from_other_region_passes(collector):
    # Trail lives in us-east-1, collector runs in eu-central-1.
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="trail-logs")
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(Name="org-trail", S3BucketName="trail-logs", IsMultiRegionTrail=True)
    ct.start_logging(Name="org-trail")
    ev = collector.cloudtrail_logging()
    assert ev.status == Status.PASS
    assert ev.details["active_multi_region_trails"][0]["home_region"] == "us-east-1"


def test_full_run_never_crashes_and_builds_report(collector):
    results = collector.run()
    assert len(results) == len(collector.checks())
    md = build_markdown(results, load_mapping())
    assert "A.8.5" in md and "Secure authentication" in md


def test_report_is_plain_ascii(collector):
    # Plain text prints on any console (Windows cp1252 cannot show emojis).
    md = build_markdown(collector.run(), load_mapping())
    assert md.isascii()
