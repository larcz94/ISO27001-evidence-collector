"""Multi-region runs: --region with several regions and --all-regions."""

import json

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from iso27001_evidence import cli
from iso27001_evidence.cli import _split_regions, main
from iso27001_evidence.collectors.aws import GLOBAL_CHECKS, AWSCollector
from iso27001_evidence.collectors.base import BaseCollector, check
from iso27001_evidence.collectors.lightsail import LightsailCollector
from iso27001_evidence.models import Evidence, Status
from iso27001_evidence.report import build_html, build_markdown, detail_rows, load_mapping

REGIONAL_AWS_CHECKS = 3   # EBS default encryption, Security Hub, AWS Config


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "eu-central-1"}.items():
        monkeypatch.setenv(k, v)


def read_json(tmp_path):
    return json.loads(next(tmp_path.glob("iso27001-evidence_*.json")).read_text(encoding="utf-8"))


def test_split_regions_accepts_spaces_and_commas():
    assert _split_regions(["eu-west-3", "eu-central-1,us-east-1", "eu-west-3"]) == [
        "eu-west-3", "eu-central-1", "us-east-1"]
    assert _split_regions(None) == []


def test_region_and_all_regions_cannot_be_combined():
    with pytest.raises(SystemExit):
        main(["collect", "--region", "eu-west-3", "--all-regions"])


def test_list_checks_needs_no_credentials(monkeypatch, capsys):
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(var)
    assert main(["list-checks", "--source", "all"]) == 0
    assert len(capsys.readouterr().out.split()) == 18


@mock_aws
def test_aws_global_checks_run_once_and_regional_checks_per_region(tmp_path):
    main(["collect", "--source", "aws", "--region", "eu-central-1", "us-east-1",
          "--out", str(tmp_path)])
    results = read_json(tmp_path)
    global_results = [r for r in results if r["region"] == "global"]
    assert {r["check_id"] for r in global_results} == GLOBAL_CHECKS
    assert len(global_results) == len(GLOBAL_CHECKS)
    for region in ("eu-central-1", "us-east-1"):
        assert len([r for r in results if r["region"] == region]) == REGIONAL_AWS_CHECKS
    # One account ID for the whole run, without the region in it.
    assert {r["scope"] for r in results} == {"aws:123456789012"}


@mock_aws
def test_regional_setting_is_checked_in_each_region(tmp_path):
    boto3.client("ec2", region_name="us-east-1").enable_ebs_encryption_by_default()
    main(["collect", "--source", "aws", "--region", "eu-central-1,us-east-1",
          "--out", str(tmp_path)])
    ebs = {r["region"]: r["status"] for r in read_json(tmp_path)
           if r["check_id"] == "aws.ec2.ebs_default_encryption"}
    assert ebs == {"eu-central-1": "FAIL", "us-east-1": "PASS"}


@mock_aws
def test_aws_available_regions_come_from_the_api():
    regions = AWSCollector.available_regions()
    assert "us-east-1" in regions and "eu-central-1" in regions
    assert len(regions) > 5 and regions == sorted(regions)


@mock_aws
def test_aws_all_regions_covers_every_listed_region(tmp_path, capsys, monkeypatch):
    # Three regions keep the test fast. The real list is tested above.
    expected = ["ap-south-1", "eu-central-1", "us-east-1"]
    monkeypatch.setattr(AWSCollector, "available_regions", classmethod(lambda cls: expected))
    main(["collect", "--source", "aws", "--all-regions", "--out", str(tmp_path)])
    results = read_json(tmp_path)
    assert {r["region"] for r in results} == set(expected) | {"global"}
    assert len(results) == len(GLOBAL_CHECKS) + REGIONAL_AWS_CHECKS * len(expected)
    assert f"(1/{len(expected)})" in capsys.readouterr().err


@mock_aws
def test_lightsail_available_regions_come_from_the_api():
    session = boto3.Session(region_name="eu-central-1")
    client = session.client("lightsail", region_name="eu-central-1")
    with Stubber(client) as stub:
        stub.add_response("get_regions", {"regions": [
            {"name": "eu-west-3"}, {"name": "ap-south-1"}, {"name": "eu-central-1"}]})
        regions = LightsailCollector.available_regions(session=session, client=client)
    assert regions == ["ap-south-1", "eu-central-1", "eu-west-3"]


class FakeRegional(BaseCollector):
    """Stands in for Lightsail: one instance only exists in eu-west-3."""

    source = "fake"
    remediation = {"fake.instance.snapshots": "Turn snapshots on."}
    created: list[tuple[str, str | None]] = []

    def __init__(self, region=None, scope=None):
        super().__init__()
        self.region = region
        self.scope = scope or "aws:123456789012"
        FakeRegional.created.append((region, scope))

    @classmethod
    def available_regions(cls, session=None):
        return ["ap-south-1", "eu-central-1", "eu-west-3"]

    @check("fake.instance.snapshots")
    def snapshots(self) -> Evidence:
        if self.region != "eu-west-3":
            return Evidence("fake.instance.snapshots", self.source, Status.NOT_APPLICABLE,
                            f"No instances in {self.region}")
        return Evidence("fake.instance.snapshots", self.source, Status.FAIL,
                        "0 of 1 instances have snapshots",
                        details={"instances_without_snapshots": ["web-1"]})


@pytest.fixture
def fake_source(monkeypatch):
    FakeRegional.created = []
    monkeypatch.setattr(cli, "collector_class", lambda source: FakeRegional)
    monkeypatch.setattr(cli, "get_collector", lambda source, **kw: FakeRegional(**kw))


def test_all_regions_creates_one_collector_per_region(fake_source):
    evidence = cli.collect(["fake"], [], all_regions=True)
    assert [e.region for e in evidence] == ["ap-south-1", "eu-central-1", "eu-west-3"]
    # The account ID is looked up by the first collector and reused after that.
    assert FakeRegional.created == [("ap-south-1", None), ("eu-central-1", "aws:123456789012"),
                                    ("eu-west-3", "aws:123456789012")]


def test_all_regions_without_permission_stops_with_a_clear_message(monkeypatch):
    def denied(cls, session=None):
        raise PermissionError("AccessDeniedException: lightsail:GetRegions")

    monkeypatch.setattr(LightsailCollector, "available_regions", classmethod(denied))
    with pytest.raises(SystemExit) as exit_info:
        main(["collect", "--source", "lightsail", "--all-regions"])
    message = str(exit_info.value)
    assert "lightsail:GetRegions" in message and "--region" in message


def test_selected_regions_are_checked_in_the_given_order(fake_source):
    evidence = cli.collect(["fake"], ["eu-west-3", "ap-south-1"], all_regions=False)
    assert [(e.region, e.status) for e in evidence] == [
        ("eu-west-3", Status.FAIL), ("ap-south-1", Status.NOT_APPLICABLE)]


def test_multi_region_console_output_hides_empty_regions(fake_source, tmp_path, capsys):
    main(["collect", "--source", "aws", "--all-regions", "--out", str(tmp_path)])
    out = capsys.readouterr().out
    assert "FAIL  eu-west-3" in out
    assert "No instances in" not in out
    assert "2 N/A result(s) not shown" in out
    assert "1 finding(s) to fix" in out


MAPPING = {"framework": "test", "controls": {
    "A.8.13": {"title": "Information backup", "checks": ["fake.instance.snapshots"]}}}


@pytest.mark.parametrize("build", [build_markdown, build_html])
def test_report_names_the_region_of_each_finding(fake_source, build):
    report = build(cli.collect(["fake"], [], all_regions=True), MAPPING)
    assert "Regions (3)" in report and "ap-south-1, eu-central-1, eu-west-3" in report
    assert "fake.instance.snapshots" in report and "(eu-west-3)" in report
    assert "web-1" in report and "Turn snapshots on." in report
    # Empty regions are one line, not one line each.
    assert "Nothing to check in 2 regions: ap-south-1, eu-central-1" in report
    assert "No instances in ap-south-1" not in report


def test_single_not_applicable_result_is_not_collapsed():
    one = [Evidence("x.check", "x", Status.NOT_APPLICABLE, "No buckets in eu-west-3",
                    region="eu-west-3", scope="aws:1")]
    rows = detail_rows(one)
    assert len(rows) == 1 and rows[0][2] == "No buckets in eu-west-3"
    assert rows[0][3].endswith("scope aws:1, region eu-west-3")


def test_control_status_is_the_worst_result_across_regions():
    ev = [Evidence("fake.instance.snapshots", "fake", Status.PASS, "ok", region="eu-central-1"),
          Evidence("fake.instance.snapshots", "fake", Status.FAIL, "bad", region="eu-west-3")]
    md = build_markdown(ev, load_mapping() | MAPPING)
    assert "| A.8.13 | Information backup | **FAIL** | 2 |" in md
