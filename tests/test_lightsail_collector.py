"""Lightsail tests.

moto does not support Lightsail, so these tests use botocore's Stubber.
Stubber feeds fixed API responses to a real boto3 client and checks that
each response matches the Lightsail API shape.
"""

from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from iso27001_evidence.collectors.lightsail import LightsailCollector
from iso27001_evidence.models import Evidence, Status
from iso27001_evidence.report import build_markdown, load_mapping

REGION = "eu-central-1"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def stubbed():
    """Yield (collector, stubber). STS is mocked by moto for the account ID."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        client = session.client("lightsail", region_name=REGION)
        stubber = Stubber(client)
        collector = LightsailCollector(session=session, region=REGION, client=client)
        with stubber:
            yield collector, stubber
        stubber.assert_no_pending_responses()


def instance(name, auto_snapshot=False, imdsv2=False, blueprint="ubuntu_24_04"):
    addons = [{"name": "AutoSnapshot", "status": "Enabled"}] if auto_snapshot else []
    return {"name": name, "addOns": addons, "blueprintId": blueprint,
            "metadataOptions": {"httpTokens": "required" if imdsv2 else "optional"}}


def port(from_port, to_port, cidrs, state="open"):
    return {"fromPort": from_port, "toPort": to_port, "protocol": "tcp",
            "state": state, "cidrs": cidrs, "ipv6Cidrs": []}


def test_scope_includes_account_and_region(stubbed):
    collector, _ = stubbed
    assert collector.scope == f"aws:123456789012/{REGION}"


def test_auto_snapshots_missing_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_instances", {"instances": [
        instance("web-1", auto_snapshot=True), instance("web-2")]})
    ev = collector.instance_auto_snapshots()
    assert ev.status == Status.FAIL
    assert ev.details["instances_without_auto_snapshots"] == ["web-2"]


def test_no_instances_is_not_applicable(stubbed):
    collector, stub = stubbed
    stub.add_response("get_instances", {"instances": []})
    assert collector.instance_auto_snapshots().status == Status.NOT_APPLICABLE


def test_instances_follow_pagination(stubbed):
    collector, stub = stubbed
    stub.add_response("get_instances", {"instances": [instance("a", True)],
                                        "nextPageToken": "p2"})
    stub.add_response("get_instances", {"instances": [instance("b", True)]},
                      expected_params={"pageToken": "p2"})
    ev = collector.instance_auto_snapshots()
    assert ev.status == Status.PASS
    assert ev.details["instances_total"] == 2


def test_ssh_open_to_world_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_instances", {"instances": [instance("web-1")]})
    stub.add_response("get_instance_port_states", {"portStates": [
        port(80, 80, ["0.0.0.0/0"]),
        port(22, 22, ["0.0.0.0/0"]),
    ]}, expected_params={"instanceName": "web-1"})
    ev = collector.instance_admin_ports()
    assert ev.status == Status.FAIL
    assert ev.details["exposed_admin_ports"] == [
        {"instance": "web-1", "port": 22, "service": "SSH", "open_to": ["0.0.0.0/0"]}]


def test_ssh_limited_to_office_ip_passes(stubbed):
    collector, stub = stubbed
    stub.add_response("get_instances", {"instances": [instance("web-1")]})
    stub.add_response("get_instance_port_states", {"portStates": [
        port(22, 22, ["203.0.113.10/32"]),
        port(443, 443, ["0.0.0.0/0"]),
    ]})
    assert collector.instance_admin_ports().status == Status.PASS


def test_wide_port_range_covering_rdp_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_instances", {"instances": [instance("win-1")]})
    stub.add_response("get_instance_port_states", {"portStates": [
        port(0, 65535, ["0.0.0.0/0"])]})
    ev = collector.instance_admin_ports()
    assert {p["service"] for p in ev.details["exposed_admin_ports"]} == {"SSH", "RDP"}


def test_public_bucket_and_overrides_fail(stubbed):
    collector, stub = stubbed
    stub.add_response("get_buckets", {"buckets": [
        {"name": "private", "accessRules": {"getObject": "private",
                                            "allowPublicOverrides": False}},
        {"name": "site", "accessRules": {"getObject": "public",
                                         "allowPublicOverrides": False}},
        {"name": "mixed", "accessRules": {"getObject": "private",
                                          "allowPublicOverrides": True}},
    ]})
    ev = collector.bucket_public_access()
    assert ev.status == Status.FAIL
    assert [i["bucket"] for i in ev.details["non_compliant"]] == ["site", "mixed"]


def test_public_database_without_backups_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_relational_databases", {"relationalDatabases": [
        {"name": "good", "backupRetentionEnabled": True, "publiclyAccessible": False},
        {"name": "bad", "backupRetentionEnabled": False, "publiclyAccessible": True},
    ]})
    ev = collector.database_backup_and_exposure()
    assert ev.status == Status.FAIL
    assert ev.details["non_compliant"] == [
        {"database": "bad", "backup_retention": False, "publicly_accessible": True}]


def test_load_balancer_without_redirect_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_load_balancers", {"loadBalancers": [
        {"name": "lb-ok", "publicPorts": [80, 443], "httpsRedirectionEnabled": True},
        {"name": "lb-http", "publicPorts": [80], "httpsRedirectionEnabled": False},
    ]})
    ev = collector.load_balancer_https()
    assert ev.status == Status.FAIL
    assert [i["load_balancer"] for i in ev.details["non_compliant"]] == ["lb-http"]


def test_certificate_expiring_soon_fails(stubbed):
    collector, stub = stubbed
    now = datetime.now(timezone.utc)
    stub.add_response("get_certificates", {"certificates": [
        {"certificateName": "fresh", "domainName": "a.example.com",
         "certificateDetail": {"notAfter": now + timedelta(days=200)}},
        {"certificateName": "old", "domainName": "b.example.com",
         "certificateDetail": {"notAfter": now + timedelta(days=5)}},
    ]}, expected_params={"certificateStatuses": ["ISSUED"],
                         "includeCertificateDetails": True})
    ev = collector.certificate_expiry()
    assert ev.status == Status.FAIL
    assert [c["certificate"] for c in ev.details["expiring_soon"]] == ["old"]


def test_full_run_with_api_error_reports_error_not_crash(stubbed):
    collector, stub = stubbed
    # Calls run in check-ID order. Instances are fetched once and reused.
    stub.add_client_error("get_buckets", service_error_code="AccessDeniedException")
    stub.add_response("get_buckets", {"buckets": []})
    stub.add_response("get_certificates", {"certificates": []})
    stub.add_response("get_relational_databases", {"relationalDatabases": []})
    stub.add_response("get_disks", {"disks": []})
    stub.add_response("get_instances", {"instances": [instance("web-1", True, imdsv2=True)]})
    stub.add_response("get_instance_port_states", {"portStates": []})
    stub.add_response("get_blueprints", {"blueprints": [
        {"blueprintId": "ubuntu_24_04", "isActive": True}]})
    stub.add_response("get_load_balancers", {"loadBalancers": []})
    results = {e.check_id: e for e in collector.run()}
    assert len(results) == 10
    assert results["lightsail.bucket.access_logging"].status == Status.ERROR
    assert results["lightsail.bucket.public_access"].status == Status.NOT_APPLICABLE
    assert results["lightsail.instance.imdsv2_required"].status == Status.PASS
    assert results["lightsail.instance.blueprint_supported"].status == Status.PASS
    assert results["lightsail.instance.auto_snapshots"].status == Status.PASS
    md = build_markdown(list(results.values()), load_mapping())
    assert "A.8.13" in md and "Information backup" in md


def test_data_disk_without_auto_snapshots_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_disks", {"disks": [
        {"name": "data-1", "isSystemDisk": False,
         "addOns": [{"name": "AutoSnapshot", "status": "Enabled"}]},
        {"name": "data-2", "isSystemDisk": False, "addOns": []},
        {"name": "root", "isSystemDisk": True, "addOns": []},
    ]})
    ev = collector.disk_auto_snapshots()
    assert ev.status == Status.FAIL
    assert ev.details["disks_without_auto_snapshots"] == ["data-2"]
    assert ev.details["disks_total"] == 2


def test_bucket_without_access_logging_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_buckets", {"buckets": [
        {"name": "logged", "accessLogConfig": {"enabled": True, "destination": "logs"}},
        {"name": "silent", "accessLogConfig": {"enabled": False}},
        {"name": "no-config"},
    ]})
    ev = collector.bucket_access_logging()
    assert ev.status == Status.FAIL
    assert ev.details["buckets_without_access_logs"] == ["silent", "no-config"]


def test_instance_allowing_imdsv1_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_instances", {"instances": [
        instance("new", imdsv2=True), instance("old", imdsv2=False)]})
    ev = collector.instance_imdsv2()
    assert ev.status == Status.FAIL
    assert ev.details["instances_allowing_imdsv1"] == ["old"]


def test_retired_blueprint_fails(stubbed):
    collector, stub = stubbed
    stub.add_response("get_instances", {"instances": [
        instance("current", blueprint="ubuntu_24_04"),
        instance("legacy", blueprint="ubuntu_16_04"),
        instance("custom", blueprint="something_else")]})
    stub.add_response("get_blueprints", {"blueprints": [
        {"blueprintId": "ubuntu_24_04", "isActive": True},
        {"blueprintId": "ubuntu_16_04", "isActive": False}]},
        expected_params={"includeInactive": True})
    ev = collector.instance_blueprint_supported()
    assert ev.status == Status.FAIL
    assert ev.details["retired_blueprints"] == [
        {"instance": "legacy", "blueprint": "ubuntu_16_04"}]
    assert ev.details["unknown_blueprints"] == ["custom"]


def test_report_separates_not_run_from_not_automated():
    ev = [Evidence(check_id="lightsail.instance.auto_snapshots", source="lightsail",
                   status=Status.PASS, summary="ok")]
    md = build_markdown(ev, load_mapping())
    assert "| A.8.5 | Secure authentication | not checked in this run | 0 |" in md
    assert "| A.8.25 | Secure development life cycle | not automated yet | 0 |" in md
