"""Amazon Lightsail collector: read-only checks for small AWS setups.

Lightsail is regional, so one collector checks one region. The CLI creates
one collector per region for multi-region runs. Credentials come from the
standard boto3 chain. Use policies/lightsail-readonly-policy.json.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

from ..models import Evidence, Status
from .base import BaseCollector, check

# Remote admin ports that should never be open to the whole internet.
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
OPEN_TO_WORLD = {"0.0.0.0/0", "::/0"}
CERT_WARNING_DAYS = 30

CHECK_INFO = {
    "lightsail.instance.auto_snapshots": ("Instances should have automatic snapshots", "medium"),
    "lightsail.disk.auto_snapshots":
        ("Block storage disks should have automatic snapshots", "medium"),
    "lightsail.instance.admin_ports_restricted":
        ("SSH and RDP should not be open to the internet", "high"),
    "lightsail.instance.imdsv2_required": ("Instances should require IMDSv2", "medium"),
    "lightsail.instance.blueprint_supported":
        ("Instances should run a supported OS image", "medium"),
    "lightsail.bucket.public_access": ("Buckets should be private", "high"),
    "lightsail.bucket.access_logging": ("Buckets should have access logging", "low"),
    "lightsail.database.backup_and_exposure":
        ("Databases should be backed up and not public", "high"),
    "lightsail.loadbalancer.https_only": ("Load balancers should enforce HTTPS", "medium"),
    "lightsail.certificate.expiry": ("Certificates should not be about to expire", "medium"),
}

REMEDIATION = {
    "lightsail.instance.auto_snapshots":
        "In the Lightsail console open the instance, go to the Snapshots tab and turn on "
        "automatic snapshots. Snapshot storage is billed per GB. If the instance holds no "
        "data you need, record that as an accepted risk instead.",
    "lightsail.disk.auto_snapshots":
        "In the Lightsail console open the disk under Storage, go to the Snapshots tab and "
        "turn on automatic snapshots. Each block storage disk has its own snapshot setting.",
    "lightsail.instance.admin_ports_restricted":
        "In the Lightsail console open the instance, go to the Networking tab and edit the "
        "SSH (22) or RDP (3389) rule in the IPv4 firewall: restrict it to your own IP "
        "addresses, or allow only Lightsail browser SSH/RDP. Do the same in the IPv6 "
        "firewall, or turn IPv6 off if you do not use it.",
    "lightsail.instance.imdsv2_required":
        "Require IMDSv2 with the AWS CLI: aws lightsail update-instance-metadata-options "
        "--instance-name <name> --http-tokens required. Test the application afterwards, "
        "because very old SDKs may still use IMDSv1.",
    "lightsail.instance.blueprint_supported":
        "The OS image is retired, which usually means the OS version is near or past end "
        "of life. Take a snapshot, create a new instance from a current blueprint, move "
        "the application and delete the old instance.",
    "lightsail.bucket.public_access":
        "In the Lightsail console open the bucket, go to the Permissions tab, set the "
        "bucket to private and turn off the option that lets individual objects be made "
        "public. If the bucket hosts a public website on purpose, record it as an accepted "
        "risk.",
    "lightsail.bucket.access_logging":
        "In the Lightsail console open the bucket, go to the Logging tab, turn on access "
        "logging and choose a second, private bucket as the destination.",
    "lightsail.database.backup_and_exposure":
        "In the Lightsail console open the database. On the Networking tab turn off public "
        "mode, so only your Lightsail resources can reach it. Make sure automatic backups "
        "are turned on.",
    "lightsail.loadbalancer.https_only":
        "In the Lightsail console open the load balancer, attach a TLS certificate and "
        "turn on the HTTP to HTTPS redirect.",
    "lightsail.certificate.expiry":
        "Lightsail renews a certificate only while it is in use and its DNS validation "
        "records still exist. Check that the validation CNAME records are still in your "
        "DNS zone, or create a new certificate and attach it before the old one expires.",
}


class LightsailCollector(BaseCollector):
    source = "lightsail"
    remediation = REMEDIATION
    check_info = CHECK_INFO

    def __init__(self, session: boto3.Session | None = None, region: str | None = None,
                 client: Any = None, scope: str | None = None) -> None:
        super().__init__()
        self.session = session or boto3.Session(region_name=region)
        self.region = region or self.session.region_name or "eu-central-1"
        # A client can be passed in so tests can attach a botocore Stubber.
        self.ls = client or self.session.client("lightsail", region_name=self.region)
        # In a multi-region run the account ID is looked up once and passed in.
        self.scope = scope or self._account_id()
        self._instances: list[dict] | None = None
        self._buckets: list[dict] | None = None

    @classmethod
    def available_regions(cls, session: boto3.Session | None = None,
                          client: Any = None) -> list[str]:
        """Regions where Lightsail is offered."""
        session = session or boto3.Session()
        client = client or session.client(
            "lightsail", region_name=session.region_name or "us-east-1")
        return sorted(r["name"] for r in client.get_regions()["regions"])

    # ---------- helpers ----------
    def _account_id(self) -> str:
        try:
            sts = self.session.client("sts", region_name=self.region)
            return "aws:" + sts.get_caller_identity()["Account"]
        except Exception:  # noqa: BLE001
            return "aws:unknown"

    def _all(self, operation: str, key: str, **params) -> list[dict]:
        """Call a Lightsail list operation and follow pageToken to the end."""
        items: list[dict] = []
        token = None
        while True:
            kwargs = dict(params, pageToken=token) if token else params
            page = getattr(self.ls, operation)(**kwargs)
            items.extend(page.get(key, []))
            token = page.get("nextPageToken")
            if not token:
                return items

    def instances(self) -> list[dict]:
        """Instances are used by several checks, so fetch them once per run."""
        if self._instances is None:
            self._instances = self._all("get_instances", "instances")
        return self._instances

    def buckets(self) -> list[dict]:
        if self._buckets is None:
            self._buckets = self._all("get_buckets", "buckets")
        return self._buckets

    def _ev(self, check_id: str, status: Status, summary: str, **details) -> Evidence:
        return Evidence(check_id=check_id, source=self.source, status=status,
                        summary=summary, details=details)

    # ---------- backup ----------
    @check("lightsail.instance.auto_snapshots")
    def instance_auto_snapshots(self) -> Evidence:
        cid = "lightsail.instance.auto_snapshots"
        instances = self.instances()
        if not instances:
            return self._ev(cid, Status.NOT_APPLICABLE, f"No Lightsail instances in {self.region}")
        missing = [
            i["name"] for i in instances
            if not any(a.get("name") == "AutoSnapshot" and a.get("status") == "Enabled"
                       for a in i.get("addOns", []))
        ]
        return self._ev(
            cid, Status.FAIL if missing else Status.PASS,
            f"{len(instances) - len(missing)} of {len(instances)} instances have "
            f"automatic snapshots enabled",
            instances_total=len(instances), instances_without_auto_snapshots=missing,
        )

    # ---------- network security ----------
    @check("lightsail.instance.admin_ports_restricted")
    def instance_admin_ports(self) -> Evidence:
        cid = "lightsail.instance.admin_ports_restricted"
        instances = self.instances()
        if not instances:
            return self._ev(cid, Status.NOT_APPLICABLE, f"No Lightsail instances in {self.region}")
        exposed = []
        for inst in instances:
            ports = self.ls.get_instance_port_states(instanceName=inst["name"])["portStates"]
            for p in ports:
                if p.get("state") != "open":
                    continue
                world = OPEN_TO_WORLD & set(p.get("cidrs", []) + p.get("ipv6Cidrs", []))
                if not world:
                    continue
                for port, label in ADMIN_PORTS.items():
                    if p["fromPort"] <= port <= p["toPort"]:
                        exposed.append({"instance": inst["name"], "port": port,
                                        "service": label, "open_to": sorted(world)})
        return self._ev(
            cid, Status.FAIL if exposed else Status.PASS,
            f"{len(exposed)} admin port(s) open to the internet across "
            f"{len(instances)} instance(s)" if exposed
            else f"No SSH/RDP ports open to the internet on {len(instances)} instance(s)",
            exposed_admin_ports=exposed,
        )

    # ---------- information access ----------
    @check("lightsail.bucket.public_access")
    def bucket_public_access(self) -> Evidence:
        cid = "lightsail.bucket.public_access"
        buckets = self.buckets()
        if not buckets:
            return self._ev(cid, Status.NOT_APPLICABLE, f"No Lightsail buckets in {self.region}")
        issues = []
        for b in buckets:
            rules = b.get("accessRules", {})
            public = rules.get("getObject") == "public"
            overrides = bool(rules.get("allowPublicOverrides"))
            if public or overrides:
                issues.append({"bucket": b["name"], "public_read": public,
                               "allow_public_object_overrides": overrides})
        return self._ev(
            cid, Status.FAIL if issues else Status.PASS,
            f"{len(buckets) - len(issues)} of {len(buckets)} buckets are private "
            f"with no public object overrides",
            buckets_total=len(buckets), non_compliant=issues,
        )

    # ---------- databases ----------
    @check("lightsail.database.backup_and_exposure")
    def database_backup_and_exposure(self) -> Evidence:
        cid = "lightsail.database.backup_and_exposure"
        dbs = self._all("get_relational_databases", "relationalDatabases")
        if not dbs:
            return self._ev(cid, Status.NOT_APPLICABLE,
                            f"No Lightsail managed databases in {self.region}")
        issues = []
        for db in dbs:
            backups = bool(db.get("backupRetentionEnabled"))
            public = bool(db.get("publiclyAccessible"))
            if public or not backups:
                issues.append({"database": db["name"], "backup_retention": backups,
                               "publicly_accessible": public})
        return self._ev(
            cid, Status.FAIL if issues else Status.PASS,
            f"{len(dbs) - len(issues)} of {len(dbs)} databases have backups on "
            f"and are not publicly accessible",
            databases_total=len(dbs), non_compliant=issues,
        )

    # ---------- cryptography ----------
    @check("lightsail.loadbalancer.https_only")
    def load_balancer_https(self) -> Evidence:
        cid = "lightsail.loadbalancer.https_only"
        lbs = self._all("get_load_balancers", "loadBalancers")
        if not lbs:
            return self._ev(cid, Status.NOT_APPLICABLE,
                            f"No Lightsail load balancers in {self.region}")
        issues = []
        for lb in lbs:
            has_tls = 443 in lb.get("publicPorts", [])
            redirect = bool(lb.get("httpsRedirectionEnabled"))
            if not (has_tls and redirect):
                issues.append({"load_balancer": lb["name"], "https_listener": has_tls,
                               "http_to_https_redirect": redirect,
                               "tls_policy": lb.get("tlsPolicyName")})
        return self._ev(
            cid, Status.FAIL if issues else Status.PASS,
            f"{len(lbs) - len(issues)} of {len(lbs)} load balancers serve HTTPS "
            f"and redirect HTTP to HTTPS",
            load_balancers_total=len(lbs), non_compliant=issues,
            tls_policies={lb["name"]: lb.get("tlsPolicyName") for lb in lbs},
        )

    @check("lightsail.certificate.expiry")
    def certificate_expiry(self) -> Evidence:
        cid = "lightsail.certificate.expiry"
        certs = self.ls.get_certificates(certificateStatuses=["ISSUED"],
                                         includeCertificateDetails=True).get("certificates", [])
        if not certs:
            return self._ev(cid, Status.NOT_APPLICABLE,
                            f"No issued Lightsail certificates in {self.region}")
        limit = datetime.now(timezone.utc) + timedelta(days=CERT_WARNING_DAYS)
        expiring = []
        for c in certs:
            detail = c.get("certificateDetail", {})
            not_after = detail.get("notAfter")
            if not_after and not_after <= limit:
                expiring.append({"certificate": c["certificateName"],
                                 "domain": c.get("domainName"),
                                 "not_after": not_after.isoformat()})
        return self._ev(
            cid, Status.FAIL if expiring else Status.PASS,
            f"{len(expiring)} of {len(certs)} certificates expire within "
            f"{CERT_WARNING_DAYS} days" if expiring
            else f"None of the {len(certs)} issued certificates expire within "
                 f"{CERT_WARNING_DAYS} days",
            certificates_total=len(certs), expiring_soon=expiring,
        )

    @check("lightsail.disk.auto_snapshots")
    def disk_auto_snapshots(self) -> Evidence:
        cid = "lightsail.disk.auto_snapshots"
        # System disks are covered by the instance snapshot check.
        disks = [d for d in self._all("get_disks", "disks") if not d.get("isSystemDisk")]
        if not disks:
            return self._ev(cid, Status.NOT_APPLICABLE,
                            f"No Lightsail block storage disks in {self.region}")
        missing = [
            d["name"] for d in disks
            if not any(a.get("name") == "AutoSnapshot" and a.get("status") == "Enabled"
                       for a in d.get("addOns", []))
        ]
        return self._ev(
            cid, Status.FAIL if missing else Status.PASS,
            f"{len(disks) - len(missing)} of {len(disks)} block storage disks have "
            f"automatic snapshots enabled",
            disks_total=len(disks), disks_without_auto_snapshots=missing,
        )

    # ---------- logging ----------
    @check("lightsail.bucket.access_logging")
    def bucket_access_logging(self) -> Evidence:
        cid = "lightsail.bucket.access_logging"
        buckets = self.buckets()
        if not buckets:
            return self._ev(cid, Status.NOT_APPLICABLE, f"No Lightsail buckets in {self.region}")
        missing = [b["name"] for b in buckets
                   if not b.get("accessLogConfig", {}).get("enabled")]
        return self._ev(
            cid, Status.FAIL if missing else Status.PASS,
            f"{len(buckets) - len(missing)} of {len(buckets)} buckets have access logging enabled",
            buckets_total=len(buckets), buckets_without_access_logs=missing,
        )

    # ---------- configuration & vulnerability management ----------
    @check("lightsail.instance.imdsv2_required")
    def instance_imdsv2(self) -> Evidence:
        cid = "lightsail.instance.imdsv2_required"
        instances = self.instances()
        if not instances:
            return self._ev(cid, Status.NOT_APPLICABLE, f"No Lightsail instances in {self.region}")
        # IMDSv2 needs a session token, which blocks most SSRF attacks that
        # try to steal instance credentials from the metadata service.
        weak = [i["name"] for i in instances
                if i.get("metadataOptions", {}).get("httpTokens") != "required"]
        return self._ev(
            cid, Status.FAIL if weak else Status.PASS,
            f"{len(instances) - len(weak)} of {len(instances)} instances require IMDSv2",
            instances_total=len(instances), instances_allowing_imdsv1=weak,
        )

    @check("lightsail.instance.blueprint_supported")
    def instance_blueprint_supported(self) -> Evidence:
        cid = "lightsail.instance.blueprint_supported"
        instances = self.instances()
        if not instances:
            return self._ev(cid, Status.NOT_APPLICABLE, f"No Lightsail instances in {self.region}")
        blueprints = self._all("get_blueprints", "blueprints", includeInactive=True)
        active = {b["blueprintId"]: b.get("isActive", False) for b in blueprints}
        retired = [{"instance": i["name"], "blueprint": i.get("blueprintId")}
                   for i in instances if active.get(i.get("blueprintId")) is False]
        unknown = [i["name"] for i in instances if i.get("blueprintId") not in active]
        return self._ev(
            cid, Status.FAIL if retired else Status.PASS,
            f"{len(retired)} of {len(instances)} instances run a retired blueprint "
            f"(OS image)" if retired
            else f"All {len(instances)} instances run a blueprint (OS image) that "
                 f"Lightsail still offers",
            instances_total=len(instances), retired_blueprints=retired,
            unknown_blueprints=unknown,
        )
