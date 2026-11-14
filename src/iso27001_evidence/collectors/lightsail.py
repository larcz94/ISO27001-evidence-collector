"""Amazon Lightsail collector: read-only checks for small AWS setups.

Lightsail is regional, so each run checks one region. Credentials come
from the standard boto3 chain. Use policies/lightsail-readonly-policy.json.
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


class LightsailCollector(BaseCollector):
    source = "lightsail"

    def __init__(self, session: boto3.Session | None = None, region: str | None = None,
                 client: Any = None) -> None:
        super().__init__()
        self.session = session or boto3.Session(region_name=region)
        self.region = region or self.session.region_name or "eu-central-1"
        # A client can be passed in so tests can attach a botocore Stubber.
        self.ls = client or self.session.client("lightsail", region_name=self.region)
        self.scope = f"{self._account_id()}/{self.region}"
        self._instances: list[dict] | None = None

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
        buckets = self._all("get_buckets", "buckets")
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
            f"{CERT_WARNING_DAYS} days",
            certificates_total=len(certs), expiring_soon=expiring,
        )
